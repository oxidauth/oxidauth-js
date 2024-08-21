import * as jose from 'jose'

const TOKEN_KEY = 'OXIDAUTH_TOKEN'
const REFRESH_TOKEN_KEY = 'OXIDAUTH_REFRESH_TOKEN'
const PUBLIC_KEYS_KEY = 'OXIDAUTH_PUBLIC_KEYS'
const OXIDAUTH_MUTEX_KEY = 'OXIDAUTH_MUTEX_KEY'

const DEFAULT_OPTS = {
    public_keys_ttl_secs: 120,
}

export class OxidAuthClient {
    constructor(host, opts = DEFAULT_OPTS) {
        this._host = host
        this._opts = opts
        this._storage = opts.storage || new LocalStorage()

        this.unlock()

        this._public_keys_exp_at = null
        this._token = null
        this._locked = false
    }

    buildUsernamePassword(client_key) {
      return new UsernamePassword(this, client_key)
    }

    async fetchValidToken() {
        return await this.validateToken()
    }

    async fetchValidJWT() {
        await this.validateToken()

        return this._token
    }

    async validateToken() {
        if (await this.isLocked()) {
            return new Promise((resolve, reject) => {
                setTimeout(() => {
                    this.validateToken()
                        .then((result) => resolve(result))
                        .catch((err) => reject(err))
                }, 250)
            })
        }

        const publicKeys = await this.getPublicKeys()

        const promises = publicKeys.map(async (key) => {

            let publicKey;

            try {
              publicKey = await jose.importSPKI(key, 'RS256')
            } catch (err) {
                throw new OxidAuthError('IMPORT_SPKI_ERR', err)
            }

            try {
                return await this.verifyToken(publicKey)
            } catch (err) {

                if (`${err}`.includes('"exp" claim timestamp check failed')) {
                    await this.lock()
                    let result

                    try {
                        result = await this.exchangeToken()
                    } catch(err) {
                        throw new OxidAuthError('TOKEN_NOT_VALID', err)
                    } finally {
                        await this.unlock()
                    }

                    return result
                } else {
                    throw new OxidAuthError('TOKEN_NOT_VALID', err)
                }
            }
        })

        try {
            const results = await Promise.any(promises)

            return results
        } catch (err) {
            throw new OxidAuthError('VALIDATE_TOKEN_ERR', err)
        }
    }

    async exchangeToken() {
        const url = `${this._host}/api/v1/refresh_tokens`

        const oldRefreshToken = await this.getRefreshToken()

        if (!oldRefreshToken) {
            throw new OxidAuthError('NO_REFRESH_TOKEN_FOR_EXCHANGE', 'no refresh token found')
        }

        const body = JSON.stringify({ refresh_token: oldRefreshToken })

        const opts = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
        }

        const { jwt, refresh_token } = await fetch(url, opts)
            .then((res) => res.json())
            .then((res) => {
                if (res.success === false) {
                    throw new OxidAuthError('EXCHANGE_REFRESH_TOKEN_ERR', res?.errors)
                }

                return res.payload
            })
            .catch((err) => {
                throw new OxidAuthError('EXCHANGE_REFRESH_TOKEN_ERR', err)
            })

        await this.setToken(jwt)
        await this.setRefreshToken(refresh_token)

        await this.unlock()

        return await this.fetchValidToken()
    }

    async verifyToken(key) {
        const token = await this.getToken()

        if (token) {
            const { payload } = await jose.jwtVerify(token, key)

            return payload
        } else {
            throw new OxidAuthError('NO_TOKEN_FOUND_ERR', 'no token was found, you may need to authenticate first')
        }
    }

    async clearToken() {
        await this._storage.reset()

        this._public_keys_exp_at = null
        this._token = null
    }

    async fetchPublicKeys() {
        const url = `${this._host}/api/v1/public_keys`

        const opts = { headers: { 'Content-Type': 'application/json' } }

        return fetch(url, opts)
            .then((res) => res.json())
            .then((res) => {
                if (res.success === false) {
                    throw new OxidAuthError('FETCH_PUBLIC_KEYS_ERR', res?.errors)
                }

                return res.payload
            })
            .catch((err) => {
                throw new OxidAuthError('FETCH_PUBLIC_KEYS_ERR', err)
            })
    }

    async getPublicKeys() {
        let publicKeys = await this._storage.get(PUBLIC_KEYS_KEY)

        if (this?._public_keys_exp_at < new Date() || !publicKeys) {
            let result = await this.fetchPublicKeys()

            await this._storage.set(PUBLIC_KEYS_KEY, result?.public_keys)

            publicKeys = result?.public_keys

            this._public_keys_exp_at =
                Date.now() + ((this._opts?.public_keys_ttl_secs || DEFAULT_OPTS.public_keys_ttl_secs) * 60 * 1000)
        }

        return publicKeys?.map((obj) => obj.public_key)
    }

    async getToken() {
        try {
            if (!this._token) {
                const token = await this._storage.get(TOKEN_KEY)

                this._token = token
            }

            return this._token
        } catch (_) {
            return undefined
        }
    }

    async setToken(value) {
        this._token = value

        await this._storage.set(TOKEN_KEY, value)
    }

    async getRefreshToken() {
        return await this._storage.get(REFRESH_TOKEN_KEY)
    }

    async setRefreshToken(value) {
        return await this._storage.set(REFRESH_TOKEN_KEY, value)
    }

    async wait(depth = 600) {
        if (depth == 0) {
            return false
        }

        if (await this.isLocked()) {
            return new Promise((resolve) => {
                setTimeout(async () => {
                    await this.wait(depth - 1)

                    resolve(true)
                }, 50)
            })
        }

        return true
    }

    async lock() {
        if (await this.isLocked()) {
            if (!await this.wait()) {
                throw new OxidAuthError('MUTEX_LOCK_ERR', "failed to get mutex")
            }
        }

        return await this._storage.set(OXIDAUTH_MUTEX_KEY, true)
    }

    async isLocked() {
        return await this._storage.get(OXIDAUTH_MUTEX_KEY)
    }

    async unlock() {
        return await this._storage.set(OXIDAUTH_MUTEX_KEY, false)
    }

    async checkPermission(permission) {
        const url = `${this._host}/api/v1/can/${permission}`

        if (!permission) {
            throw new OxidAuthError('NO_PERMISSION_TO_CHECK', 'no permission provided to check against')
        }

        const headers = {
            'Content-Type': 'application/json',
        }

        const token = await this.fetchValidJWT()

        if (token !== undefined && token !== null && token.trim() !== '') {
            headers['Authorization'] = `Bearer ${token}`
        }

        const opts = { headers }

        return fetch(url, opts)
            .then((res) => res.json())
            .then((res) => {
                if (res.success === false) {
                    throw new OxidAuthError('CHECK_PERMISSION_ERR', res?.errors)
                }

                return res.payload
            })
            .catch((err) => {
                throw new OxidAuthError('CHECK_PERMISSION_ERR', err)
            })
    }
}

class LocalStorage {
    async get(key) {
        try {
            const raw = localStorage.getItem(key)

            if (!raw) {
                return undefined
            }

            try {
                return JSON.parse(raw)
            } catch (err) {
                return undefined
            }
        } catch (err) {
            throw new OxidAuthError('STORAGE_GET_ERR', err)
        }
    }

    async set(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value))
        } catch (err) {
            throw new OxidAuthError('STORAGE_SET_ERR', err)
        }
    }

    async remove(key) {
        try {
            localStorage.removeItem(key)
        } catch (err) {
            throw new OxidAuthError('STORAGE_REMOVE_ERR', err)
        }
    }

    async reset() {
        try {
            this.remove(TOKEN_KEY)
            this.remove(PUBLIC_KEYS_KEY)
            this.remove(REFRESH_TOKEN_KEY)
        } catch (err) {
            throw new OxidAuthError('STORAGE_RESET_ERR', err)
        }
    }
}

export class OxidAuthError extends Error {
    constructor(type, err) {
        super(err)

        console.log("OxidauthError", type, err)

        this.name = type
        this.message = err
    }
}

export class UsernamePassword {
  constructor(client, clientKey) {
    this._client = client
    this._clientKey = clientKey
  }

  async authenticate(username, password) {
    const url = `${this._client._host}/api/v1/auth/authenticate`

    const body = JSON.stringify({
        client_key: this._clientKey,
        params: { username, password },
    })

    const opts = {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
    }

    const { jwt, refresh_token } = await fetch(url, opts)
        .then((res) => res.json())
        .then((res) => {
            if (res.success === false) {
                throw new OxidAuthError('AUTHENTICATE_ERR', res?.errors)
            }

            return res.payload
        })
        .catch((err) => {
            throw new OxidAuthError('AUTHENTICATE_ERR', err)
        })
    
    await this._client.setToken(jwt)
    await this._client.setRefreshToken(refresh_token)

    await this._client.getToken()

    return jwt
  }

  async validateEmailCode(code) {
    const url = `${this._client._host}/api/v1/totp/validate`
    const oldJwt = await this._client.getToken()

    const body = JSON.stringify({
      code,
      client_key: this._clientKey,
    })

    const opts = {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${oldJwt}`,
      },
      body,
    }

    const { jwt, refresh_token } = await fetch(url, opts)
    .then((res) => res.json())
    .then((res) => {
        if (res.success === false) {
            throw new OxidAuthError('AUTHENTICATE_ERR', res?.errors)
        }

        return res.payload
    })
    .catch((err) => {
        throw new OxidAuthError('AUTHENTICATE_ERR', err)
    })

    await this._client.setToken(jwt)
    await this._client.setRefreshToken(refresh_token)

    await this._client.getToken()

    return jwt
  }
}
