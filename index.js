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
        console.log("in the constructor")
        this._host = host
        this._opts = opts
        this._storage = opts.storage || new LocalStorage()

        this.unlock()

        this._public_keys_exp_at = null
        this._token = null
        this._locked = false
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

        console.log("starting to validate token")
        console.log("fetching public keys")
        const public_keys = await this.get_public_keys()

        console.log("checking public keys for match")
        const promises = public_keys.map(async (key) => {
            console.log("checking key", key)

            let public_key;

            try {
                public_key = await jose.importSPKI(key, 'RS256')
            } catch (err) {
                throw new OxidAuthError('IMPORT_SPKI_ERR', err)
            }

            try {
                return await this.verifyToken(public_key)
            } catch (err) {
                console.log("error verifying token", err)

                if (`${err}`.includes('"exp" claim timestamp check failed')) {
                    console.log("JWT seems to be expired", err)

                    console.log("attempting to exchange refresh token")

                    await this.lock()

                    let result

                    try {
                        result = await this.exchangeToken()
                        console.log("verifyToken try ::: ", result)
                    } catch(err) {
                        throw new OxidAuthError('TOKEN_NOT_VALID', err)
                    } finally {
                        console.log("verifyToken reached finally")
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

        const old_refresh_token = await this.get_refresh_token()

        if (!old_refresh_token) {
            throw new OxidAuthError('NO_REFRESH_TOKEN_FOR_EXCHANGE', 'no refresh token found')
        }

        const body = JSON.stringify({ refresh_token: old_refresh_token })

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
                throw new OxidAuthError('FETCH_PUBLIC_KEYS_ERR', err)
            })

        await this.set_token(jwt)
        await this.set_refresh_token(refresh_token)

        await this.unlock()

        return await this.fetchValidToken()
    }

    async verifyToken(key) {
        const token = await this.get_token()

        if (token) {
            const { payload } = await jose.jwtVerify(token, key)

            return payload
        } else {
            throw new OxidAuthError('NO_TOKEN_FOUND_ERR', 'no token was found, you may need to authenticate first')
        }
    }

    async authUsernamePassword(username, password) {
        const url = `${this._host}/api/v1/auth/authenticate`

        const body = JSON.stringify({
            strategy: 'username_password',
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

        await this.set_token(jwt)
        await this.set_refresh_token(refresh_token)

        await this.get_token()

        return jwt
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

    async get_public_keys() {
        let public_keys = await this._storage.get(PUBLIC_KEYS_KEY)

        if (this?._public_keys_exp_at < new Date() || !public_keys) {
            let result = await this.fetchPublicKeys()

            await this._storage.set(PUBLIC_KEYS_KEY, result?.public_keys)

            public_keys = result?.public_keys

            this._public_keys_exp_at =
                Date.now() + ((this._opts?.public_keys_ttl_secs || DEFAULT_OPTS.public_keys_ttl_secs) * 60 * 1000)
        }

        return public_keys?.map((obj) => obj.public_key)
    }

    async get_token() {
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

    async set_token(value) {
        this._token = value

        await this._storage.set(TOKEN_KEY, value)
    }

    async get_refresh_token() {
        return await this._storage.get(REFRESH_TOKEN_KEY)
    }

    async set_refresh_token(value) {
        return await this._storage.set(REFRESH_TOKEN_KEY, value)
    }

    async wait(depth = 600) {
        console.log("waiting...", depth)

        if (depth == 0) {
            console.log("wait depth is 0")

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
        console.log("attempting to lock mutex")

        if (await this.isLocked()) {
            console.log("mutex is already locked")

            if (!await this.wait()) {
                throw new OxidAuthError('MUTEX_LOCK_ERR', "failed to get mutex")
            }
        }

        console.log("mutex locked")
        return await this._storage.set(OXIDAUTH_MUTEX_KEY, true)
    }

    async isLocked() {
        return await this._storage.get(OXIDAUTH_MUTEX_KEY)
    }

    async unlock() {
        console.log("unlocking")
        return await this._storage.set(OXIDAUTH_MUTEX_KEY, false)
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
