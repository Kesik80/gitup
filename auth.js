/* ============================================================================
   GitUp · auth.js — вход по отпечатку + пароль
   ----------------------------------------------------------------------------
   Отличие от Fahrzeit-версии (важно, читай перед правками):

   В Fahrzeit auth.js охраняет вход в редактор, и в localStorage лежит сам
   пароль. Здесь ставка выше: за паролем — GitHub-токен с полным доступом к
   репозиториям. Поэтому пароль НЕ сохраняется никогда.

   Модель:
     1. Пароль уходит на /api/github-token один раз. Сервер возвращает
        GitHub-токен + подписанный session-токен (HMAC, срок жизни задан
        сервером, отзывается сменой GITUP_PASSWORD / GITHUB_TOKEN /
        GITUP_SESSION_SECRET).
     2. На устройстве живёт только session-токен. GitHub-токен — исключительно
        в sessionStorage, на диск не попадает.
     3. Если устройство умеет WebAuthn PRF, session-токен лежит на диске
        зашифрованным AES-GCM ключом, который выдаёт отпечаток. Без пальца
        его не расшифровать даже с полным доступом к localStorage.
     4. Если PRF недоступен — session-токен лежит обфусцированным, а отпечаток
        работает как экранная защёлка. Это слабее: честно сообщаем об этом
        через Auth.strength().

   Публичный API (совместим по именам с Fahrzeit):
     Auth.available()            → Promise<bool>  платформенный аутентификатор есть
     Auth.enrolled()             → bool           отпечаток привязан
     Auth.enroll()               → Promise<bool>  привязать отпечаток
     Auth.forget()               → void           стереть всё с устройства
     Auth.remember(secret, mode) → Promise<bool>  сохранить session/токен
     Auth.unlock()               → Promise<bool>  запросить отпечаток
     Auth.verify(password)       → Promise<{ok, token, session, exp, error}>
     Auth.resume(opts)           → Promise<{ok, token, need, error}>
     Auth.stored()               → {mode, exp, protected} | null (без расшифровки)
     Auth.strength()             → 'prf' | 'gate' | 'plain' | 'none'
     Auth.biometricRequired()    → bool
     Auth.setBiometricRequired(v)→ void
   ========================================================================== */
(function () {
    'use strict';

    const STORE_KEY  = 'gitup-auth-v2';   // {mode, exp, enc, iv, data}
    const CRED_KEY   = 'gitup-webauthn';  // {id, prf}
    const BIO_KEY    = 'gitup-bio-required';
    const LEGACY_KEY = 'gh-auth-v1';      // прошлая версия: хранила сам пароль
    const MASK       = 'GitUp/2026';
    const PRF_SALT   = new TextEncoder().encode('gitup-session-key-v1');
    const API_URL    = '/api/github-token';

    const hasWebAuthn = typeof window.PublicKeyCredential === 'function' &&
                        !!(navigator.credentials && navigator.credentials.create);
    const hasSubtle   = !!(window.crypto && window.crypto.subtle);

    // ── низкоуровневые утилиты ───────────────────────────────────────────
    function b64(bytes) {
        let bin = '';
        const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
        return btoa(bin);
    }
    function unb64(str) {
        const bin = atob(str);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }
    function xorBytes(bytes) {
        const out = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
            out[i] = bytes[i] ^ (MASK.charCodeAt(i % MASK.length) & 0xFF);
        }
        return out;
    }
    function readJSON(key) {
        try {
            const raw = localStorage.getItem(key);
            return raw ? JSON.parse(raw) : null;
        } catch { return null; }
    }
    function writeJSON(key, obj) {
        try { localStorage.setItem(key, JSON.stringify(obj)); return true; }
        catch (e) { console.warn('Auth: запись в localStorage не удалась:', e.message); return false; }
    }
    function drop(key) { try { localStorage.removeItem(key); } catch {} }

    // ── WebAuthn ─────────────────────────────────────────────────────────
    let availableCache = null;

    async function available() {
        if (!hasWebAuthn) return false;
        if (availableCache !== null) return availableCache;
        try {
            availableCache = await PublicKeyCredential
                .isUserVerifyingPlatformAuthenticatorAvailable();
        } catch { availableCache = false; }
        return availableCache;
    }

    function credential() { return readJSON(CRED_KEY); }
    function enrolled()  { return !!(credential() && credential().id); }

    async function enroll() {
        if (!(await available())) return false;
        try {
            const userId = crypto.getRandomValues(new Uint8Array(16));
            const cred = await navigator.credentials.create({
                publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    rp: { name: 'GitUp', id: location.hostname },
                    user: { id: userId, name: 'gitup@' + location.hostname, displayName: 'GitUp' },
                    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
                    authenticatorSelection: {
                        authenticatorAttachment: 'platform',
                        userVerification: 'required',
                        residentKey: 'preferred'
                    },
                    timeout: 60000,
                    attestation: 'none',
                    extensions: { prf: { eval: { first: PRF_SALT } } }
                }
            });
            if (!cred) return false;

            let prf = false;
            try {
                const ext = cred.getClientExtensionResults();
                prf = !!(ext && ext.prf && ext.prf.enabled);
            } catch {}

            writeJSON(CRED_KEY, { id: b64(cred.rawId), prf });
            setBiometricRequired(true);
            console.log('Auth: отпечаток привязан, PRF =', prf);
            return true;
        } catch (e) {
            console.warn('Auth: привязка отпечатка отменена:', e.name || e.message);
            return false;
        }
    }

    // Запрашивает отпечаток. Возвращает ключ PRF (Uint8Array) либо true/false.
    async function assert() {
        const cred = credential();
        if (!cred || !cred.id) return { ok: false };
        try {
            const assertion = await navigator.credentials.get({
                publicKey: {
                    challenge: crypto.getRandomValues(new Uint8Array(32)),
                    allowCredentials: [{ type: 'public-key', id: unb64(cred.id) }],
                    userVerification: 'required',
                    timeout: 60000,
                    extensions: { prf: { eval: { first: PRF_SALT } } }
                }
            });
            if (!assertion) return { ok: false };

            let prfKey = null;
            try {
                const ext = assertion.getClientExtensionResults();
                if (ext && ext.prf && ext.prf.results && ext.prf.results.first) {
                    prfKey = new Uint8Array(ext.prf.results.first).slice(0, 32);
                }
            } catch {}
            return { ok: true, prfKey };
        } catch (e) {
            console.warn('Auth: отпечаток не подтверждён:', e.name || e.message);
            return { ok: false, cancelled: e.name === 'NotAllowedError' };
        }
    }

    async function unlock() { return (await assert()).ok; }

    // ── шифрование секрета ───────────────────────────────────────────────
    async function aesKey(rawKey) {
        return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    }

    async function packSecret(secret, prfKey) {
        const plain = new TextEncoder().encode(secret);
        if (prfKey && hasSubtle) {
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const buf = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, await aesKey(prfKey), plain
            );
            return { enc: 'prf', iv: b64(iv), data: b64(new Uint8Array(buf)) };
        }
        return { enc: 'xor', data: b64(xorBytes(plain)) };
    }

    async function unpackSecret(rec, prfKey) {
        if (rec.enc === 'prf') {
            if (!prfKey || !hasSubtle) return null;
            try {
                const buf = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: unb64(rec.iv) }, await aesKey(prfKey), unb64(rec.data)
                );
                return new TextDecoder().decode(buf);
            } catch (e) {
                console.warn('Auth: расшифровка не удалась:', e.message);
                return null;
            }
        }
        return new TextDecoder().decode(xorBytes(unb64(rec.data)));
    }

    // ── хранилище секрета ────────────────────────────────────────────────
    // mode: 'session' (продакшн, серверный session-токен) | 'token' (локальный режим, PAT)
    async function remember(secret, mode, exp, prfKey) {
        if (!secret) return false;
        let key = prfKey || null;
        const cred = credential();

        // Отпечаток привязан и умеет PRF, но ключа под рукой нет — спросим палец
        if (!key && cred && cred.prf) {
            const res = await assert();
            if (res.ok && res.prfKey) key = res.prfKey;
        }

        const packed = await packSecret(secret, key);
        return writeJSON(STORE_KEY, {
            v: 2,
            mode: mode || 'session',
            exp: exp || 0,
            ...packed
        });
    }

    function stored() {
        const rec = readJSON(STORE_KEY);
        if (!rec || !rec.data) return null;
        if (rec.exp && Date.now() > rec.exp) { drop(STORE_KEY); return null; }
        return { mode: rec.mode || 'session', exp: rec.exp || 0, protected: rec.enc === 'prf' };
    }

    async function recall(prfKey) {
        const rec = readJSON(STORE_KEY);
        if (!rec || !rec.data) return null;
        if (rec.exp && Date.now() > rec.exp) { drop(STORE_KEY); return null; }
        const secret = await unpackSecret(rec, prfKey);
        return secret ? { secret, mode: rec.mode || 'session', exp: rec.exp || 0 } : null;
    }

    function forget() {
        drop(STORE_KEY);
        drop(CRED_KEY);
        drop(BIO_KEY);
        drop(LEGACY_KEY);
        try { sessionStorage.removeItem('gh-token'); } catch {}
    }

    // Стереть только сохранённый сеанс, привязку отпечатка оставить.
    // Нужно, когда сервер отверг сессию: пароль человек введёт заново,
    // а заново привязывать палец — лишняя морока.
    function forgetSecret() {
        drop(STORE_KEY);
        drop(LEGACY_KEY);
        try { sessionStorage.removeItem('gh-token'); } catch {}
    }

    // ── Миграция с версии, где на устройстве лежал сам пароль ────────────
    // Ключ gh-auth-v1: {v:1, mode:'pwd'|'token', s: base64(xor(utf8))}
    function legacyRecord() {
        const rec = readJSON(LEGACY_KEY);
        if (!rec || !rec.s) return null;
        try {
            const secret = new TextDecoder().decode(xorBytes(unb64(rec.s)));
            return secret ? { secret, mode: rec.mode === 'token' ? 'token' : 'pwd' } : null;
        } catch { return null; }
    }
    function dropLegacy() { drop(LEGACY_KEY); }

    function biometricRequired() {
        if (!enrolled()) return false;
        return localStorage.getItem(BIO_KEY) !== '0';
    }
    function setBiometricRequired(v) {
        try { localStorage.setItem(BIO_KEY, v ? '1' : '0'); } catch {}
    }

    function strength() {
        const rec = readJSON(STORE_KEY);
        if (!rec) return 'none';
        if (rec.enc === 'prf') return 'prf';
        return enrolled() ? 'gate' : 'plain';
    }

    // ── обмен с сервером ─────────────────────────────────────────────────
    async function post(body) {
        let resp;
        try {
            resp = await fetch(API_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
        } catch (e) {
            const err = new Error('Сеть: ' + e.message);
            err.network = true;
            throw err;
        }
        let data;
        try { data = await resp.json(); }
        catch { throw new Error('Ответ не JSON (статус ' + resp.status + ')'); }

        if (!data.ok) {
            const err = new Error(data.error || 'Отказано (' + resp.status + ')');
            // 401/403 — пароль или сессия недействительны, хранить нечего
            err.authFailed = resp.status === 401 || resp.status === 403 || resp.status === 200;
            throw err;
        }
        return data;
    }

    // Пароль → GitHub-токен + session-токен. Пароль дальше не сохраняем.
    async function verify(password) {
        const data = await post({ password });
        return { ok: true, token: data.token, session: data.session, exp: data.exp || 0 };
    }

    // Session-токен → свежий GitHub-токен.
    async function exchange(session) {
        const data = await post({ session });
        return { ok: true, token: data.token, session: data.session || session, exp: data.exp || 0 };
    }

    /**
     * Восстановить сеанс из того, что лежит на устройстве.
     * opts.interactive — можно ли показывать запрос отпечатка (нужен жест
     * пользователя на некоторых браузерах).
     * Ответ: {ok, token} | {need:'password'|'unlock'} | {ok:false, error}
     */
    async function resume(opts) {
        opts = opts || {};
        const meta = stored();
        if (!meta) return { need: 'password' };

        let prfKey = null;
        const needFinger = meta.protected || biometricRequired();

        if (needFinger) {
            if (!opts.interactive) return { need: 'unlock', mode: meta.mode };
            const res = await assert();
            if (!res.ok) return { need: 'unlock', mode: meta.mode, cancelled: !!res.cancelled };
            prfKey = res.prfKey || null;
        }

        const rec = await recall(prfKey);
        if (!rec) return { need: 'unlock', mode: meta.mode };

        if (rec.mode === 'token') {
            // локальный режим: на устройстве лежит сам PAT
            return { ok: true, token: rec.secret, mode: 'token' };
        }

        try {
            const data = await exchange(rec.secret);
            if (data.session && data.session !== rec.secret) {
                await remember(data.session, 'session', data.exp, prfKey);
            }
            return { ok: true, token: data.token, mode: 'session' };
        } catch (e) {
            if (e.authFailed) { drop(STORE_KEY); return { need: 'password', error: e.message }; }
            return { ok: false, error: e.message, network: !!e.network };
        }
    }

    window.Auth = {
        available, enrolled, enroll, unlock, forget, forgetSecret,
        remember, recall, stored, strength,
        legacyRecord, dropLegacy,
        verify, exchange, resume,
        biometricRequired, setBiometricRequired,
        _assert: assert
    };

    console.log('Auth: загружен · WebAuthn =', hasWebAuthn, '· enrolled =', enrolled());
})();
