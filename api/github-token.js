// /api/github-token.js — Vercel Serverless Function
// Пароль ИЛИ session-токен → GitHub-токен.
//
// Env vars:
//   GITUP_PASSWORD        — пароль входа (обязательно)
//   GITHUB_TOKEN          — PAT, который выдаём клиенту (обязательно)
//   GITUP_SESSION_SECRET  — ключ подписи сессий (необязательно; по умолчанию
//                           выводится из GITUP_PASSWORD + GITHUB_TOKEN, поэтому
//                           смена пароля или ротация PAT гасит все сессии)
//   GITUP_SESSION_DAYS    — срок жизни сессии в днях (по умолчанию 30)
//   GITUP_ALLOWED_ORIGIN  — дополнительный origin для CORS (необязательно)

const crypto = require('crypto');

const SESSION_DAYS = Math.max(1, parseInt(process.env.GITUP_SESSION_DAYS || '30', 10) || 30);

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(str) {
  return Buffer.from(String(str).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function signingKey() {
  if (process.env.GITUP_SESSION_SECRET) return process.env.GITUP_SESSION_SECRET;
  return crypto.createHash('sha256')
    .update(`${process.env.GITUP_PASSWORD}::${process.env.GITHUB_TOKEN}`)
    .digest('hex');
}

function issueSession() {
  const now = Date.now();
  const payload = { iat: now, exp: now + SESSION_DAYS * 86400000, jti: crypto.randomBytes(8).toString('hex') };
  const body = b64url(JSON.stringify(payload));
  const sig  = b64url(crypto.createHmac('sha256', signingKey()).update(body).digest());
  return { session: `v1.${body}.${sig}`, exp: payload.exp };
}

function verifySession(token) {
  if (typeof token !== 'string' || token.length > 512) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;

  const expected = b64url(crypto.createHmac('sha256', signingKey()).update(parts[1]).digest());
  const a = Buffer.from(parts[2]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try { payload = JSON.parse(unb64url(parts[1]).toString('utf8')); } catch { return null; }
  if (!payload || typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
  return payload;
}

function samePassword(given, correct) {
  const a = crypto.createHash('sha256').update(String(given)).digest();
  const b = crypto.createHash('sha256').update(String(correct)).digest();
  return crypto.timingSafeEqual(a, b);
}

// Примитивный лимит попыток. В serverless живёт в рамках тёплого инстанса —
// не броня, но сбивает быстрый перебор.
const attempts = new Map();
function tooManyAttempts(ip) {
  const now = Date.now();
  const rec = attempts.get(ip) || { n: 0, until: 0, ts: 0 };
  if (rec.until > now) return true;
  if (now - rec.ts > 15 * 60000) rec.n = 0;
  rec.n += 1;
  rec.ts = now;
  if (rec.n > 10) { rec.until = now + 5 * 60000; rec.n = 0; }
  attempts.set(ip, rec);
  if (attempts.size > 500) attempts.clear();
  return false;
}

module.exports = async function handler(req, res) {
  // CORS: только свой домен (плюс явно разрешённый), не '*' —
  // за этим эндпоинтом стоит токен с полным доступом к репозиториям.
  const origin  = req.headers.origin || '';
  const host    = req.headers.host || '';
  const allowed = [`https://${host}`, `http://${host}`, process.env.GITUP_ALLOWED_ORIGIN].filter(Boolean);
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  const correctPassword = process.env.GITUP_PASSWORD;
  const githubToken     = process.env.GITHUB_TOKEN;
  if (!correctPassword || !githubToken) {
    return res.status(500).json({ ok: false, error: 'Сервер не настроен' });
  }

  const body = req.body || {};
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';

  // ── 1. Продление по session-токену ─────────────────────────────────────
  if (body.session) {
    const payload = verifySession(body.session);
    if (!payload) {
      return res.status(401).json({ ok: false, error: 'Сессия истекла — введите пароль' });
    }
    // Скользящее продление: каждый успешный вход отодвигает срок.
    const fresh = issueSession();
    return res.status(200).json({ ok: true, token: githubToken, session: fresh.session, exp: fresh.exp });
  }

  // ── 2. Первый вход по паролю ───────────────────────────────────────────
  const { password } = body;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ ok: false, error: 'Пароль не указан' });
  }
  if (tooManyAttempts(ip)) {
    return res.status(429).json({ ok: false, error: 'Слишком много попыток — подождите 5 минут' });
  }

  await new Promise(r => setTimeout(r, 300 + Math.random() * 200));

  if (!samePassword(password, correctPassword)) {
    return res.status(401).json({ ok: false, error: 'Неверный пароль' });
  }

  const fresh = issueSession();
  return res.status(200).json({ ok: true, token: githubToken, session: fresh.session, exp: fresh.exp });
};
