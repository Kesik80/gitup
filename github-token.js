// /api/github-token.js — Vercel Serverless Function
// Проверяет пароль и возвращает GitHub токен
// Env vars: GITUP_PASSWORD, GITHUB_TOKEN

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { password } = req.body || {};

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ ok: false, error: 'Пароль не указан' });
  }

  const correctPassword = process.env.GITUP_PASSWORD;
  const githubToken    = process.env.GITHUB_TOKEN;

  if (!correctPassword || !githubToken) {
    return res.status(500).json({ ok: false, error: 'Сервер не настроен' });
  }

  // Фиксированная задержка против брутфорса
  await new Promise(r => setTimeout(r, 300 + Math.random() * 200));

  if (password !== correctPassword) {
    return res.status(200).json({ ok: false, error: 'Неверный пароль' });
  }

  return res.status(200).json({ ok: true, token: githubToken });
}
