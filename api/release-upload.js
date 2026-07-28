// /api/release-upload.js — Vercel Serverless Function
//
// НЕ проксирует файл — только выдаёт одноразовые данные для
// прямой загрузки из браузера на uploads.github.com.
//
// Почему так: Vercel ограничивает тело запроса до 4.5 МБ даже
// для Edge функций (на Hobby плане). Прямая загрузка из браузера
// не имеет этого ограничения.
//
// CORS на uploads.github.com: GitHub разрешает cross-origin POST
// с Authorization заголовком если запрос идёт напрямую (не через
// промежуточный сервер) — браузер при этом делает preflight OPTIONS
// который GitHub корректно обрабатывает.
//
// Env vars: GITHUB_TOKEN
//
// POST /api/release-upload
//   Body JSON: { uploadUrl: string, fileName: string }
//   Response:  { token: string, url: string }

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = process.env.GITHUB_TOKEN;
  if (!token) return res.status(500).json({ error: 'GITHUB_TOKEN не задан' });

  const { uploadUrl, fileName } = req.body || {};
  if (!uploadUrl || !fileName) {
    return res.status(400).json({ error: 'uploadUrl и fileName обязательны' });
  }

  // Валидируем что это действительно GitHub uploads URL
  if (!uploadUrl.includes('uploads.github.com') && !uploadUrl.includes('api.github.com')) {
    return res.status(400).json({ error: 'Недопустимый uploadUrl' });
  }

  const cleanUrl = uploadUrl.replace('{?name,label}', '');
  const url = `${cleanUrl}?name=${encodeURIComponent(fileName)}`;

  // Возвращаем токен и готовый URL — браузер загружает файл сам
  return res.status(200).json({ token, url });
};
