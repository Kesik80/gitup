// /api/release-upload.js — Vercel Serverless Function
// Проксирует загрузку файла в GitHub Release Assets
// (uploads.github.com блокирует CORS из браузера напрямую)
//
// Env vars: GITHUB_TOKEN
//
// POST /api/release-upload
//   Headers: Content-Type (оригинальный тип файла), X-File-Name, X-Upload-Url (upload_url из релиза)
//   Body: raw binary

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-File-Name, X-Upload-Url');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const token = process.env.GITHUB_TOKEN;
  if (!token) return res.status(500).json({ error: 'GITHUB_TOKEN не задан' });

  // Имя файла и upload_url передаются в заголовках (чтобы не усложнять multipart)
  const fileName  = req.headers['x-file-name'];
  const uploadUrl = req.headers['x-upload-url'];

  if (!fileName || !uploadUrl) {
    return res.status(400).json({ error: 'X-File-Name и X-Upload-Url обязательны' });
  }

  // Собираем тело запроса из потока
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks);

  if (body.length === 0) {
    return res.status(400).json({ error: 'Пустое тело запроса' });
  }

  // upload_url из GitHub API выглядит как:
  // https://uploads.github.com/repos/{owner}/{repo}/releases/{id}/assets{?name,label}
  const cleanUrl = uploadUrl.replace('{?name,label}', '');
  const url = `${cleanUrl}?name=${encodeURIComponent(fileName)}`;

  const contentType = req.headers['content-type'] || 'application/octet-stream';

  try {
    const ghRes = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `token ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': contentType,
        'Content-Length': body.length,
      },
      body,
      // Node 18+ fetch поддерживает Buffer как body
    });

    const data = await ghRes.json().catch(() => ({}));

    if (!ghRes.ok) {
      return res.status(ghRes.status).json({
        error: data.message || `GitHub ответил ${ghRes.status}`,
        details: data,
      });
    }

    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};

// Важно: отключаем bodyParser Vercel чтобы получить raw binary
module.exports.config = {
  api: {
    bodyParser: false,
    // Максимальный размер — 100 МБ (лимит GitHub для release assets)
    responseLimit: false,
  },
};
