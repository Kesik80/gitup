// /api/release-upload.js — Vercel Edge Function
//
// Проксирует загрузку файла в GitHub Release Assets.
// uploads.github.com блокирует CORS из браузера, поэтому
// браузер → эта функция → uploads.github.com.
//
// Edge Runtime не имеет лимита на тело запроса (в отличие от
// Serverless Functions с лимитом 4.5 МБ) — подходит для
// больших .wgt файлов (5+ МБ).
//
// Env vars: GITHUB_TOKEN
//
// POST /api/release-upload
//   Header X-File-Name:  имя файла (напр. PRISMA_v0.2.7.wgt)
//   Header X-Upload-Url: upload_url из GitHub Releases API
//   Body: raw binary (тело файла)

export const config = { runtime: 'edge' };

export default async function handler(req) {
  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-File-Name, X-Upload-Url',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers: cors });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  const token = process.env.GITHUB_TOKEN;
  if (!token) {
    return new Response(JSON.stringify({ error: 'GITHUB_TOKEN не задан' }), {
      status: 500, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  const fileName  = req.headers.get('x-file-name');
  const uploadUrl = req.headers.get('x-upload-url');

  if (!fileName || !uploadUrl) {
    return new Response(JSON.stringify({ error: 'X-File-Name и X-Upload-Url обязательны' }), {
      status: 400, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  const cleanUrl = uploadUrl.replace('{?name,label}', '');
  const url = `${cleanUrl}?name=${encodeURIComponent(fileName)}`;
  const contentType = req.headers.get('content-type') || 'application/octet-stream';

  // Пробрасываем тело как ReadableStream — никакой буферизации,
  // нет ограничения по размеру на стороне Edge функции.
  const ghRes = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `token ${token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': contentType,
    },
    body: req.body,        // ReadableStream напрямую
    duplex: 'half',        // обязательно для streaming body в fetch
  }).catch(err => {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 502, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  });

  // ghRes может быть Response (из catch) — возвращаем как есть
  if (ghRes instanceof Response && !ghRes.headers.get('authorization')) {
    return ghRes;
  }

  const data = await ghRes.json().catch(() => ({}));

  return new Response(JSON.stringify(data), {
    status: ghRes.ok ? 200 : ghRes.status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}
