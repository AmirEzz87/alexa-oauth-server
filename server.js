require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

const {
  PORT = 3000,
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  OAUTH_CLIENT_ID,
  OAUTH_CLIENT_SECRET,
  ACCESS_TOKEN_TTL_SECONDS = 3600,
  REFRESH_TOKEN_TTL_SECONDS = 2592000
} = process.env;

function renderLoginPage({ redirectUri, clientId, state, error }) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Login to link Alexa</title>
  <style>
    body { background:#000; color:#fff; font-family:sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
    .card { background:#111; padding:32px; border-radius:8px; width:100%; max-width:480px; box-sizing:border-box; }
    h1 { text-align:center; margin-top:0; margin-bottom:24px; }
    input { width:100%; padding:10px; margin:8px 0; border-radius:4px; border:none; font-size:16px; }
    button { width:100%; padding:12px; margin-top:8px; font-size:18px; font-weight:bold; background:#1dd65f; color:#000; border:none; border-radius:4px; cursor:pointer; }
    .error { color:#ff6b6b; margin-bottom:8px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Alexa Login</h1>
    ${error ? `<div class="error">${error}</div>` : ''}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="${clientId || ''}">
      <input type="hidden" name="redirect_uri" value="${redirectUri || ''}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Sign in & Link</button>
    </form>
  </div>
</body>
</html>`;
}

// VERY SIMPLE DB helper – we will replace with proper RPC/REST later if needed
async function insertAuthCode({ code, userId, clientId, redirectUri, expiresAt }) {
  const url = `${SUPABASE_URL}/rest/v1/alexa_auth_codes`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    },
    body: JSON.stringify([
      {
        code,
        user_id: userId,
        client_id: clientId,
        redirect_uri: redirectUri,
        expires_at: expiresAt,
        used: false
      }
    ])
  });
  if (!res.ok) {
    console.error('insertAuthCode error:', await res.text());
    throw new Error('DB insert error');
  }
}

async function getValidAuthCode({ code, clientId, redirectUri }) {
  const url = `${SUPABASE_URL}/rest/v1/alexa_auth_codes` +
    `?code=eq.${code}&client_id=eq.${clientId}&redirect_uri=eq.${encodeURIComponent(
      redirectUri
    )}&used=eq.false&select=*&limit=1`;
  const res = await fetch(url, {
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    }
  });
  if (!res.ok) {
    console.error('getValidAuthCode error:', await res.text());
    throw new Error('DB select error');
  }
  const rows = await res.json();
  if (!rows.length) return null;
  const row = rows[0];
  if (new Date(row.expires_at) <= new Date()) return null;
  return row;
}

async function markCodeUsed(code) {
  const url = `${SUPABASE_URL}/rest/v1/alexa_auth_codes?code=eq.${code}`;
  const res = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    },
    body: JSON.stringify({ used: true })
  });
  if (!res.ok) {
    console.error('markCodeUsed error:', await res.text());
    throw new Error('DB update error');
  }
}

async function insertTokens({ accessToken, refreshToken, userId, clientId, expiresAt, refreshExpiresAt }) {
  const url = `${SUPABASE_URL}/rest/v1/alexa_tokens`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
    },
    body: JSON.stringify([
      {
        access_token: accessToken,
        refresh_token: refreshToken,
        user_id: userId,
        client_id: clientId,
        expires_at: expiresAt,
        refresh_expires_at: refreshExpiresAt
      }
    ])
  });
  if (!res.ok) {
    console.error('insertTokens error:', await res.text());
    throw new Error('DB insert tokens error');
  }
}

// GET /oauth/authorize
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state, response_type } = req.query;

  if (client_id !== OAUTH_CLIENT_ID) {
    return res.status(400).send('Invalid client_id');
  }
  if (response_type !== 'code') {
    return res.status(400).send('response_type must be "code"');
  }
  if (!redirect_uri) {
    return res.status(400).send('Missing redirect_uri');
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(renderLoginPage({ redirectUri: redirect_uri, clientId: client_id, state }));
});

// POST /oauth/authorize – verify email/password via Supabase, issue code
app.post('/oauth/authorize', express.urlencoded({ extended: false }), async (req, res) => {
  const { email, password, client_id, redirect_uri, state } = req.body;

  if (client_id !== OAUTH_CLIENT_ID) {
    return res.status(400).send('Invalid client_id');
  }

  try {
    const authRes = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        apikey: SUPABASE_ANON_KEY
      },
      body: JSON.stringify({ email, password })
    });

    const authJson = await authRes.json();
    if (!authRes.ok || !authJson.user || !authJson.user.id) {
      return res
        .status(401)
        .send(
          renderLoginPage({
            redirectUri: redirect_uri,
            clientId: client_id,
            state,
            error: 'Invalid email or password.'
          })
        );
    }

    const userId = authJson.user.id;
    const code = uuidv4().replace(/-/g, '');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

    await insertAuthCode({
      code,
      userId,
      clientId: client_id,
      redirectUri: redirect_uri,
      expiresAt
    });

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);

    return res.redirect(url.toString());
  } catch (err) {
    console.error('Authorize error:', err);
    return res.status(500).send('Server error');
  }
});

// POST /oauth/token – exchange code or refresh_token for access_token
app.post('/oauth/token', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Basic (.+)$/);
  if (!match) {
    return res.status(401).json({ error: 'invalid_client' });
  }
  const decoded = Buffer.from(match[1], 'base64').toString('utf8');
  const [clientId, clientSecret] = decoded.split(':');
  if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // body-parser urlencoded already applied
  const { grant_type } = req.body;

  if (grant_type === 'authorization_code') {
    const { code, redirect_uri } = req.body;
    if (!code || !redirect_uri) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    try {
      const record = await getValidAuthCode({ code, clientId, redirectUri: redirect_uri });
      if (!record) {
        return res.status(400).json({ error: 'invalid_grant' });
      }

      await markCodeUsed(code);

      const accessToken = uuidv4().replace(/-/g, '');
      const refreshToken = uuidv4().replace(/-/g, '');
      const accessExpires = new Date(Date.now() + ACCESS_TOKEN_TTL_SECONDS * 1000).toISOString();
      const refreshExpires = new Date(
        Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000
      ).toISOString();

      await insertTokens({
        accessToken,
        refreshToken,
        userId: record.user_id,
        clientId,
        expiresAt: accessExpires,
        refreshExpiresAt: refreshExpires
      });

      return res.json({
        access_token: accessToken,
        token_type: 'bearer',
        expires_in: Number(ACCESS_TOKEN_TTL_SECONDS),
        refresh_token: refreshToken
      });
    } catch (err) {
      console.error('Token error:', err);
      return res.status(500).json({ error: 'server_error' });
    }
  }

  // (refresh_token part can be added later; not required to pass Alexa linking initially)
  return res.status(400).json({ error: 'unsupported_grant_type' });
});

app.listen(PORT, () => {
  console.log(`OAuth server listening on port ${PORT}`);
});
