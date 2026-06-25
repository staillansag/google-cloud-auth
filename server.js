const express = require('express');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));

// Common GCP scopes offered in the form
const AVAILABLE_SCOPES = [
  { value: 'https://www.googleapis.com/auth/cloud-platform', label: 'Cloud Platform (full access)' },
  { value: 'https://www.googleapis.com/auth/calendar', label: 'Calendar' },
  { value: 'https://www.googleapis.com/auth/pubsub', label: 'Pub/Sub' },
  { value: 'https://www.googleapis.com/auth/bigquery', label: 'BigQuery' },
  { value: 'https://www.googleapis.com/auth/devstorage.full_control', label: 'Cloud Storage (full control)' },
  { value: 'https://www.googleapis.com/auth/drive', label: 'Drive' },
  { value: 'https://www.googleapis.com/auth/spreadsheets', label: 'Sheets' },
  { value: 'https://www.googleapis.com/auth/gmail.readonly', label: 'Gmail (read-only)' },
  { value: 'https://www.googleapis.com/auth/userinfo.email', label: 'User info (email)' },
];

// In-memory storage of submitted credentials for the duration of the OAuth round-trip.
// Key = random state passed in the authorization URL.
const pendingAuths = new Map();

function getRedirectUri(req) {
  return `${req.protocol}://${req.get('host')}/oauth2callback`;
}

function renderForm({ error } = {}) {
  const scopeCheckboxes = AVAILABLE_SCOPES.map(
    (s) => `
      <label class="scope">
        <input type="checkbox" name="scopes" value="${s.value}">
        ${s.label}
        <span class="scope-value">${s.value}</span>
      </label>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GCP OAuth2 Consent</title>
<style>
  body { font-family: sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; color: #202124; }
  h1 { font-size: 1.4rem; }
  label.field { display: block; margin: 16px 0 4px; font-weight: 600; }
  input[type=text], input[type=password] { width: 100%; padding: 8px; box-sizing: border-box; }
  .scopes { border: 1px solid #ddd; border-radius: 6px; padding: 8px 12px; max-height: 260px; overflow-y: auto; }
  label.scope { display: block; font-weight: normal; margin: 6px 0; }
  .scope-value { display: block; margin-left: 24px; color: #5f6368; font-size: 0.8rem; }
  button { margin-top: 20px; padding: 10px 20px; cursor: pointer; }
  .error { color: #d93025; margin-top: 12px; }
</style>
</head>
<body>
  <h1>GCP OAuth2 Consent</h1>
  <form method="POST" action="/auth">
    <label class="field" for="clientId">Client ID</label>
    <input type="text" id="clientId" name="clientId" required>

    <label class="field" for="clientSecret">Client Secret</label>
    <input type="password" id="clientSecret" name="clientSecret" required>

    <label class="field">Scopes</label>
    <div class="scopes">${scopeCheckboxes}</div>

    ${error ? `<div class="error">${error}</div>` : ''}

    <button type="submit">Request consent</button>
  </form>
</body>
</html>`;
}

app.get('/', (req, res) => {
  res.send(renderForm());
});

app.post('/auth', (req, res) => {
  const { clientId, clientSecret } = req.body;
  const scopes = [].concat(req.body.scopes || []);

  if (!clientId || !clientSecret || scopes.length === 0) {
    return res.status(400).send(renderForm({ error: 'Client ID, Client Secret and at least one scope are required.' }));
  }

  const state = crypto.randomBytes(16).toString('hex');
  pendingAuths.set(state, { clientId, clientSecret });

  const oauth2Client = new OAuth2Client(clientId, clientSecret, getRedirectUri(req));
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: scopes,
    state,
  });
  res.redirect(url);
});

app.get('/oauth2callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(`<p>Authorization denied: ${error}</p><p><a href="/">Back</a></p>`);
  }

  const pending = pendingAuths.get(state);
  if (!pending) {
    return res.status(400).send('<p>Session expired or invalid. Please start over.</p><p><a href="/">Back</a></p>');
  }
  pendingAuths.delete(state);

  try {
    const oauth2Client = new OAuth2Client(pending.clientId, pending.clientSecret, getRedirectUri(req));
    const { tokens } = await oauth2Client.getToken(code);

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Tokens received</title>
<style>
  body { font-family: sans-serif; max-width: 640px; margin: 40px auto; padding: 0 16px; color: #202124; }
  h1 { font-size: 1.4rem; }
  label { display: block; font-weight: 600; margin-top: 16px; }
  textarea { width: 100%; padding: 8px; box-sizing: border-box; font-family: monospace; }
</style>
</head>
<body>
  <h1>Authentication successful</h1>

  <label for="accessToken">Access Token</label>
  <textarea id="accessToken" rows="3" readonly>${tokens.access_token || ''}</textarea>

  <label for="refreshToken">Refresh Token</label>
  <textarea id="refreshToken" rows="3" readonly>${tokens.refresh_token || '(no refresh token returned — make sure prompt=consent and access_type=offline are set)'}</textarea>

  <p><a href="/">Back to form</a></p>
</body>
</html>`);
  } catch (err) {
    res.status(500).send(`<p>Error exchanging code: ${err.message}</p><p><a href="/">Back</a></p>`);
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
