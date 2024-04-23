require('dotenv').config();
const express = require('express');
const { OAuth2Client } = require('google-auth-library'); // Importation ajustée ici

const app = express();
const port = 3000;

const oauth2Client = new OAuth2Client(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

app.get('/auth', (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/pubsub', 'https://www.googleapis.com/auth/bigquery', 'https://www.googleapis.com/auth/devstorage.write_only']
  });
  res.redirect(url);
});

app.get('/oauth2callback', async (req, res) => {
  const { tokens } = await oauth2Client.getToken(req.query.code);
  oauth2Client.setCredentials(tokens);
  res.send('Authentication successful, check the server logs for tokens');
  console.log(tokens); // Contiendra l'access token et le refresh token
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
