// server.js
const express = require('express');
const dns = require('dns');
const cors = require('cors');
const axios = require('axios');
const { http, https } = require('follow-redirects');
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Redirect Tracker
app.post('/api/redirect', async (req, res) => {
  const { url } = req.body;
  try {
    const protocol = url.startsWith('https') ? https : http;
    const redirects = [];
    const reqOptions = {
      maxRedirects: 10,
      timeout: 10000,
    };

    const instance = axios.create({
      maxRedirects: 10,
      timeout: 10000,
      validateStatus: null,
    });

    const response = await instance.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0'
      }
    });

    redirects.push({
      url: response.request.res.responseUrl || url,
      status: response.status,
    });

    res.json({ redirects });
  } catch (err) {
    res.status(500).json({ error: err.toString() });
  }
});

// CNAME Lookup
app.get('/api/cname', (req, res) => {
  const { domain } = req.query;
  dns.resolveCname(domain, (err, addresses) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ cname: addresses });
  });
});

// CAA Lookup
app.get('/api/caa', (req, res) => {
  const { domain } = req.query;
  dns.resolve(domain, 'CAA', (err, records) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ caa: records });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});