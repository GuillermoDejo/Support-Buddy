const express = require('express');
const dns = require('dns');
const https = require('https');
const tls = require('tls');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // sirve tu HTML estático

app.post('/api/domain-check', async (req, res) => {
  const domain = req.body.domain;
  if (!domain) return res.status(400).json({ error: 'No domain provided' });

  const results = {
    domain,
    cname: null,
    cnameValid: false,
    cnameFlow: 'Unknown',
    caa: null,
    caaValid: null,
    certValid: null,
    clickHandler: null,
  };

  // CNAME
  try {
    const cname = await new Promise(resolve => {
      dns.resolveCname(domain, (err, addresses) => {
        if (err || !addresses.length) return resolve(null);
        resolve(addresses[0]);
      });
    });
    results.cname = cname;
    if (cname) {
      if (cname.includes('appsflyer.com')) results.cnameValid = true;
      if (cname.includes('customlinks.appsflyer.com')) results.cnameFlow = 'Branded Domain Flow';
      else if (cname.includes('esplinks.appsflyer.com')) results.cnameFlow = 'ESP Flow';
      else results.cnameFlow = 'Not pointing to recognized flow';
    } else {
      results.cnameFlow = 'No CNAME found';
    }
  } catch {
    results.cname = 'Error checking CNAME';
  }

  // CAA
// CAA con fallback al dominio raíz si no se encuentra en el subdominio
try {
  const caaDomains = [domain];
  const parts = domain.split('.');
  if (parts.length > 2) {
    const root = parts.slice(-2).join('.');
    if (!caaDomains.includes(root)) caaDomains.push(root);
  }

  let caa = [];
  for (const d of caaDomains) {
    caa = await new Promise(resolve => {
      dns.resolve(d, 'CAA', (err, records) => {
        if (err || !records.length) return resolve([]);
        resolve(records);
      });
    });
    if (caa.length) break;
  }

  results.caa = caa;
  const caaText = JSON.stringify(caa);
  if (!caa.length || caaText.includes('letsencrypt.org')) results.caaValid = true;
  else results.caaValid = false;
} catch {
  results.caa = 'Error checking CAA';
}

  // SSL Cert expiration
  try {
    const socket = tls.connect(443, domain, { servername: domain, timeout: 3000 }, () => {
      const cert = socket.getPeerCertificate();
      if (cert && cert.valid_to) {
        const expiry = new Date(cert.valid_to);
        results.certValid = expiry > new Date();
      } else {
        results.certValid = false;
      }
      socket.end();
    });
    socket.on('error', () => (results.certValid = false));
  } catch {
    results.certValid = false;
  }

  // Click handler
  try {
    const response = await axios.get(`https://${domain}/onelink`, { timeout: 5000 });
    if (typeof response.data === 'string' && response.data.trim() === 'ok') {
      results.clickHandler = 'Responded OK';
    } else {
      results.clickHandler = 'Responded but not OK';
    }
  } catch {
    results.clickHandler = 'Not reachable or error';
  }

  setTimeout(() => res.json(results), 3000); // da tiempo al socket SSL
});

const puppeteer = require('puppeteer');

const userAgents = {
  ios: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
  android: 'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.105 Mobile Safari/537.36',
  desktop: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
};

app.post('/api/redirect', async (req, res) => {
  const { url, device = 'desktop' } = req.body;
  if (!url) return res.status(400).json({ error: 'No URL provided' });

  const userAgent = userAgents[device.toLowerCase()] || userAgents.desktop;
  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox'] });
  const page = await browser.newPage();

  await page.setUserAgent(userAgent);
  const redirects = [];

  page.on('response', async (response) => {
    const request = response.request();
    const url = response.url();
    const status = response.status();
    const frame = request.frame();

    const isMainDocument = request.resourceType() === 'document' && (!frame || frame.parentFrame() === null);

    if (isMainDocument && /^https:\/\//.test(url)) {
      redirects.push({ url, status });
    }
  });

  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
    await page.waitForTimeout(5000);
  } catch (error) {
    console.error('Navigation error:', error.message);
  } finally {
    await browser.close();
    const unique = Array.from(new Map(redirects.map(i => [i.url, i])).values());
    res.json({ chain: unique });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🟢 Redirect server running at http://localhost:${PORT}`);
});