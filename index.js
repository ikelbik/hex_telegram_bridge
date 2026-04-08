const express = require('express');
const https = require('https');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const BRIDGE_SECRET = process.env.BRIDGE_SECRET || '';
const BOOST_STAR_PRICES = [1, 2, 3, 5];

// Offset state (in-memory; Railway restarts reset it, which is fine)
let tgOffset = 0;

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Telegram-Init-Data, X-Bridge-Secret');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── helpers ───────────────────────────────────────────────────────────────────
function tgPost(method, payload) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(payload);
    const req = https.request({
      hostname: 'api.telegram.org',
      path: `/bot${BOT_TOKEN}/${method}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('bad_json')); } });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => { req.destroy(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

function verifyInitData(initData) {
  if (!initData) return { ok: false, error: 'init_data_empty' };
  const token = BOT_TOKEN.trim();
  if (!token) return { ok: false, error: 'bot_token_missing' };

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return { ok: false, error: 'hash_missing' };

  // Try both with and without 'signature' field (Telegram sometimes includes it)
  for (const skipSig of [true, false]) {
    const p = new URLSearchParams(initData);
    p.delete('hash');
    if (skipSig) p.delete('signature');

    const entries = [...p.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    const checkStr = entries.map(([k, v]) => `${k}=${v}`).join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(token).digest();
    const calcHash = crypto.createHmac('sha256', secretKey).update(checkStr).digest('hex');

    if (calcHash === hash) {
      const authDate = parseInt(p.get('auth_date') || '0', 10);
      const now = Math.floor(Date.now() / 1000);
      if (authDate <= 0 || (now - authDate) > 86400 * 30) return { ok: false, error: 'auth_expired' };
      return { ok: true };
    }
  }

  return { ok: false, error: 'signature_invalid' };
}

// Temporary debug endpoint — remove after fixing
app.post('/debug_verify', (req, res) => {
  const token = BOT_TOKEN.trim();
  const initData = req.body.telegram_init_data || req.headers['x-telegram-init-data'] || '';
  if (!initData) return res.json({ error: 'no_init_data' });

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  params.delete('hash');
  params.delete('signature');
  const entries = [...params.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const checkStr = entries.map(([k, v]) => `${k}=${v}`).join('\n');
  const secretKey = crypto.createHmac('sha256', 'WebAppData').update(token).digest();
  const calcHash = crypto.createHmac('sha256', secretKey).update(checkStr).digest('hex');

  res.json({
    hash_from_tg: hash,
    hash_computed: calcHash,
    match: calcHash === hash,
    token_length: token.length,
    token_first4: token.slice(0, 4),
    check_str_preview: checkStr.slice(0, 200),
  });
});

function getInitData(req) {
  return (req.body && req.body.telegram_init_data)
    || req.headers['x-telegram-init-data']
    || '';
}

function verifyBridgeSecret(req) {
  if (!BRIDGE_SECRET) return true;
  return req.headers['x-bridge-secret'] === BRIDGE_SECRET;
}

// ── POST /create_invoice ──────────────────────────────────────────────────────
app.post('/create_invoice', async (req, res) => {
  if (!BOT_TOKEN) return res.status(500).json({ success: false, error: 'BOT_TOKEN_not_set' });

  const auth = verifyInitData(getInitData(req));
  if (!auth.ok) return res.status(401).json({ success: false, error: auth.error });

  const boostIndex = parseInt(req.body.boost_index ?? -1, 10);
  if (boostIndex < 0 || boostIndex >= BOOST_STAR_PRICES.length)
    return res.status(422).json({ success: false, error: 'invalid_boost_index' });

  const starPrice = BOOST_STAR_PRICES[boostIndex];
  const label = String(req.body.title || 'Boost').slice(0, 32);

  try {
    const result = await tgPost('createInvoiceLink', {
      title: label,
      description: String(req.body.description || 'HexDrop boost').slice(0, 255),
      payload: String(req.body.payload || `boost_${boostIndex}_${Date.now()}`).slice(0, 128),
      provider_token: '',
      currency: 'XTR',
      prices: [{ label, amount: starPrice }],
    });

    if (!result.ok) return res.status(500).json({ success: false, error: 'telegram_error', description: result.description });
    res.json({ success: true, invoice_link: result.result });
  } catch (e) {
    res.status(500).json({ success: false, error: 'request_failed', details: e.message });
  }
});

// ── POST /answer_precheckout ──────────────────────────────────────────────────
app.post('/answer_precheckout', async (req, res) => {
  if (!BOT_TOKEN) return res.status(500).json({ ok: false, error: 'BOT_TOKEN_not_set' });

  const auth = verifyInitData(getInitData(req));
  if (!auth.ok) return res.status(401).json({ ok: false, error: auth.error });

  try {
    const updates = await tgPost('getUpdates', {
      offset: tgOffset,
      limit: 50,
      timeout: 0,
      allowed_updates: ['pre_checkout_query'],
    });

    if (!updates.ok) return res.status(500).json({ ok: false, error: 'getUpdates_failed' });

    let answered = 0;
    let maxId = tgOffset - 1;

    for (const upd of updates.result) {
      if (upd.update_id > maxId) maxId = upd.update_id;
      if (!upd.pre_checkout_query) continue;
      await tgPost('answerPreCheckoutQuery', { pre_checkout_query_id: upd.pre_checkout_query.id, ok: true });
      answered++;
    }

    if (maxId >= tgOffset) tgOffset = maxId + 1;

    res.json({ ok: true, answered, updates: updates.result.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'request_failed', details: e.message });
  }
});

// ── POST /send_message ────────────────────────────────────────────────────────
app.post('/send_message', async (req, res) => {
  if (!BOT_TOKEN) return res.status(500).json({ success: false, error: 'BOT_TOKEN_not_set' });
  if (!verifyBridgeSecret(req)) {
    return res.status(401).json({ success: false, error: 'bridge_secret_invalid' });
  }

  const chatId = req.body.chat_id;
  const text = typeof req.body.text === 'string' ? req.body.text : '';
  if (!chatId) return res.status(422).json({ success: false, error: 'chat_id_required' });
  if (!text) return res.status(422).json({ success: false, error: 'text_required' });

  const payload = {
    chat_id: chatId,
    text,
    parse_mode: typeof req.body.parse_mode === 'string' ? req.body.parse_mode : 'HTML',
  };
  if (req.body.reply_markup && typeof req.body.reply_markup === 'object') {
    payload.reply_markup = req.body.reply_markup;
  }
  if (typeof req.body.disable_web_page_preview === 'boolean') {
    payload.disable_web_page_preview = req.body.disable_web_page_preview;
  }

  try {
    const result = await tgPost('sendMessage', payload);
    if (!result.ok) {
      return res.status(500).json({
        success: false,
        error: 'telegram_error',
        description: result.description,
      });
    }
    res.json({ success: true, result: result.result });
  } catch (e) {
    res.status(500).json({ success: false, error: 'request_failed', details: e.message });
  }
});

// ── health ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ ok: true, service: 'hexdrop-tg-bridge' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Bridge listening on port ${PORT}`));
