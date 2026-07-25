const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thendisch_yt_destek_secure_jwt_key_2026';

// Security Headers (Sizden Gelenler Standard)
app.use(
  helmet({
    contentSecurityPolicy: false, // Allow inline styles & fonts for single-page UI
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Persistent Storage Directories (Railway Persistent Volume Uyumlu)
// Railway Volume Mount Path: /app/data veya process.env.RAILWAY_VOLUME_MOUNT_PATH
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'data');
const SNAPSHOTS_DIR = path.join(DATA_DIR, 'snapshots');
const BACKUP_FILE = path.join(DATA_DIR, 'backup.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(SNAPSHOTS_DIR)) fs.mkdirSync(SNAPSHOTS_DIR, { recursive: true });

console.log(`🛡️ Persistent Volume Hafıza Dizin: ${DATA_DIR}`);

// Owner Credentials (sizden-gelenler standard)
const OWNER_USER = 'thendisch';
const DEFAULT_PASS_HASH = '$2b$12$GY9WWFuKfr1Os.zJ6QJOmO5iOdjsNfOJbXlRHrlUWedAPBpc9hvye';

// JWT Auth Middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'Yetkisiz erişim. Lütfen giriş yapın.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Oturum süresi dolmuş veya geçersiz.' });
    req.user = user;
    next();
  });
}

// POST /api/login - Owner & Staff Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, error: 'Kullanıcı adı ve şifre gereklidir.' });
  }

  if (username.toLowerCase() === OWNER_USER) {
    const isValid = password === 'thendisch2026' || bcrypt.compareSync(password, DEFAULT_PASS_HASH);
    if (isValid) {
      const token = jwt.sign({ username: OWNER_USER, role: 'owner' }, JWT_SECRET, { expiresIn: '7d' });
      return res.json({ success: true, token, username: OWNER_USER, role: 'owner' });
    }
  }

  return res.status(401).json({ success: false, error: 'Hatalı kullanıcı adı veya şifre.' });
});

// GET /api/verify - Check token validity
app.get('/api/verify', (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.json({ authenticated: false });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.json({ authenticated: false });
    return res.json({ authenticated: true, user });
  });
});

// GET /api/backup - Retrieve persistent memory snapshot from Railway Volume
app.get('/api/backup', (req, res) => {
  if (fs.existsSync(BACKUP_FILE)) {
    try {
      const data = fs.readFileSync(BACKUP_FILE, 'utf8');
      return res.json({ success: true, backup: JSON.parse(data), storagePath: DATA_DIR });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Yedek okunamadı' });
    }
  }
  return res.json({ success: false, message: 'Railway Volume üzerinde henüz kayıtlı yedek yok' });
});

// POST /api/backup - Persist memory snapshot on Railway Volume (Rolling Disk Snapshots)
app.post('/api/backup', (req, res) => {
  try {
    const payload = req.body;
    const timestamp = new Date().toISOString();
    payload.serverTimestamp = timestamp;

    // 1. Write main backup file to Railway Volume
    fs.writeFileSync(BACKUP_FILE, JSON.stringify(payload, null, 2), 'utf8');

    // 2. Write rolling snapshot file (sizden-gelenler persistent volume engine)
    const snapshotFileName = `snapshot_${Date.now()}.json`;
    fs.writeFileSync(path.join(SNAPSHOTS_DIR, snapshotFileName), JSON.stringify(payload, null, 2), 'utf8');

    // Keep last 20 snapshots on volume
    const files = fs.readdirSync(SNAPSHOTS_DIR).sort().reverse();
    if (files.length > 20) {
      files.slice(20).forEach(file => {
        try { fs.unlinkSync(path.join(SNAPSHOTS_DIR, file)); } catch (e) {}
      });
    }

    return res.json({ success: true, message: 'Yedek ve rolling snapshot Railway Volume diskine güvenle yazıldı', timestamp, path: DATA_DIR });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Volume diske kaydetme hatası: ' + err.message });
  }
});

// GET /api/snapshots - List available rolling snapshots from Railway Volume
app.get('/api/snapshots', (req, res) => {
  try {
    const files = fs.readdirSync(SNAPSHOTS_DIR).sort().reverse();
    const snapshots = files.map(file => {
      const stats = fs.statSync(path.join(SNAPSHOTS_DIR, file));
      return { filename: file, time: stats.mtime, size: stats.size };
    });
    return res.json({ success: true, snapshots, storagePath: DATA_DIR });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Serve index.html for SPA routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🛡️ Sizden-Gelenler Railway Volume Hafızalı Sunucu Aktif: http://localhost:${PORT}`);
});
