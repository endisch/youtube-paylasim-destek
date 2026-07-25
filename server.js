const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Server-side persistent storage directory
const DATA_DIR = path.join(__dirname, 'data');
const BACKUP_FILE = path.join(DATA_DIR, 'backup.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// GET /api/backup - Retrieve server-saved memory snapshot
app.get('/api/backup', (req, res) => {
  if (fs.existsSync(BACKUP_FILE)) {
    try {
      const data = fs.readFileSync(BACKUP_FILE, 'utf8');
      return res.json({ success: true, backup: JSON.parse(data) });
    } catch (err) {
      return res.status(500).json({ success: false, error: 'Yedek okunamadı' });
    }
  }
  return res.json({ success: false, message: 'Sunucuda henüz kayıtlı yedek yok' });
});

// POST /api/backup - Persist memory snapshot on Railway server
app.post('/api/backup', (req, res) => {
  try {
    const payload = req.body;
    payload.serverTimestamp = new Date().toISOString();
    fs.writeFileSync(BACKUP_FILE, JSON.stringify(payload, null, 2), 'utf8');
    return res.json({ success: true, message: 'Yedek sunucuya güvenle kaydedildi', timestamp: payload.serverTimestamp });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Sunucuya kaydetme hatası: ' + err.message });
  }
});

// Serve index.html for SPA routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 YouTube Paylaşım Destek Güvenlik & Hafıza Sunucusu Aktif: http://localhost:${PORT}`);
});
