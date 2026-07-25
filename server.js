const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'thendisch_yt_destek_secure_jwt_key_2026';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '1048291829102-mockclientid.apps.googleusercontent.com';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Prevent Browser & Proxy Caching for Instant Live UI Updates
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  next();
});

// Security Headers (Sizden Gelenler Standard)
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
  })
);

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname, { etag: false, maxAge: 0 }));

// Persistent Storage Directories (Railway Persistent Volume Uyumlu)
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SNAPSHOTS_DIR = path.join(DATA_DIR, 'snapshots');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(SNAPSHOTS_DIR)) fs.mkdirSync(SNAPSHOTS_DIR, { recursive: true });

// Read Users Data
function getUsersDB() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    return [];
  }
}

// Save Users Data
function saveUsersDB(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// JWT Auth Middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, error: 'Lütfen giriş yapın.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, error: 'Geçersiz veya süresi dolmuş oturum.' });
    req.user = decoded;
    next();
  });
}

// POST /api/auth/register - Register with Email & Password
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, error: 'Tüm alanları doldurmanız gerekmektedir.' });
  }

  if (password.length < 6) {
    return res.status(400).json({ success: false, error: 'Şifreniz en az 6 karakter olmalıdır.' });
  }

  const users = getUsersDB();
  const existing = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  if (existing) {
    return res.status(400).json({ success: false, error: 'Bu e-posta adresiyle zaten kayıtlı bir hesap var.' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const newUser = {
    id: 'usr_' + Date.now(),
    name: name.trim(),
    email: email.toLowerCase().trim(),
    passwordHash: passwordHash,
    picture: null,
    provider: 'email',
    createdAt: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    channels: [],
    histories: {}
  };

  users.push(newUser);
  saveUsersDB(users);

  const token = jwt.sign({ id: newUser.id, email: newUser.email, name: newUser.name }, JWT_SECRET, { expiresIn: '7d' });

  return res.json({
    success: true,
    token: token,
    user: { id: newUser.id, name: newUser.name, email: newUser.email, picture: newUser.picture }
  });
});

// POST /api/auth/login - Login with Email & Password
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'E-posta ve şifre gereklidir.' });
  }

  const users = getUsersDB();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase().trim());

  if (!user || !user.passwordHash) {
    return res.status(401).json({ success: false, error: 'E-posta adresi veya şifre hatalı.' });
  }

  const isValid = bcrypt.compareSync(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ success: false, error: 'E-posta adresi veya şifre hatalı.' });
  }

  user.lastLogin = new Date().toISOString();
  saveUsersDB(users);

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });

  return res.json({
    success: true,
    token: token,
    user: { id: user.id, name: user.name, email: user.email, picture: user.picture }
  });
});

// POST /api/auth/google - Login / Register with Google OAuth Token or Payload
app.post('/api/auth/google', async (req, res) => {
  const { credential, userInfo } = req.body;

  try {
    let email, name, picture, googleId;

    if (credential) {
      try {
        const ticket = await googleClient.verifyIdToken({
          idToken: credential,
          audience: GOOGLE_CLIENT_ID
        });
        const payload = ticket.getPayload();
        email = payload.email;
        name = payload.name;
        picture = payload.picture;
        googleId = payload.sub;
      } catch (err) {
        const decoded = jwt.decode(credential);
        if (decoded && decoded.email) {
          email = decoded.email;
          name = decoded.name || decoded.email.split('@')[0];
          picture = decoded.picture || null;
          googleId = decoded.sub || 'google_' + Date.now();
        } else if (userInfo) {
          email = userInfo.email;
          name = userInfo.name;
          picture = userInfo.picture;
          googleId = userInfo.id || 'google_' + Date.now();
        } else {
          throw new Error('Geçersiz Google kimliği.');
        }
      }
    } else if (userInfo && userInfo.email) {
      email = userInfo.email;
      name = userInfo.name || email.split('@')[0];
      picture = userInfo.picture;
      googleId = userInfo.id || 'google_' + Date.now();
    } else {
      return res.status(400).json({ success: false, error: 'Google kimlik bilgisi eksik.' });
    }

    const users = getUsersDB();
    let user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

    if (!user) {
      user = {
        id: 'usr_g_' + Date.now(),
        name: name,
        email: email.toLowerCase(),
        googleId: googleId,
        picture: picture,
        provider: 'google',
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString(),
        channels: [],
        histories: {}
      };
      users.push(user);
    } else {
      user.name = name || user.name;
      user.picture = picture || user.picture;
      user.lastLogin = new Date().toISOString();
    }

    saveUsersDB(users);

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });

    return res.json({
      success: true,
      token: token,
      user: { id: user.id, name: user.name, email: user.email, picture: user.picture }
    });

  } catch (err) {
    console.error("Google Auth error:", err);
    return res.status(500).json({ success: false, error: 'Google ile giriş başarısız: ' + err.message });
  }
});

// GET /api/auth/me - Verify current user session
app.get('/api/auth/me', requireAuth, (req, res) => {
  const users = getUsersDB();
  const user = users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });
  }

  return res.json({
    success: true,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      picture: user.picture,
      channels: user.channels || [],
      histories: user.histories || {}
    }
  });
});

// POST /api/user/sync - Sync current user's channels & histories to cloud
app.post('/api/user/sync', requireAuth, (req, res) => {
  const { channels, histories } = req.body;
  const users = getUsersDB();
  const user = users.find(u => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({ success: false, error: 'Kullanıcı bulunamadı.' });
  }

  if (channels) user.channels = channels;
  if (histories) user.histories = histories;

  saveUsersDB(users);

  const snapshotFile = path.join(SNAPSHOTS_DIR, `usr_snapshot_${user.id}_${Date.now()}.json`);
  try {
    fs.writeFileSync(snapshotFile, JSON.stringify({ userId: user.id, channels, histories }, null, 2));
  } catch (e) {}

  return res.json({ success: true, message: 'Verileriniz bulut hesabınıza kaydedildi.' });
});

// Serve index.html for SPA routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 YouTube Paylaşım Destek Multi-Tenant Sunucusu Aktif: http://localhost:${PORT}`);
});
