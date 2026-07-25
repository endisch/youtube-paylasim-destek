const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Statik dosyaları sun
app.use(express.static(__dirname));

// Tüm yönlendirmeleri index.html'e yönlendir (SPA desteği)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 YouTube Paylaşım Destek sunucusu çalışıyor: http://localhost:${PORT}`);
});
