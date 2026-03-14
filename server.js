const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const mime = require('mime-types');
const marked = require('marked');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const META_FILE = path.join(__dirname, 'metadata.json');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Metadata store: { [filename]: { password: hashedOrNull, created: date, size, originalName, locked } }
let metadata = {};
if (fs.existsSync(META_FILE)) {
  try { metadata = JSON.parse(fs.readFileSync(META_FILE, 'utf8')); } catch(e) { metadata = {}; }
}
function saveMeta() { fs.writeFileSync(META_FILE, JSON.stringify(metadata, null, 2)); }

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Fallback — serve index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const safe = Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 500 * 1024 * 1024 } });

// Auth middleware
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Admin access required' });
  next();
}

// List files
app.get('/api/files', (req, res) => {
  const files = fs.existsSync(UPLOAD_DIR) ? fs.readdirSync(UPLOAD_DIR) : [];
  const result = files.map(filename => {
    const stat = fs.statSync(path.join(UPLOAD_DIR, filename));
    const meta = metadata[filename] || {};
    return {
      id: filename,
      name: meta.originalName || filename,
      filename,
      size: stat.size,
      created: meta.created || stat.birthtime,
      modified: stat.mtime,
      mimeType: mime.lookup(filename) || 'application/octet-stream',
      locked: !!(meta.password),
      ext: path.extname(filename).toLowerCase()
    };
  });
  result.sort((a, b) => new Date(b.modified) - new Date(a.modified));
  res.json(result);
});

// Upload file (admin only)
app.post('/api/upload', requireAdmin, upload.array('files'), async (req, res) => {
  const results = [];
  for (const file of req.files) {
    const password = req.body.password;
    let hashedPwd = null;
    if (password) hashedPwd = await bcrypt.hash(password, 10);
    metadata[file.filename] = {
      originalName: file.originalname,
      password: hashedPwd,
      created: new Date().toISOString(),
      size: file.size
    };
    results.push({ filename: file.filename, name: file.originalname });
  }
  saveMeta();
  res.json({ success: true, files: results });
});

// Create txt/md file (admin only)
app.post('/api/create', requireAdmin, async (req, res) => {
  const { name, content, password, ext } = req.body;
  const extension = ext || 'txt';
  const safeName = Date.now() + '_' + name.replace(/[^a-zA-Z0-9._-]/g, '_') + '.' + extension;
  fs.writeFileSync(path.join(UPLOAD_DIR, safeName), content || '');
  let hashedPwd = null;
  if (password) hashedPwd = await bcrypt.hash(password, 10);
  metadata[safeName] = {
    originalName: name + '.' + extension,
    password: hashedPwd,
    created: new Date().toISOString(),
    size: Buffer.byteLength(content || '')
  };
  saveMeta();
  res.json({ success: true, filename: safeName, name: name + '.' + extension });
});

// Verify access (admin or file password)
app.post('/api/verify', async (req, res) => {
  const { filename, password, adminToken } = req.body;
  if (adminToken === ADMIN_PASSWORD) return res.json({ access: true, isAdmin: true });
  const meta = metadata[filename] || {};
  if (!meta.password) return res.json({ access: true, isAdmin: false });
  const ok = await bcrypt.compare(password || '', meta.password);
  res.json({ access: ok, isAdmin: false });
});

// Get file content (text/md) - requires auth check from client
app.post('/api/content', async (req, res) => {
  const { filename, password, adminToken } = req.body;
  const meta = metadata[filename] || {};
  let hasAccess = false;
  if (adminToken === ADMIN_PASSWORD) hasAccess = true;
  else if (!meta.password) hasAccess = true;
  else hasAccess = await bcrypt.compare(password || '', meta.password);
  if (!hasAccess) return res.status(403).json({ error: 'Access denied' });
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  const content = fs.readFileSync(filePath, 'utf8');
  const ext = path.extname(filename).toLowerCase();
  res.json({ content, ext });
});

// Edit file content (admin only)
app.post('/api/edit', requireAdmin, (req, res) => {
  const { filename, content } = req.body;
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Not found' });
  fs.writeFileSync(filePath, content);
  if (metadata[filename]) {
    metadata[filename].size = Buffer.byteLength(content);
    saveMeta();
  }
  res.json({ success: true });
});

// Set/change file password (admin only)
app.post('/api/setpassword', requireAdmin, async (req, res) => {
  const { filename, password } = req.body;
  if (!metadata[filename]) return res.status(404).json({ error: 'Not found' });
  if (password) metadata[filename].password = await bcrypt.hash(password, 10);
  else metadata[filename].password = null;
  saveMeta();
  res.json({ success: true });
});

// Delete file (admin only)
app.delete('/api/files/:filename', requireAdmin, (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(UPLOAD_DIR, filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  delete metadata[filename];
  saveMeta();
  res.json({ success: true });
});

// Rename file (admin only)
app.post('/api/rename', requireAdmin, (req, res) => {
  const { filename, newName } = req.body;
  if (!metadata[filename]) return res.status(404).json({ error: 'Not found' });
  metadata[filename].originalName = newName;
  saveMeta();
  res.json({ success: true });
});

// Serve/download file with auth
app.post('/api/serve', async (req, res) => {
  const { filename, password, adminToken } = req.body;
  const meta = metadata[filename] || {};
  let hasAccess = false;
  if (adminToken === ADMIN_PASSWORD) hasAccess = true;
  else if (!meta.password) hasAccess = true;
  else hasAccess = await bcrypt.compare(password || '', meta.password);
  if (!hasAccess) return res.status(403).json({ error: 'Access denied' });
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  const mimeType = mime.lookup(filename) || 'application/octet-stream';
  res.setHeader('Content-Type', mimeType);
  res.setHeader('Content-Disposition', `inline; filename="${meta.originalName || filename}"`);
  fs.createReadStream(filePath).pipe(res);
});

// Download file
app.post('/api/download', async (req, res) => {
  const { filename, password, adminToken } = req.body;
  const meta = metadata[filename] || {};
  let hasAccess = false;
  if (adminToken === ADMIN_PASSWORD) hasAccess = true;
  else if (!meta.password) hasAccess = true;
  else hasAccess = await bcrypt.compare(password || '', meta.password);
  if (!hasAccess) return res.status(403).json({ error: 'Access denied' });
  const filePath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).send('Not found');
  res.download(filePath, meta.originalName || filename);
});

app.listen(PORT, () => {
  console.log(`VaultFS running on port ${PORT}`);
  console.log(`Admin password: ${ADMIN_PASSWORD}`);
});
