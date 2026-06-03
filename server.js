const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const multer = require('multer');
const compression = require('compression');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  pingTimeout: 20000,
  pingInterval: 10000,
  transports: ['websocket', 'polling'],
  perMessageDeflate: { threshold: 512 }
});



app.use(compression());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads')));

// ── Config ──
const SALT_ROUNDS = 10;
const MAX_MSG_LENGTH = 2000;
const RATE_LIMIT_WINDOW = 5000;
const RATE_LIMIT_MAX = 15;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');

[DATA_DIR, UPLOADS_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ── Persistent secrets ──
// First run: generate and save to data/secrets.json
// Every restart: load from disk — keeps JWT tokens and message decryption working
// Set JWT_SECRET env var to override (recommended for AWS/production)
const SECRETS_FILE = path.join(DATA_DIR, 'secrets.json');

function loadSecrets() {
  if (process.env.JWT_SECRET) {
    const msgKey = process.env.MSG_ENC_KEY
      ? Buffer.from(process.env.MSG_ENC_KEY, 'hex')
      : crypto.createHash('sha256').update(process.env.JWT_SECRET + ':msg-enc').digest();
    return { jwtSecret: process.env.JWT_SECRET, msgEncKey: msgKey };
  }
  if (fs.existsSync(SECRETS_FILE)) {
    try {
      const s = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8'));
      if (s.jwtSecret && s.msgEncKey) {
        console.log('Loaded secrets from disk');
        return { jwtSecret: s.jwtSecret, msgEncKey: Buffer.from(s.msgEncKey, 'hex') };
      }
    } catch {}
  }
  // First run — generate fresh secrets and persist them
  const raw = { jwtSecret: crypto.randomBytes(64).toString('hex'), msgEncKey: crypto.randomBytes(32).toString('hex') };
  fs.writeFileSync(SECRETS_FILE, JSON.stringify(raw, null, 2), 'utf8');
  try { fs.chmodSync(SECRETS_FILE, 0o600); } catch {}
  console.log('Generated new secrets, saved to', SECRETS_FILE);
  return { jwtSecret: raw.jwtSecret, msgEncKey: Buffer.from(raw.msgEncKey, 'hex') };
}

const { jwtSecret: JWT_SECRET, msgEncKey: MSG_ENC_KEY } = loadSecrets();

// ── AES-256-GCM Message Encryption ──

function encryptText(plaintext) {
  if (!plaintext) return null;
  const iv = crypto.randomBytes(12); // 96-bit IV (GCM standard)
  const cipher = crypto.createCipheriv('aes-256-gcm', MSG_ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag(); // 128-bit auth tag — detects any tampering
  return `${iv.toString('base64')}:${tag.toString('base64')}:${encrypted.toString('base64')}`;
}

function decryptText(stored) {
  if (!stored) return '';
  // Legacy plain text (pre-encryption messages) — if it doesn't look like iv:tag:data, return as-is
  if (!stored.includes(':')) return stored;
  try {
    const parts = stored.split(':');
    if (parts.length !== 3) return stored;
    const [ivB64, tagB64, dataB64] = parts;
    const iv  = Buffer.from(ivB64,  'base64');
    const tag  = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64,'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', MSG_ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(data, undefined, 'utf8') + decipher.final('utf8');
  } catch {
    return '[message could not be decrypted]';
  }
}

// ── JSON File DB ──
const DB_FILES = {
  users:    path.join(DATA_DIR, 'users.json'),
  rooms:    path.join(DATA_DIR, 'rooms.json'),
  messages: path.join(DATA_DIR, 'messages.json'),
};

function readDB(key) {
  try {
    if (!fs.existsSync(DB_FILES[key])) {
      return key === 'rooms'
        ? { general: { owner: null, private: false, createdAt: new Date().toISOString() } }
        : {};
    }
    return JSON.parse(fs.readFileSync(DB_FILES[key], 'utf8'));
  } catch { return {}; }
}

function writeDB(key, data) {
  // Atomic write via temp file — prevents corruption on crash
  const tmp = DB_FILES[key] + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, DB_FILES[key]);
}

let usersDB    = readDB('users');
let roomsDB    = readDB('rooms');
let messagesDB = readDB('messages');
if (!messagesDB.general) messagesDB.general = [];

setInterval(() => {
  writeDB('users', usersDB);
  writeDB('rooms', roomsDB);
  writeDB('messages', messagesDB);
}, 10000);

process.on('SIGINT', () => {
  writeDB('users', usersDB);
  writeDB('rooms', roomsDB);
  writeDB('messages', messagesDB);
  process.exit(0);
});

// ── In-memory state ──
const onlineUsers = {};
const rateLimits  = {};
const typingUsers = {};

// ── Multer ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /jpeg|jpg|png|gif|webp/;
    cb(null, ok.test(file.mimetype) && ok.test(path.extname(file.originalname).toLowerCase()));
  }
});

// ── Helpers ──
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#x27;').trim().slice(0, MAX_MSG_LENGTH);
}

function getDMRoomId(a, b) {
  return 'dm:' + crypto.createHash('sha256').update([a,b].sort().join(':')).digest('hex').slice(0,16);
}

function checkRateLimit(socketId) {
  const now = Date.now();
  if (!rateLimits[socketId] || now - rateLimits[socketId].windowStart > RATE_LIMIT_WINDOW) {
    rateLimits[socketId] = { count: 1, windowStart: now };
    return true;
  }
  if (rateLimits[socketId].count >= RATE_LIMIT_MAX) return false;
  rateLimits[socketId].count++;
  return true;
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function getOnlineUsernames() {
  return [...new Set(Object.values(onlineUsers).map(u => u.username))];
}

function getRoomList() {
  return Object.entries(roomsDB)
    .filter(([, r]) => !r.private)
    .map(([name, r]) => ({ name, owner: r.owner, createdAt: r.createdAt }));
}

function findSocketByUsername(username) {
  return Object.entries(onlineUsers).find(([, u]) => u.username === username);
}

// Decrypt stored message before sending to client
function prepareMessage(msg) {
  if (msg.deleted) return { ...msg, text: '', imageUrl: null };
  return { ...msg, text: msg.text ? decryptText(msg.text) : '' };
}

// ── REST Auth ──
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const clean = sanitize(username);
  if (clean.length < 3 || clean.length > 20) return res.status(400).json({ error: 'Username must be 3–20 chars' });
  if (!/^[a-zA-Z0-9_]+$/.test(clean)) return res.status(400).json({ error: 'Letters, numbers, underscores only' });
  if (password.length < 6) return res.status(400).json({ error: 'Password min 6 chars' });
  if (usersDB[clean]) return res.status(409).json({ error: 'Username taken' });

  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  usersDB[clean] = { passwordHash, createdAt: new Date().toISOString() };
  writeDB('users', usersDB);
  const token = jwt.sign({ username: clean }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: clean });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Required fields missing' });
  const clean = sanitize(username);
  const user = usersDB[clean];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ username: clean }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: clean });
});

// ── Image Upload ──
app.post('/api/upload', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const payload = verifyToken(auth.replace('Bearer ', ''));
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  upload.single('image')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message || 'Upload failed' });
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    res.json({ url: `/uploads/${req.file.filename}` });
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── Socket.IO Auth Middleware ──
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication required'));
  const payload = verifyToken(token);
  if (!payload) return next(new Error('Invalid or expired token'));
  socket.username = payload.username;
  next();
});

io.on('connection', (socket) => {
  const username = socket.username;
  onlineUsers[socket.id] = { username, socketId: socket.id };

  socket.emit('room list', getRoomList());
  io.emit('online users', getOnlineUsernames());
  socket.join('general');

  const generalHistory = (messagesDB.general || []).slice(-100).map(prepareMessage);
  socket.emit('history', { room: 'general', messages: generalHistory });
  socket.emit('system message', `Welcome back, ${username}!`);

  // ── Rooms ──
  socket.on('create room', (roomName) => {
    const clean = sanitize(roomName).replace(/\s+/g, '-').toLowerCase();
    if (!clean || clean.length < 1 || clean.length > 30) return;
    if (roomsDB[clean]) return socket.emit('error message', 'Room already exists');
    roomsDB[clean] = { owner: username, private: false, createdAt: new Date().toISOString() };
    messagesDB[clean] = [];
    io.emit('room list', getRoomList());
    io.emit('system message', `#${clean} created by ${username}`);
  });

  socket.on('delete room', (roomName) => {
    if (!roomsDB[roomName]) return;
    if (roomsDB[roomName].owner !== username) return socket.emit('error message', 'Owner only');
    if (roomName === 'general') return socket.emit('error message', 'Cannot delete #general');
    delete roomsDB[roomName];
    delete messagesDB[roomName];
    io.emit('room list', getRoomList());
    io.emit('system message', `#${roomName} was deleted`);
  });

  socket.on('join room', (room) => {
    if (!roomsDB[room]) return socket.emit('error message', 'Room not found');
    socket.join(room);
    const msgs = (messagesDB[room] || []).slice(-100).map(prepareMessage);
    socket.emit('history', { room, messages: msgs });
  });

  // ── Typing ──
  socket.on('typing start', (room) => {
    if (!typingUsers[room]) typingUsers[room] = new Set();
    typingUsers[room].add(username);
    socket.to(room).emit('typing update', { room, users: [...typingUsers[room]] });
  });

  socket.on('typing stop', (room) => {
    if (typingUsers[room]) {
      typingUsers[room].delete(username);
      socket.to(room).emit('typing update', { room, users: [...typingUsers[room]] });
    }
  });

  // ── DM ──
  socket.on('start dm', (targetUsername) => {
    if (targetUsername === username) return;
    const dmRoom = getDMRoomId(username, targetUsername);
    if (!roomsDB[dmRoom]) {
      roomsDB[dmRoom] = { owner: null, private: true, members: [username, targetUsername] };
      messagesDB[dmRoom] = [];
    }
    socket.join(dmRoom);
    socket.emit('dm started', { roomId: dmRoom, with: targetUsername });
    const msgs = (messagesDB[dmRoom] || []).slice(-100).map(prepareMessage);
    socket.emit('history', { room: dmRoom, messages: msgs });

    const targetEntry = findSocketByUsername(targetUsername);
    if (targetEntry) io.to(targetEntry[0]).emit('dm invite', { roomId: dmRoom, from: username });
  });

  socket.on('join dm', (dmRoom) => {
    if (!roomsDB[dmRoom]?.private) return;
    if (!roomsDB[dmRoom].members.includes(username)) return socket.emit('error message', 'Not authorized');
    socket.join(dmRoom);
    const msgs = (messagesDB[dmRoom] || []).slice(-100).map(prepareMessage);
    socket.emit('history', { room: dmRoom, messages: msgs });
  });

  // ── Send Message ──
  socket.on('chat message', (msg) => {
    if (!checkRateLimit(socket.id)) return socket.emit('error message', 'Slow down!');
    if (!msg.room || (!msg.text && !msg.imageUrl)) return;
    if (!roomsDB[msg.room]) return;
    if (roomsDB[msg.room].private && !roomsDB[msg.room].members.includes(username)) return;

    const plainText = msg.text ? sanitize(msg.text) : '';

    const stored = {
      id:       uuidv4(),
      user:     username,
      text:     plainText ? encryptText(plainText) : '',  // AES-256-GCM encrypted at rest
      imageUrl: msg.imageUrl || null,
      room:     msg.room,
      time:     new Date().toISOString(),
      deleted:  false,
      replyTo:  msg.replyTo || null
    };

    if (!messagesDB[msg.room]) messagesDB[msg.room] = [];
    messagesDB[msg.room].push(stored);
    if (messagesDB[msg.room].length > 500) messagesDB[msg.room].splice(0, messagesDB[msg.room].length - 500);

    // Broadcast plaintext to clients (they never see the encrypted form)
    io.to(msg.room).emit('chat message', { ...stored, text: plainText });
    socket.emit('message status', { id: stored.id, status: 'delivered' });

    // Offline DM notification
    if (roomsDB[msg.room]?.private) {
      const other = roomsDB[msg.room].members.find(m => m !== username);
      const otherEntry = findSocketByUsername(other);
      if (!otherEntry && usersDB[other]) {
        if (!usersDB[other].pendingNotifs) usersDB[other].pendingNotifs = [];
        usersDB[other].pendingNotifs.push({ from: username, room: msg.room, preview: plainText.slice(0, 50) });
      }
    }
  });

  // ── Delete Message ──
  socket.on('delete message', ({ room, messageId }) => {
    if (!room || !messageId) return;
    if (!roomsDB[room]) return socket.emit('error message', 'Room not found');
    if (roomsDB[room].private && !roomsDB[room].members.includes(username)) return;

    const msgs = messagesDB[room];
    if (!msgs) return;
    const idx = msgs.findIndex(m => m.id === messageId);
    if (idx === -1) return socket.emit('error message', 'Message not found');

    const msg = msgs[idx];
    if (msg.user !== username) return socket.emit('error message', 'Can only delete your own messages');
    if (msg.deleted) return;

    // Soft-delete: wipe content, keep record for history integrity
    msgs[idx] = { ...msg, text: '', imageUrl: null, deleted: true, deletedAt: new Date().toISOString() };

    // Tell everyone in the room to remove it from their UI
    io.to(room).emit('message deleted', { room, messageId });
  });

  // ── Mark Read ──
  socket.on('mark read', ({ room, messageId }) => {
    const senderEntry = findSocketByUsername(username);
    if (senderEntry) io.to(senderEntry[0]).emit('message status', { id: messageId, status: 'read' });
  });

  // Pending notifications on reconnect
  if (usersDB[username]?.pendingNotifs?.length) {
    const notifs = usersDB[username].pendingNotifs;
    usersDB[username].pendingNotifs = [];
    socket.emit('pending notifications', notifs);
  }

  socket.on('disconnect', () => {
    delete onlineUsers[socket.id];
    delete rateLimits[socket.id];
    Object.keys(typingUsers).forEach(room => {
      if (typingUsers[room]?.has(username)) {
        typingUsers[room].delete(username);
        socket.to(room).emit('typing update', { room, users: [...typingUsers[room]] });
      }
    });
    io.emit('online users', getOnlineUsernames());
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Pulse Chat → http://localhost:${PORT}`));
