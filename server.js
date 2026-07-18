// ============================================================
// pod-tracker-api — Software Engineer Daily Work Tracker API
// ============================================================
// Auth: JWT (30-day tokens).  Passwords: bcrypt (12 rounds).
//
// DEPLOY TO RENDER.COM:
//   1. Push this repo to GitHub
//   2. Create a new "Web Service" on Render.com pointing to this repo
//   3. Build Command:  npm install
//   4. Start Command:  node server.js
//   5. Add environment variables:
//        MONGODB_URI = <your MongoDB Atlas connection string>
//        JWT_SECRET  = <a long random secret string>
//   6. In MongoDB Atlas → Network Access → Add IP: 0.0.0.0/0
//      (allows Render's dynamic IPs to connect)
// ============================================================

require('dotenv').config();

const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');

const app  = express();
const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ENTRY_TYPES = [
  'task', 'issue', 'analysis', 'meeting', 'review', 'deployment',
  'planning', 'learning', 'support', 'mentoring', 'testing',
  'break', 'other',
];

// ── Middleware ─────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Root health check (used by Render.com) ────────────────────
app.get('/', (_req, res) => {
  res.json({ message: 'Work Tracker API', version: '1.0.0', status: 'ok' });
});

// ── MongoDB Connection ─────────────────────────────────────────
mongoose
  .connect(process.env.MONGODB_URI, { dbName: 'work_tracker' })
  .then(() => console.log('✅ Connected to MongoDB (work_tracker)'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ── User Schema & Model ────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    name:     { type: String, required: true, trim: true },
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true }, // bcrypt hash — never returned to client
  },
  { timestamps: true }
);
const User = mongoose.model('User', userSchema, 'users');

// ── Entry Schema & Model ───────────────────────────────────────
const entrySchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    task:   { type: String, required: true, trim: true },
    type:   {
      type: String,
      required: true,
      enum: ENTRY_TYPES,
    },
    date:   { type: String, required: true },        // YYYY-MM-DD
    mins:   { type: Number, required: true, min: 1 },
    start:  { type: String, default: '' },            // HH:MM (optional)
    ticket: { type: String, default: '', trim: true },
    notes:  { type: String, default: '' },
  },
  { timestamps: true }
);
entrySchema.index({ userId: 1, date: 1 });
const Entry = mongoose.model('Entry', entrySchema, 'entries');

// ── Auth Middleware ────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Unauthorized — missing token' });
  }
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
}

// ── Auth Routes ────────────────────────────────────────────────

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'name, email and password are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters' });
    }
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ success: false, error: 'An account with this email already exists' });
    }
    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ name, email, password: hash });
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    res.status(201).json({
      success: true,
      data: { token, user: { id: user._id, name: user.name, email: user.email } },
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'email and password are required' });
    }
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    // Use the same error message for both cases to prevent user enumeration
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      success: true,
      data: { token, user: { id: user._id, name: user.name, email: user.email } },
    });
  } catch (err) {
    next(err);
  }
});

// ── Entry Routes (all protected with requireAuth) ──────────────

// GET /api/entries?date=YYYY-MM-DD
app.get('/api/entries', requireAuth, async (req, res, next) => {
  try {
    const { date } = req.query;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return res.status(400).json({ success: false, error: 'Valid date query param required (YYYY-MM-DD)' });
    }
    const entries = await Entry.find({ userId: req.userId, date }).sort({ start: 1, createdAt: 1 });
    res.json({ success: true, data: entries });
  } catch (err) {
    next(err);
  }
});

// GET /api/entries/range?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/entries/range', requireAuth, async (req, res, next) => {
  try {
    const { from, to } = req.query;
    if (!from || !to || !DATE_RE.test(from) || !DATE_RE.test(to)) {
      return res.status(400).json({ success: false, error: 'from and to query params required (YYYY-MM-DD)' });
    }
    const entries = await Entry
      .find({ userId: req.userId, date: { $gte: from, $lte: to } })
      .sort({ date: 1, start: 1 });
    res.json({ success: true, data: entries });
  } catch (err) {
    next(err);
  }
});

// POST /api/entries — create a new entry
app.post('/api/entries', requireAuth, async (req, res, next) => {
  try {
    const { task, type, date, mins } = req.body;
    if (!task || !String(task).trim()) {
      return res.status(400).json({ success: false, error: 'task is required' });
    }
    if (!type || !ENTRY_TYPES.includes(type)) {
      return res.status(400).json({ success: false, error: `type must be one of: ${ENTRY_TYPES.join(', ')}` });
    }
    if (!date || !DATE_RE.test(date)) {
      return res.status(400).json({ success: false, error: 'date is required (YYYY-MM-DD)' });
    }
    if (mins === undefined || mins === null || Number.isNaN(Number(mins)) || Number(mins) < 1) {
      return res.status(400).json({ success: false, error: 'mins must be a number >= 1' });
    }
    const entry = new Entry({ ...req.body, userId: req.userId });
    await entry.save();
    res.status(201).json({ success: true, data: entry });
  } catch (err) {
    next(err);
  }
});

// PUT /api/entries/:id — update an entry (only owner can update)
app.put('/api/entries/:id', requireAuth, async (req, res, next) => {
  try {
    const { task, type, date, mins } = req.body;
    if (task !== undefined && !String(task).trim()) {
      return res.status(400).json({ success: false, error: 'task cannot be empty' });
    }
    if (type !== undefined && !ENTRY_TYPES.includes(type)) {
      return res.status(400).json({ success: false, error: `type must be one of: ${ENTRY_TYPES.join(', ')}` });
    }
    if (date !== undefined && !DATE_RE.test(date)) {
      return res.status(400).json({ success: false, error: 'date must be in YYYY-MM-DD format' });
    }
    if (mins !== undefined && (Number.isNaN(Number(mins)) || Number(mins) < 1)) {
      return res.status(400).json({ success: false, error: 'mins must be a number >= 1' });
    }
    const entry = await Entry.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      req.body,
      { new: true, runValidators: true }
    );
    if (!entry) return res.status(404).json({ success: false, error: 'Entry not found' });
    res.json({ success: true, data: entry });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/entries/:id — delete an entry (only owner can delete)
app.delete('/api/entries/:id', requireAuth, async (req, res, next) => {
  try {
    const entry = await Entry.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    if (!entry) return res.status(404).json({ success: false, error: 'Entry not found' });
    res.json({ success: true, data: { deleted: true } });
  } catch (err) {
    next(err);
  }
});

// ── Error Handling Middleware ──────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err);
  if (err.name === 'ValidationError') {
    return res.status(400).json({ success: false, error: err.message });
  }
  if (err.name === 'CastError') {
    return res.status(400).json({ success: false, error: 'Invalid ID format' });
  }
  res.status(500).json({ success: false, error: 'Internal server error' });
});

// Listen only in local dev — Vercel manages the HTTP server in production
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}

module.exports = app;
