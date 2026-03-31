require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

/* ================= FORCE CORS (FINAL FIX) ================= */
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://vishwasfin.netlify.app");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

app.use(express.json());

/* ================= ENV ================= */
const ADMIN_USER = process.env.ADMIN_USER;
const HASHED_PASS = process.env.ADMIN_PASS;
const SECRET = process.env.JWT_SECRET;

/* ================= TEST ================= */
app.get('/', (req, res) => {
  res.send("API Running ✅");
});

/* ================= LOGIN ================= */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (username !== ADMIN_USER) {
    return res.status(401).json({ success: false });
  }

  const match = await bcrypt.compare(password, HASHED_PASS);

  if (!match) {
    return res.status(401).json({ success: false });
  }

  const token = jwt.sign({ user: username }, SECRET, { expiresIn: '2h' });

  res.json({ success: true, token });
});

/* ================= VERIFY ================= */
app.get('/verify', (req, res) => {
  const token = req.headers.authorization;

  if (!token) return res.status(403).json({ success: false });

  try {
    const decoded = jwt.verify(token, SECRET);
    res.json({ success: true, user: decoded.user });
  } catch {
    res.status(401).json({ success: false });
  }
});

/* ================= START ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port " + PORT));