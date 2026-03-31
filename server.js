require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

/* ================= CORS FIX (BULLETPROOF) ================= */
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, PUT, DELETE, OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }

  next();
});

app.use(cors());
app.use(express.json());

/* ================= ENV VARIABLES ================= */
const ADMIN_USER = process.env.ADMIN_USER;
const HASHED_PASS = process.env.ADMIN_PASS;
const SECRET = process.env.JWT_SECRET;

/* ================= HEALTH CHECK ================= */
app.get('/', (req, res) => {
  res.send("API Running ✅");
});

/* ================= LOGIN ================= */
app.post('/login', async (req, res) => {
  try {
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

  } catch (err) {
    res.status(500).json({ success: false, error: "Server error" });
  }
});

/* ================= VERIFY ================= */
app.get('/verify', (req, res) => {
  try {
    const token = req.headers.authorization;

    if (!token) {
      return res.status(403).json({ success: false });
    }

    const decoded = jwt.verify(token, SECRET);

    res.json({ success: true, user: decoded.user });

  } catch (err) {
    res.status(401).json({ success: false });
  }
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});