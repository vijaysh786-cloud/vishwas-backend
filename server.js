require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

/* ================= CORS (FINAL CORRECT WAY) ================= */
app.use(cors({
  origin: 'https://vishwasfin.netlify.app', // 🔥 your frontend
  methods: ['GET','POST','PUT','DELETE'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(express.json());

/* ================= ENV ================= */
const ADMIN_USER = process.env.ADMIN_USER;
const HASHED_PASS = process.env.ADMIN_PASS;
const SECRET = process.env.JWT_SECRET;

/* ================= HEALTH ================= */
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
    console.error(err);
    res.status(500).json({ success: false });
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

  } catch {
    res.status(401).json({ success: false });
  }
});

/* ================= START ================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});