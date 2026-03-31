require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

app.use(cors({
  origin: '*'
}));

const ADMIN_USER = process.env.ADMIN_USER;
const HASHED_PASS = process.env.ADMIN_PASS;
const SECRET = process.env.JWT_SECRET;

// LOGIN
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

// VERIFY
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

app.listen(3000, () => console.log("Server running on port 3000"));