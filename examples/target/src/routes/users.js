const express = require("express");
const db = require("../db");
const { hashPassword, checkPassword, issueToken } = require("../auth");

const router = express.Router();

router.post("/signup", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8) return res.status(400).json({ error: "email and 8+ char password required" });
  const info = db.prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)").run(email, hashPassword(password));
  const user = db.prepare("SELECT id, role FROM users WHERE id = ?").get(info.lastInsertRowid);
  res.status(201).json({ token: issueToken(user) });
});

router.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT id, role, password_hash FROM users WHERE email = ?").get(email);
  if (!user || !checkPassword(password, user.password_hash)) return res.status(401).json({ error: "bad credentials" });
  res.json({ token: issueToken(user) });
});

module.exports = router;
