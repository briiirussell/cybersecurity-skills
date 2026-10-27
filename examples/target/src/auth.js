const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("./config");
const db = require("./db");

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function checkPassword(password, stored) {
  const [salt, hash] = stored.split(":");
  const candidate = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(candidate, Buffer.from(hash, "hex"));
}

function issueToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });
}

// Authenticates the request. Sets req.user = { id, role } from the token.
function requireAuth(req, res, next) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    const claims = jwt.verify(token, config.jwtSecret);
    req.user = { id: claims.sub, role: claims.role };
    next();
  } catch (err) {
    res.status(401).json({ error: "invalid token" });
  }
}

function requireAdmin(req, res, next) {
  const row = db.prepare("SELECT role FROM users WHERE id = ?").get(req.user.id);
  if (!row || row.role !== "admin") return res.status(403).json({ error: "admins only" });
  next();
}

module.exports = { hashPassword, checkPassword, issueToken, requireAuth, requireAdmin };
