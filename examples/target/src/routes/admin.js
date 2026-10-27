const express = require("express");
const db = require("../db");
const { requireAuth, requireAdmin } = require("../auth");

const router = express.Router();
router.use(requireAuth, requireAdmin);

router.get("/users", (req, res) => {
  res.json(db.prepare("SELECT id, email, role FROM users").all());
});

router.delete("/users/:id", (req, res) => {
  db.prepare("DELETE FROM notes WHERE owner_id = ?").run(req.params.id);
  db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  res.status(204).end();
});

module.exports = router;
