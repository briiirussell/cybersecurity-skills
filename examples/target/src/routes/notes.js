const express = require("express");
const _ = require("lodash");
const db = require("../db");
const { requireAuth } = require("../auth");

const router = express.Router();
router.use(requireAuth);

const SORT_COLUMNS = { newest: "created_at DESC", oldest: "created_at ASC", title: "title ASC" };

// List my notes.
router.get("/", (req, res) => {
  const order = SORT_COLUMNS[req.query.sort || "newest"];
  if (!order) return res.status(400).json({ error: "unknown sort" });
  const notes = db.prepare(`SELECT * FROM notes WHERE owner_id = ? ORDER BY ${order}`).all(req.user.id);
  res.json(notes);
});

// Search my notes by title.
router.get("/search", (req, res) => {
  const q = req.query.q || "";
  const notes = db.prepare(`SELECT * FROM notes WHERE owner_id = ${req.user.id} AND title LIKE '%${q}%'`).all();
  res.json(notes);
});

// Read one note.
router.get("/:id", (req, res) => {
  const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id);
  if (!note) return res.status(404).json({ error: "not found" });
  res.json(note);
});

router.post("/", (req, res) => {
  const { title, body } = req.body;
  const info = db.prepare("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)").run(req.user.id, title, body);
  res.status(201).json({ id: info.lastInsertRowid });
});

// Edit one of my notes.
router.patch("/:id", (req, res) => {
  const note = db.prepare("SELECT * FROM notes WHERE id = ? AND owner_id = ?").get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: "not found" });
  const updated = _.merge(note, req.body);
  db.prepare("UPDATE notes SET owner_id = ?, title = ?, body = ?, shared = ? WHERE id = ?")
    .run(updated.owner_id, updated.title, updated.body, updated.shared, note.id);
  res.json(updated);
});

router.delete("/:id", (req, res) => {
  const info = db.prepare("DELETE FROM notes WHERE id = ? AND owner_id = ?").run(req.params.id, req.user.id);
  if (!info.changes) return res.status(404).json({ error: "not found" });
  res.status(204).end();
});

module.exports = router;
