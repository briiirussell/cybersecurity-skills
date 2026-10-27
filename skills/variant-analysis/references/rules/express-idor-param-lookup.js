// Test cases for express-idor-param-lookup. Run: semgrep --test .semgrep/variants/
const express = require("express");
const router = express.Router();

// The original finding, reduced to its shape.
router.get("/:id", (req, res) => {
  // ruleid: express-idor-param-lookup
  const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id);
  res.json(note);
});

// Variant: classic function handler, different table and param name.
router.get("/attachments/:attachmentId", function (req, res) {
  // ruleid: express-idor-param-lookup
  const row = db.prepare("SELECT path FROM attachments WHERE id = ?").get(req.params.attachmentId);
  res.sendFile(row.path);
});

// Variant: node-postgres query with a parameter array, async handler.
router.delete("/comments/:id", requireAuth, async (req, res) => {
  // ruleid: express-idor-param-lookup
  await pool.query("DELETE FROM comments WHERE id = $1", [req.params.id]);
  res.status(204).end();
});

// Variant: Prisma lookup keyed only by the param.
router.get("/invoices/:id", async (req, res) => {
  // ruleid: express-idor-param-lookup
  const invoice = await prisma.invoice.findUnique({ where: { id: Number(req.params.id) } });
  res.json(invoice);
});

// Fixed shape: owner predicate in the SQL.
router.patch("/:id", (req, res) => {
  // ok: express-idor-param-lookup
  const note = db.prepare("SELECT * FROM notes WHERE id = ? AND owner_id = ?").get(req.params.id, req.user.id);
  res.json(note);
});

// Fixed shape: tenant predicate in node-postgres.
router.get("/projects/:id", async (req, res) => {
  // ok: express-idor-param-lookup
  const { rows } = await pool.query("SELECT * FROM projects WHERE id = $1 AND org_id = $2", [req.params.id, req.user.orgId]);
  res.json(rows[0]);
});

// Fixed shape: Prisma where object also scoped to the caller.
router.get("/orders/:id", async (req, res) => {
  // ok: express-idor-param-lookup
  const order = await prisma.order.findFirst({ where: { id: req.params.id, userId: req.user.id } });
  res.json(order);
});

// Known gap: the guard checks that owner_id is named, not that it is bound to the caller.
router.delete("/users/:id/notes", (req, res) => {
  // todoruleid: express-idor-param-lookup
  db.prepare("DELETE FROM notes WHERE owner_id = ?").run(req.params.id);
  res.status(204).end();
});

// Not a param lookup: the id comes from the session.
router.get("/me", (req, res) => {
  // ok: express-idor-param-lookup
  const me = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
  res.json(me);
});

// Not in a route handler: a helper the rule can't judge on its own.
function loadNote(id) {
  // ok: express-idor-param-lookup
  return db.prepare("SELECT * FROM notes WHERE id = ?").get(id);
}
