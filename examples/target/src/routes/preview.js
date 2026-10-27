const express = require("express");
const axios = require("axios");
const { requireAuth } = require("../auth");

const router = express.Router();

// Fetch a page and return its <title> for link previews in notes.
router.post("/", requireAuth, async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!/^https?:\/\//.test(url || "")) return res.status(400).json({ error: "http(s) url required" });
    const page = await axios.get(url, { timeout: 5000, maxContentLength: 1_000_000 });
    const match = /<title>([^<]*)<\/title>/i.exec(page.data);
    res.json({ url, title: match ? match[1] : null });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
