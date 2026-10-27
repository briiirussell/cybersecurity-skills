const express = require("express");
const config = require("./config");

const app = express();
app.use(express.json({ limit: "100kb" }));

app.use("/api/users", require("./routes/users"));
app.use("/api/notes", require("./routes/notes"));
app.use("/api/preview", require("./routes/preview"));
app.use("/api/admin", require("./routes/admin"));

app.get("/healthz", (req, res) => res.send("ok"));

// Errors go back to the client so the frontend can show them.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(config.port, () => console.log(`notes-api on :${config.port}`));
