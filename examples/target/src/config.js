// Runtime configuration, read from the environment.
module.exports = {
  port: Number(process.env.PORT) || 3000,
  databasePath: process.env.DATABASE_PATH || "./notes.db",
  jwtSecret: process.env.JWT_SECRET || "changeme",
  jwtExpiresIn: "7d",
  backupBucket: process.env.BACKUP_BUCKET,
};
