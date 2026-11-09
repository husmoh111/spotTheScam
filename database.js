const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');
const dbPath = process.env.SCAM_DB_PATH || path.join(__dirname, 'spotthescam.sqlite');
const legacyPath = process.env.SCAM_LEGACY_PATH || path.join(__dirname, 'data.json');
const db = new DatabaseSync(dbPath);
db.exec(`PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scores (id INTEGER PRIMARY KEY, user_id TEXT REFERENCES users(id), name TEXT NOT NULL, score INTEGER NOT NULL, correct INTEGER NOT NULL, time INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS scores_ranking ON scores(score DESC, correct DESC, time ASC);
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
// Import only once, atomically. Keep the original file as a backup.
if (!db.prepare("SELECT 1 FROM metadata WHERE key = 'legacy_imported'").get()) {
  db.exec('BEGIN IMMEDIATE');
  try {
    if (fs.existsSync(legacyPath)) {
      const legacy = JSON.parse(fs.readFileSync(legacyPath, 'utf8'));
      if (!Array.isArray(legacy.users) || !Array.isArray(legacy.scores)) throw new Error('Invalid legacy data.json');
      const insertUser = db.prepare('INSERT INTO users (id,name,name_key,salt,hash) VALUES (?,?,?,?,?)');
      const insertScore = db.prepare('INSERT INTO scores (user_id,name,score,correct,time) VALUES (?,?,?,?,?)');
      const ids = new Map();
      for (const u of legacy.users) { insertUser.run(u.id,u.name,u.name.toLowerCase(),u.salt,u.hash); ids.set(u.name.toLowerCase(),u.id); }
      for (const s of legacy.scores) insertScore.run(ids.get(s.name.toLowerCase()) || null,s.name,s.score,s.correct,s.time);
    }
    db.prepare("INSERT INTO metadata (key,value) VALUES ('legacy_imported','1')").run();
    db.exec('COMMIT');
  } catch (error) { db.exec('ROLLBACK'); db.close(); throw new Error(`Could not import existing data: ${error.message}`); }
}
module.exports = db;
