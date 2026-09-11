require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET in .env to a random secret of at least 32 characters.");
  process.exit(1);
}

const db = new Database(path.join(__dirname, "mh_services.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id TEXT UNIQUE,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  country TEXT NOT NULL DEFAULT 'Nigeria',
  balance_kobo INTEGER NOT NULL DEFAULT 0,
  total_earned_kobo INTEGER NOT NULL DEFAULT 0,
  total_withdrawn_kobo INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  amount_kobo INTEGER NOT NULL,
  status TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

function makeMemberId(id) {
  return `MH-${new Date().getFullYear()}-${String(id).padStart(6, "0")}`;
}

function signToken(user) {
  return jwt.sign({ userId: user.id, memberId: user.member_id }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const token = req.cookies.mh_token;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie("mh_token");
    return res.status(401).json({ error: "Session expired. Please log in again." });
  }
}

app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/register", async (req, res) => {
  try {
    const firstName = String(req.body.firstName || "").trim();
    const lastName = String(req.body.lastName || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const country = String(req.body.country || "Nigeria").trim();

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: "All required fields must be completed." });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Enter a valid email address." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    }

    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) return res.status(409).json({ error: "An account with this email already exists." });

    const passwordHash = await bcrypt.hash(password, 12);

    const insert = db.prepare(`
      INSERT INTO users (first_name,last_name,email,password_hash,country)
      VALUES (?,?,?,?,?)
    `);
    const result = insert.run(firstName, lastName, email, passwordHash);
    const memberId = makeMemberId(result.lastInsertRowid);

    db.prepare("UPDATE users SET member_id=? WHERE id=?").run(memberId, result.lastInsertRowid);

    const user = db.prepare(`
      SELECT id,member_id,first_name,last_name,email,country,balance_kobo,total_earned_kobo,total_withdrawn_kobo,created_at
      FROM users WHERE id=?
    `).get(result.lastInsertRowid);

    res.cookie("mh_token", signToken(user), {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(201).json({ user: publicUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    res.cookie("mh_token", signToken(user), {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({ user: publicUser(user) });
  } catch {
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("mh_token");
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  const user = db.prepare(`
    SELECT id,member_id,first_name,last_name,email,country,balance_kobo,total_earned_kobo,total_withdrawn_kobo,created_at
    FROM users WHERE id=?
  `).get(req.auth.userId);

  if (!user) return res.status(404).json({ error: "User not found." });
  res.json({ user: publicUser(user) });
});

app.get("/api/transactions", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT id,type,amount_kobo,status,description,created_at
    FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 50
  `).all(req.auth.userId);
  res.json({ transactions: rows.map(publicTransaction) });
});

function publicUser(u) {
  return {
    memberId: u.member_id,
    firstName: u.first_name,
    lastName: u.last_name,
    email: u.email,
    country: u.country,
    balanceNGN: u.balance_kobo / 100,
    totalEarnedNGN: u.total_earned_kobo / 100,
    totalWithdrawnNGN: u.total_withdrawn_kobo / 100,
    createdAt: u.created_at
  };
}
function publicTransaction(t) {
  return {
    id: t.id,
    type: t.type,
    amountNGN: t.amount_kobo / 100,
    status: t.status,
    description: t.description,
    createdAt: t.created_at
  };
}

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`MH Services running at http://localhost:${PORT}`));
