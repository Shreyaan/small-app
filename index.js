import { serve } from "bun";
import { Database } from "bun:sqlite";

import homepage from "./index.html";

const db = new Database("app.db");

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  PRAGMA cache_size = 1000;
  PRAGMA temp_store = memory;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    pass_salt TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    done INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
try { db.exec(`ALTER TABLE todos ADD COLUMN user_id INTEGER NOT NULL DEFAULT 0`); } catch {}
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_todos_user ON todos(user_id, id DESC);
`);

// Prepared statements for better performance
const queries = {
  getUserSession: db.query(`SELECT u.id, u.email, s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?`),
  deleteSession: db.query(`DELETE FROM sessions WHERE id=?`),
  insertUser: db.query(`INSERT INTO users(email, pass_salt, pass_hash) VALUES(?,?,?)`),
  getUserByEmail: db.query(`SELECT id, email, pass_salt, pass_hash FROM users WHERE email=?`),
  insertSession: db.query(`INSERT INTO sessions(id, user_id, expires_at) VALUES(?,?,?)`),
  getTodos: db.query(`SELECT id, title, done, created_at FROM todos WHERE user_id = ? ORDER BY id DESC`),
  insertTodo: db.query(`INSERT INTO todos (title, done, user_id) VALUES (?,?,?)`),
  getLastTodo: db.query(`SELECT id, title, done, created_at FROM todos WHERE id = last_insert_rowid()`),
  getTodo: db.query(`SELECT id, title, done, created_at FROM todos WHERE id = ? AND user_id = ?`),
  updateTodo: db.query(`UPDATE todos SET title = ?, done = ? WHERE id = ? AND user_id = ?`),
  updateTodoTitle: db.query(`UPDATE todos SET title = ? WHERE id = ? AND user_id = ?`),
  updateTodoDone: db.query(`UPDATE todos SET done = ? WHERE id = ? AND user_id = ?`),
  deleteTodo: db.query(`DELETE FROM todos WHERE id = ? AND user_id = ?`),
};

function rowToTodo(row) {
  return {
    id: row.id,
    title: row.title,
    done: Boolean(row.done),
    created_at: row.created_at,
  };
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) {
      out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
    }
  });
  return out;
}
function isoPlusDays(days) {
  return new Date(Date.now() + days * 864e5).toISOString();
}
function setCookie(name, val, days) {
  const parts = [
    `${name}=${encodeURIComponent(val)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (days) parts.push(`Max-Age=${Math.floor(days * 86400)}`);
  return parts.join("; ");
}
async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
async function hashPassword(password, salt) {
  return sha256Hex(password + ":" + salt);
}
function newSalt() {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 16);
}

async function getUser(req) {
  const sid = parseCookies(req.headers.get("cookie") || "").sid;
  if (!sid) return null;
  const row = queries.getUserSession.get(sid);
  if (!row) return null;
  if (new Date(row.expires_at) < new Date()) {
    queries.deleteSession.run(sid);
    return null;
  }
  return { id: row.id, email: row.email };
}

const json = (data, init = {}) =>
  new Response(JSON.stringify(data), {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers || {}) },
  });

const server = serve({
  port: 3000,
  routes: {
    "/": homepage,
    "/manifest.json": () => json({
      name: "Todos App",
      short_name: "Todos",
      description: "A beautiful, fast todo app",
      start_url: "/",
      display: "standalone",
      background_color: "#0f0f14",
      theme_color: "#6366f1",
      icons: [
        { src: "data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3e%3ccircle cx='50' cy='50' r='45' fill='%236366f1'/%3e%3cpath d='M25 50l15 15 30-30' stroke='white' stroke-width='8' fill='none' stroke-linecap='round' stroke-linejoin='round'/%3e%3c/svg%3e", sizes: "any", type: "image/svg+xml" }
      ]
    }),

    // auth
    "/api/auth/register": {
      async POST(req) {
        try {
          const { email, password } = await req.json();
          if (
            !email ||
            !password ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            password.length < 6 ||
            !email.includes("@")
          )
            return json({ error: "Invalid credentials" }, { status: 400 });
                     const salt = newSalt();
           const pass_hash = await hashPassword(password, salt);
           queries.insertUser.run(email.trim().toLowerCase(), salt, pass_hash);
           const user = queries.getUserByEmail.get(email.trim().toLowerCase());
           const sid = crypto.randomUUID().replace(/-/g, "");
           queries.insertSession.run(sid, user.id, isoPlusDays(7));
          return json(
            { id: user.id, email: user.email },
            { headers: { "set-cookie": setCookie("sid", sid, 7) } }
          );
        } catch (err) {
          if (String(err).includes("UNIQUE"))
            return json({ error: "Email in use" }, { status: 409 });
          console.error("[ERROR] register", err);
          return json({ error: "Bad Request" }, { status: 400 });
        }
      },
    },
    "/api/auth/login": {
      async POST(req) {
        try {
                     const { email, password } = await req.json();
           if (!email || !password)
             return json({ error: "Invalid credentials" }, { status: 400 });
           const u = queries.getUserByEmail.get(email.trim().toLowerCase());
           if (!u) return json({ error: "Invalid login" }, { status: 401 });
           const h = await hashPassword(password, u.pass_salt);
           if (h !== u.pass_hash)
             return json({ error: "Invalid login" }, { status: 401 });
           const sid = crypto.randomUUID().replace(/-/g, "");
           queries.insertSession.run(sid, u.id, isoPlusDays(7));
          return json(
            { id: u.id, email: u.email },
            { headers: { "set-cookie": setCookie("sid", sid, 7) } }
          );
        } catch (err) {
          console.error("[ERROR] login", err);
          return json({ error: "Bad Request" }, { status: 400 });
        }
      },
    },
    "/api/auth/logout": {
             async POST(req) {
         const sid = parseCookies(req.headers.get("cookie") || "").sid;
         if (sid) queries.deleteSession.run(sid);
        return new Response(null, {
          status: 204,
          headers: { "set-cookie": setCookie("sid", "", -1) },
        });
      },
    },
    "/api/me": async (req) => {
      const user = await getUser(req);
      if (!user) return json({ error: "Unauthorized" }, { status: 401 });
      return json(user);
    },

    // todos
    "/api/todos": {
      async GET(req) {
        const user = await getUser(req);
        if (!user) return json({ error: "Unauthorized" }, { status: 401 });
        const rows = queries.getTodos.all(user.id);
        return json(rows.map(rowToTodo));
      },
      async POST(req) {
        try {
          const user = await getUser(req);
          if (!user) return json({ error: "Unauthorized" }, { status: 401 });
          const { title } = await req.json();
          if (!title || typeof title !== "string") {
            return json({ error: "Invalid title" }, { status: 400 });
          }
          queries.insertTodo.run(title.trim(), 0, user.id);
          const created = queries.getLastTodo.get();
          console.log("[INFO] Created todo", {
            id: created.id,
            title: created.title,
            user: user.id,
          });
          return json(rowToTodo(created));
        } catch (err) {
          console.error("[ERROR] POST /api/todos", err);
          return json({ error: "Bad Request" }, { status: 400 });
        }
      },
    },
    "/api/todos/:id": async (req) => {
      const user = await getUser(req);
      if (!user) return json({ error: "Unauthorized" }, { status: 401 });
      const { id } = req.params;
      const numericId = Number(id);
      if (!Number.isInteger(numericId) || numericId <= 0) {
        return json({ error: "Invalid id" }, { status: 400 });
      }

      if (req.method === "GET") {
        const row = queries.getTodo.get(numericId, user.id);
        if (!row) {
          return json({ error: "Not found" }, { status: 404 });
        }
        return json(rowToTodo(row));
      }

      if (req.method === "PATCH" || req.method === "PUT") {
        try {
          const body = await req.json();
          const nextTitle =
            typeof body.title === "string" ? body.title.trim() : undefined;
          const nextDone =
            typeof body.done === "boolean" ? (body.done ? 1 : 0) : undefined;

          if (nextTitle === undefined && nextDone === undefined) {
            return json({ error: "Nothing to update" }, { status: 400 });
          }
          if (nextTitle !== undefined && nextTitle.length === 0) {
            return json({ error: "Title cannot be empty" }, { status: 400 });
          }

          if (nextTitle !== undefined && nextDone !== undefined) {
            queries.updateTodo.run(nextTitle, nextDone, numericId, user.id);
          } else if (nextTitle !== undefined) {
            queries.updateTodoTitle.run(nextTitle, numericId, user.id);
          } else if (nextDone !== undefined) {
            queries.updateTodoDone.run(nextDone, numericId, user.id);
          }

          const updated = queries.getTodo.get(numericId, user.id);
          if (!updated) {
            return json({ error: "Not found" }, { status: 404 });
          }
          console.log("[INFO] Updated todo", { id: updated.id, user: user.id });
          return json(rowToTodo(updated));
        } catch (err) {
          console.error("[ERROR] PATCH/PUT /api/todos/:id", err);
          return json({ error: "Bad Request" }, { status: 400 });
        }
      }

      if (req.method === "DELETE") {
        const info = queries.deleteTodo.run(numericId, user.id);
        if (info.changes === 0) {
          return json({ error: "Not found" }, { status: 404 });
        }
        console.log("[INFO] Deleted todo", { id: numericId, user: user.id });
        return new Response(null, { status: 204 });
      }

      return json({ error: "Method Not Allowed" }, { status: 405 });
    },
  },

  development: true,
});

console.log(`Listening on ${server.url}`);
