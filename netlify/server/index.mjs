import { Hono } from "hono";
import { drizzle } from "drizzle-orm/netlify-db";
import { eq, and, or, desc, sql, count } from "drizzle-orm";
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import * as schema from "../../db/schema.ts";

const db = drizzle({ schema });
const { users, zones, events, passes, scans, sessions, settings } = schema;

const app = new Hono();

/* ---------- helpers ---------- */

function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(":");
    const test = scryptSync(password, salt, 64);
    const orig = Buffer.from(hash, "hex");
    return orig.length === test.length && timingSafeEqual(orig, test);
  } catch {
    return false;
  }
}

const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  username: u.username,
  role: u.role,
  phone: u.phone,
  zone_id: u.zoneId,
  status: u.status,
});

async function auth(c, required) {
  const header = c.req.header("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return null;
  const rows = await db
    .select()
    .from(sessions)
    .where(eq(sessions.token, token))
    .limit(1);
  const s = rows[0];
  if (!s || new Date(s.expiresAt) < new Date()) return null;
  const urows = await db.select().from(users).where(eq(users.id, s.userId)).limit(1);
  const u = urows[0];
  if (!u || u.status !== "active") return null;
  if (required && !required.includes(u.role)) return null;
  return u;
}

const bad = (c, msg, code = 400) => c.json({ error: msg }, code);

/* ---------- auth routes ---------- */

app.get("/api/bootstrap-check", async (c) => {
  try {
    const rows = await db.select({ id: users.id }).from(users).limit(1);
    return c.json({ needs_setup: rows.length === 0 });
  } catch {
    return c.json({ needs_setup: true });
  }
});

app.post("/api/bootstrap", async (c) => {
  const rows = await db.select({ id: users.id }).from(users).limit(1);
  if (rows.length) return bad(c, "Setup already done — use the normal login form", 403);
  const body = await c.req.json().catch(() => ({}));
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  const name = String(body.name || "").trim();
  if (!username || !password || !name) return bad(c, "name, username, password required");
  if (password.length < 6) return bad(c, "Password must be at least 6 characters");
  const rows2 = await db
    .insert(users)
    .values({
      role: "master",
      name,
      username,
      passwordHash: hashPassword(password),
      status: "active",
    })
    .returning();
  const token = randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  await db.insert(sessions).values({ token, userId: rows2[0].id, expiresAt: expires });
  return c.json({ token, user: publicUser(rows2[0]) });
});

app.post("/api/login", async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!username || !password) return bad(c, "Username and password required");
  const rows = await db.select().from(users).where(eq(users.username, username)).limit(1);
  const u = rows[0];
  if (!u || !verifyPassword(password, u.passwordHash))
    return bad(c, "Invalid username or password", 401);
  if (u.status !== "active") return bad(c, "Account is disabled", 403);
  const token = randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  await db.insert(sessions).values({ token, userId: u.id, expiresAt: expires });
  return c.json({ token, user: publicUser(u) });
});

app.post("/api/logout", async (c) => {
  const u = await auth(c);
  const header = c.req.header("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (token) await db.delete(sessions).where(eq(sessions.token, token));
  return c.json({ ok: true });
});

app.get("/api/me", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  let zone = null;
  if (u.zoneId) {
    const zrows = await db.select().from(zones).where(eq(zones.id, u.zoneId)).limit(1);
    zone = zrows[0] || null;
  }
  return c.json({ user: publicUser(u), zone });
});

/* ---------- zones (master only) ---------- */

app.get("/api/zones", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  if (u.role === "sub_admin") {
    const zrows = await db.select().from(zones).where(eq(zones.id, u.zoneId)).limit(1);
    return c.json({ zones: zrows });
  }
  const rows = await db.select().from(zones).orderBy(zones.id);
  return c.json({ zones: rows });
});

app.post("/api/zones", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const name = String(body.name || "").trim();
  if (!name) return bad(c, "Zone name required");
  const rows = await db
    .insert(zones)
    .values({ name, description: String(body.description || "") })
    .returning();
  return c.json({ zone: rows[0] });
});

app.put("/api/zones/:id", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const patch = {};
  if (body.name !== undefined) patch.name = String(body.name).trim();
  if (body.description !== undefined) patch.description = String(body.description);
  const rows = await db
    .update(zones)
    .set(patch)
    .where(eq(zones.id, Number(c.req.param("id"))))
    .returning();
  if (!rows[0]) return bad(c, "Zone not found", 404);
  return c.json({ zone: rows[0] });
});

app.delete("/api/zones/:id", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const id = Number(c.req.param("id"));
  const used = await db.select({ id: users.id }).from(users).where(eq(users.zoneId, id)).limit(1);
  if (used[0]) return bad(c, "This zone has users assigned — reassign them first");
  await db.delete(zones).where(eq(zones.id, id));
  return c.json({ ok: true });
});

/* ---------- users (master manages all; sub_admin limited) ---------- */

app.get("/api/users", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  const role = c.req.query("role");
  const rows = await db.select().from(users).orderBy(users.id);
  let list = rows.map(publicUser);
  if (u.role === "sub_admin") {
    list = list.filter((r) => r.zone_id === u.zoneId && r.role !== "master");
  }
  if (role) list = list.filter((r) => r.role === role);
  return c.json({ users: list });
});

app.post("/api/users", async (c) => {
  const u = await auth(c, ["master", "sub_admin"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const role = body.role === "sub_admin" ? "sub_admin" : body.role === "master" ? "master" : "guard";
  if (u.role === "sub_admin" && role !== "guard") return bad(c, "Sub admins can only create guards", 403);
  let zoneId = body.zone_id ? Number(body.zone_id) : null;
  if (u.role === "sub_admin") zoneId = u.zoneId;
  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!username || !body.name || !password) return bad(c, "name, username, password required");
  const exists = await db.select({ id: users.id }).from(users).where(eq(users.username, username)).limit(1);
  if (exists[0]) return bad(c, "This username already exists", 409);
  const rows = await db
    .insert(users)
    .values({
      role,
      name: String(body.name).trim(),
      phone: String(body.phone || ""),
      username,
      passwordHash: hashPassword(password),
      zoneId,
      status: "active",
      createdBy: u.id,
    })
    .returning();
  return c.json({ user: publicUser(rows[0]) });
});

app.put("/api/users/:id", async (c) => {
  const u = await auth(c, ["master", "sub_admin"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const id = Number(c.req.param("id"));
  const rows0 = await db.select().from(users).where(eq(users.id, id)).limit(1);
  const target = rows0[0];
  if (!target) return bad(c, "User not found", 404);
  if (u.role === "sub_admin" && (target.zoneId !== u.zoneId || target.role !== "guard"))
    return bad(c, "Not allowed", 403);
  const body = await c.req.json().catch(() => ({}));
  const patch = {};
  if (body.name !== undefined) patch.name = String(body.name).trim();
  if (body.phone !== undefined) patch.phone = String(body.phone);
  if (body.status !== undefined) patch.status = body.status === "disabled" ? "disabled" : "active";
  if (body.zone_id !== undefined) {
    if (u.role === "sub_admin") return bad(c, "Not allowed", 403);
    patch.zoneId = body.zone_id === null ? null : Number(body.zone_id);
  }
  if (body.password) patch.passwordHash = hashPassword(String(body.password));
  patch.updatedAt = new Date();
  const rows = await db.update(users).set(patch).where(eq(users.id, id)).returning();
  return c.json({ user: publicUser(rows[0]) });
});

app.delete("/api/users/:id", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const id = Number(c.req.param("id"));
  if (id === u.id) return bad(c, "You cannot delete yourself");
  await db.delete(sessions).where(eq(sessions.userId, id));
  await db.delete(users).where(eq(users.id, id));
  return c.json({ ok: true });
});

/* ---------- events (master only) ---------- */

app.get("/api/events", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  const rows = await db.select().from(events).orderBy(desc(events.id));
  return c.json({ events: rows });
});

app.post("/api/events", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const name = String(body.name || "").trim();
  if (!name) return bad(c, "Event name required");
  const rows = await db
    .insert(events)
    .values({
      name,
      venue: String(body.venue || ""),
      eventDate: String(body.event_date || ""),
      status: "active",
    })
    .returning();
  return c.json({ event: rows[0] });
});

app.put("/api/events/:id", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const patch = {};
  if (body.name !== undefined) patch.name = String(body.name).trim();
  if (body.venue !== undefined) patch.venue = String(body.venue);
  if (body.event_date !== undefined) patch.eventDate = String(body.event_date);
  if (body.status !== undefined) patch.status = body.status === "closed" ? "closed" : "active";
  const rows = await db
    .update(events)
    .set(patch)
    .where(eq(events.id, Number(c.req.param("id"))))
    .returning();
  if (!rows[0]) return bad(c, "Event not found", 404);
  return c.json({ event: rows[0] });
});

app.delete("/api/events/:id", async (c) => {
  const u = await auth(c, ["master"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const id = Number(c.req.param("id"));
  const used = await db.select({ id: passes.id }).from(passes).where(eq(passes.eventId, id)).limit(1);
  if (used[0]) return bad(c, "This event has passes — delete the passes first");
  await db.delete(events).where(eq(events.id, id));
  return c.json({ ok: true });
});

/* ---------- passes ---------- */

app.get("/api/passes", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  const eventId = c.req.query("event_id");
  const q = c.req.query("q");
  const zone = c.req.query("zone");
  const conds = [];
  if (eventId) conds.push(eq(passes.eventId, Number(eventId)));
  if (zone) conds.push(eq(passes.zoneId, Number(zone)));
  if (q) {
    const like = `%${q.toLowerCase()}%`;
    conds.push(
      or(
        sql`lower(${passes.passNo}) like ${like}`,
        sql`lower(${passes.name}) like ${like}`,
        sql`lower(${passes.phone}) like ${like}`,
        sql`lower(${passes.group}) like ${like}`
      )
    );
  }
  let rows = await db
    .select()
    .from(passes)
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(passes.id))
    .limit(1000);
  const zoneRows = await db.select().from(zones);
  const zmap = Object.fromEntries(zoneRows.map((z) => [z.id, z.name]));
  const evRows = await db.select().from(events);
  const emap = Object.fromEntries(evRows.map((e) => [e.id, e.name]));
  rows = rows.map((r) => ({
    ...r,
    zone_name: r.zoneId ? zmap[r.zoneId] || "" : "",
    event_name: emap[r.eventId] || "",
  }));
  return c.json({ passes: rows });
});

app.post("/api/passes", async (c) => {
  const u = await auth(c, ["master", "sub_admin"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  let eventId = Number(body.event_id || 0);
  if (!eventId) {
    const active = await db.select().from(events).where(eq(events.status, "active")).orderBy(desc(events.id)).limit(1);
    if (!active[0]) return bad(c, "Create an event first");
    eventId = active[0].id;
  }
  let zoneId = body.zone_id ? Number(body.zone_id) : null;
  if (u.role === "sub_admin") zoneId = u.zoneId;
  const rows = await db
    .insert(passes)
    .values({
      passNo: String(body.pass_no || "").trim() || `P${Date.now().toString(36).toUpperCase()}`,
      name: String(body.name || "").trim(),
      phone: String(body.phone || ""),
      group: String(body.group || ""),
      eventId,
      zoneId,
      status: "active",
      issuedBy: u.id,
      note: String(body.note || ""),
    })
    .returning();
  return c.json({ pass: rows[0] });
});

app.post("/api/passes/bulk", async (c) => {
  const u = await auth(c, ["master", "sub_admin"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const lines = String(body.text || "").split("\n").map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return bad(c, "No data found");
  const eventId = Number(body.event_id || 0);
  if (!eventId) return bad(c, "event_id required");
  let zoneId = body.zone_id ? Number(body.zone_id) : null;
  if (u.role === "sub_admin") zoneId = u.zoneId;
  const values = [];
  for (const line of lines) {
    const parts = line.split(",").map((p) => p.trim());
    const [name, phone, group, note] = parts;
    if (!name) continue;
    values.push({
      passNo: `P${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
      name,
      phone: phone || "",
      group: group || "",
      eventId,
      zoneId,
      status: "active",
      issuedBy: u.id,
      note: note || "",
    });
  }
  if (!values.length) return bad(c, "Format: name, phone, group, note");
  const rows = await db.insert(passes).values(values).returning();
  return c.json({ created: rows.length, passes: rows });
});

app.put("/api/passes/:id", async (c) => {
  const u = await auth(c, ["master", "sub_admin"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const id = Number(c.req.param("id"));
  const rows0 = await db.select().from(passes).where(eq(passes.id, id)).limit(1);
  const p = rows0[0];
  if (!p) return bad(c, "Pass not found", 404);
  if (u.role === "sub_admin" && p.zoneId !== u.zoneId) return bad(c, "Not allowed", 403);
  const body = await c.req.json().catch(() => ({}));
  const patch = {};
  if (body.name !== undefined) patch.name = String(body.name).trim();
  if (body.phone !== undefined) patch.phone = String(body.phone);
  if (body.group !== undefined) patch.group = String(body.group);
  if (body.status !== undefined)
    patch.status = ["active", "blocked", "checked_in", "checked_out"].includes(body.status)
      ? body.status
      : "active";
  if (body.note !== undefined) patch.note = String(body.note);
  if (body.zone_id !== undefined) {
    if (u.role === "sub_admin") return bad(c, "Not allowed", 403);
    patch.zoneId = body.zone_id === null ? null : Number(body.zone_id);
  }
  patch.updatedAt = new Date();
  const rows = await db.update(passes).set(patch).where(eq(passes.id, id)).returning();
  return c.json({ pass: rows[0] });
});

app.delete("/api/passes/:id", async (c) => {
  const u = await auth(c, ["master", "sub_admin"]);
  if (!u) return bad(c, "Unauthorized", 401);
  const id = Number(c.req.param("id"));
  const rows0 = await db.select().from(passes).where(eq(passes.id, id)).limit(1);
  const p = rows0[0];
  if (!p) return bad(c, "Pass not found", 404);
  if (u.role === "sub_admin" && p.zoneId !== u.zoneId) return bad(c, "Not allowed", 403);
  await db.delete(scans).where(eq(scans.passId, id));
  await db.delete(passes).where(eq(passes.id, id));
  return c.json({ ok: true });
});

/* ---------- scan (guard) ---------- */

app.get("/api/scan/:passNo", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  const passNo = String(c.req.param("passNo")).trim();
  const rows = await db.select().from(passes).where(eq(passes.passNo, passNo)).limit(1);
  const p = rows[0];
  if (!p) return bad(c, "Pass not found", 404);
  const recent = await db
    .select()
    .from(scans)
    .where(eq(scans.passId, p.id))
    .orderBy(desc(scans.id))
    .limit(5);
  const evRows = await db.select().from(events).where(eq(events.id, p.eventId)).limit(1);
  const zoneRows = p.zoneId ? await db.select().from(zones).where(eq(zones.id, p.zoneId)).limit(1) : [];
  return c.json({
    pass: { ...p, zoneName: p.zoneId ? (zoneRows[0] ? zoneRows[0].name : "") : "", eventName: evRows[0] ? evRows[0].name : "" },
    event: evRows[0] || null,
    recent,
  });
});

app.post("/api/scan", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  const body = await c.req.json().catch(() => ({}));
  const passNo = String(body.pass_no || "").trim();
  const type = body.type === "exit" ? "exit" : "entry";
  if (!passNo) return bad(c, "pass_no required");
  const rows = await db.select().from(passes).where(eq(passes.passNo, passNo)).limit(1);
  const p = rows[0];
  if (!p) {
    await db.insert(scans).values({
      passId: 0,
      eventId: 0,
      guardId: u.id,
      guardZoneId: u.zoneId,
      type,
      result: "not_found",
    });
    return bad(c, "Pass not found", 404);
  }
  const evRows = await db.select().from(events).where(eq(events.id, p.eventId)).limit(1);
  const ev = evRows[0];
  const zoneRows = p.zoneId ? await db.select().from(zones).where(eq(zones.id, p.zoneId)).limit(1) : [];
  const enrich = (pass) => ({
    ...pass,
    zoneName: pass.zoneId ? (zoneRows[0] ? zoneRows[0].name : "") : "",
    eventName: ev ? ev.name : "",
  });
  if (!ev || ev.status !== "active") {
    await db.insert(scans).values({
      passId: p.id,
      eventId: p.eventId,
      guardId: u.id,
      guardZoneId: u.zoneId,
      type,
      result: "event_closed",
    });
    return c.json({ ok: false, result: "event_closed", pass: enrich(p), message: "Event is closed" });
  }
  if (p.status === "blocked") {
    await db.insert(scans).values({
      passId: p.id,
      eventId: p.eventId,
      guardId: u.id,
      guardZoneId: u.zoneId,
      type,
      result: "blocked",
    });
    return c.json({ ok: false, result: "blocked", pass: enrich(p), message: "Pass is blocked" });
  }
  if (type === "entry" && p.status === "checked_in") {
    await db.insert(scans).values({
      passId: p.id,
      eventId: p.eventId,
      guardId: u.id,
      guardZoneId: u.zoneId,
      type,
      result: "already_in",
    });
    return c.json({ ok: false, result: "already_in", pass: enrich(p), message: "This mumin is already inside (entry already recorded)" });
  }
  if (type === "exit" && p.status !== "checked_in") {
    await db.insert(scans).values({
      passId: p.id,
      eventId: p.eventId,
      guardId: u.id,
      guardZoneId: u.zoneId,
      type,
      result: "no_entry",
    });
    return c.json({ ok: false, result: "no_entry", pass: enrich(p), message: "No entry recorded for this pass — exit is not possible" });
  }
  const newStatus = type === "entry" ? "checked_in" : "checked_out";
  await db
    .update(passes)
    .set({ status: newStatus, updatedAt: new Date() })
    .where(eq(passes.id, p.id));
  await db.insert(scans).values({
    passId: p.id,
    eventId: p.eventId,
    guardId: u.id,
    guardZoneId: u.zoneId,
    type,
    result: "ok",
  });
  return c.json({
    ok: true,
    result: "ok",
    pass: enrich({ ...p, status: newStatus }),
    message: type === "entry" ? "ENTRY ALLOWED" : "EXIT ALLOWED",
  });
});

/* ---------- stats ---------- */

app.get("/api/stats", async (c) => {
  const u = await auth(c);
  if (!u) return bad(c, "Unauthorized", 401);
  const passCount = (extra) => {
    const conds = [];
    if (extra && extra.eventId) conds.push(eq(passes.eventId, extra.eventId));
    if (extra && extra.status) conds.push(eq(passes.status, extra.status));
    if (u.role === "sub_admin") conds.push(eq(passes.zoneId, u.zoneId));
    return db
      .select({ n: count() })
      .from(passes)
      .where(conds.length ? and(...conds) : undefined);
  };
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const scanConds = [];
  if (u.role === "sub_admin") scanConds.push(eq(scans.guardZoneId, u.zoneId));
  scanConds.push(sql`${scans.createdAt} >= ${today.toISOString()}`);
  const todayScans = await db
    .select({ n: count() })
    .from(scans)
    .where(and(...scanConds));
  const activeEvents = await db.select({ n: count() }).from(events).where(eq(events.status, "active"));
  const guardCount = await db
    .select({ n: count() })
    .from(users)
    .where(and(eq(users.role, "guard"), eq(users.status, "active")));
  const totalPasses = await passCount();
  const inside = await passCount({ status: "checked_in" });
  const out = await passCount({ status: "checked_out" });
  const blocked = await passCount({ status: "blocked" });
  const zoneRows = await db.select().from(zones);
  const zoneStats = [];
  for (const z of zoneRows) {
    const guards = await db
      .select({ n: count() })
      .from(users)
      .where(and(eq(users.zoneId, z.id), eq(users.role, "guard"), eq(users.status, "active")));
    const zPasses = await db
      .select({ n: count() })
      .from(passes)
      .where(and(eq(passes.zoneId, z.id), eq(passes.status, "checked_in")));
    const sub = await db
      .select({ n: count() })
      .from(users)
      .where(and(eq(users.zoneId, z.id), eq(users.role, "sub_admin")));
    zoneStats.push({ zone: z, guards: guards[0].n, sub_admins: sub[0].n, inside: zPasses[0].n });
  }
  const recentScans = await db
    .select()
    .from(scans)
    .where(u.role === "sub_admin" ? eq(scans.guardZoneId, u.zoneId) : undefined)
    .orderBy(desc(scans.id))
    .limit(50);
  const passRows = await db.select().from(passes);
  const userRows = await db.select().from(users);
  const pmap = Object.fromEntries(passRows.map((p) => [p.id, p]));
  const umap = Object.fromEntries(userRows.map((x) => [x.id, x.name]));
  const zmap = Object.fromEntries(zoneRows.map((z) => [z.id, z.name]));
  return c.json({
    total_passes: totalPasses[0].n,
    inside: inside[0].n,
    out: out[0].n,
    blocked: blocked[0].n,
    today_scans: todayScans[0].n,
    active_events: activeEvents[0].n,
    active_guards: guardCount[0].n,
    zone_stats: zoneStats,
    recent_scans: recentScans.map((s) => ({
      ...s,
      pass_name: pmap[s.passId] ? pmap[s.passId].name : "(deleted pass)",
      pass_no: pmap[s.passId] ? pmap[s.passId].passNo : "",
      guard_name: umap[s.guardId] || "-",
      zone_name: s.guardZoneId ? zmap[s.guardZoneId] || "" : "",
    })),
  });
});

export default app;
