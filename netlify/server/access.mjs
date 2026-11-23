// Access engine + gate/zone/profile/permission routes for BGI Live Pass.
// Everything here is ADMIN-CONTROLLED: a pass can only enter where the admin has allowed it.
import { eq, and, or, desc, sql, gt, inArray } from "drizzle-orm";
import * as schema from "../../db/schema.ts";

const { users, zones, events, passes, scans, gates, accessProfiles, accessRules, passPresence } = schema;

const inWindow = (r, now) =>
  (!r.validFrom || new Date(r.validFrom) <= now) && (!r.validTo || new Date(r.validTo) >= now);

/**
 * Pure permission decision for ENTRY at a gate.
 * Priority (first level that has an active rule decides; deny beats allow inside a level):
 *   1. pass  -> gate     2. pass    -> zone
 *   3. profile -> gate   4. profile -> zone
 * No matching rule at all = DENIED (admin must explicitly allow).
 */
export function decideAccess({ pass, gate, rules, now = new Date() }) {
  if (pass.validFrom && new Date(pass.validFrom) > now)
    return { allowed: false, result: "not_yet_valid", message: "Pass is not valid yet" };
  if (pass.validTo && new Date(pass.validTo) < now)
    return { allowed: false, result: "expired", message: "Pass has expired" };
  if (pass.accessMode === "all") return { allowed: true, via: "all zones" };

  const levels = [
    ["pass", "gate"],
    ["pass", "zone"],
    ["profile", "gate"],
    ["profile", "zone"],
  ];
  let outOfWindow = false;
  for (const [scope, target] of levels) {
    const targetId = target === "gate" ? gate.id : gate.zoneId;
    const matching = rules.filter(
      (r) => r.scopeType === scope && r.targetType === target && r.targetId === targetId
    );
    if (!matching.length) continue;
    const active = matching.filter((r) => inWindow(r, now));
    if (!active.length) {
      outOfWindow = true;
      continue;
    }
    const denied = active.find((r) => r.effect === "deny");
    if (denied)
      return {
        allowed: false,
        result: "no_permission",
        message: denied.note ? `Access denied: ${denied.note}` : `Admin has denied access to this ${target}`,
        via: `${scope} ${target} rule`,
      };
    return { allowed: true, via: `${scope} ${target} rule` };
  }
  return outOfWindow
    ? { allowed: false, result: "outside_time", message: "Not allowed at this time" }
    : { allowed: false, result: "no_permission", message: "No permission for this zone / gate" };
}

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

async function loadRules(db, p) {
  const scopes = [and(eq(accessRules.scopeType, "pass"), eq(accessRules.scopeId, p.id))];
  if (p.profileId) scopes.push(and(eq(accessRules.scopeType, "profile"), eq(accessRules.scopeId, p.profileId)));
  return db.select().from(accessRules).where(or(...scopes));
}

async function zoneInside(db, zoneId, eventId) {
  const r = await db
    .select({ n: sql`coalesce(sum(${passPresence.membersInside}),0)`.mapWith(Number) })
    .from(passPresence)
    .innerJoin(passes, eq(passes.id, passPresence.passId))
    .where(and(eq(passPresence.zoneId, zoneId), eq(passes.eventId, eventId)));
  return r[0] ? r[0].n : 0;
}

async function allowedZoneNames(db, p, rules) {
  if (p.accessMode === "all") return ["All zones"];
  const allow = rules.filter((r) => r.effect === "allow");
  const passDeniedZones = new Set(
    rules.filter((r) => r.scopeType === "pass" && r.effect === "deny" && r.targetType === "zone").map((r) => r.targetId)
  );
  const zIds = new Set(allow.filter((r) => r.targetType === "zone").map((r) => r.targetId));
  const gIds = allow.filter((r) => r.targetType === "gate").map((r) => r.targetId);
  if (gIds.length) {
    const gs = await db.select().from(gates).where(inArray(gates.id, gIds));
    gs.forEach((g) => zIds.add(g.zoneId));
  }
  passDeniedZones.forEach((id) => zIds.delete(id));
  if (!zIds.size) return [];
  const zs = await db.select().from(zones).where(inArray(zones.id, [...zIds]));
  return zs.map((z) => z.name);
}

/**
 * Smart scan. Used by the guard app and by the demo simulator.
 * Returns { status, body } so the caller just does c.json(body, status).
 */
export async function processScan(db, { user, passNo, gateId, type, members, now = new Date() }) {
  const gate = gateId ? (await db.select().from(gates).where(eq(gates.id, gateId)).limit(1))[0] : null;
  if (!gate) return { status: 400, body: { ok: false, result: "no_gate", error: "Select your gate first" } };
  const zone = (await db.select().from(zones).where(eq(zones.id, gate.zoneId)).limit(1))[0];

  const p = (await db.select().from(passes).where(eq(passes.passNo, String(passNo).trim())).limit(1))[0];
  if (!p) {
    await db.insert(scans).values({
      passId: 0, eventId: 0, guardId: user.id, guardZoneId: user.zoneId, type: "entry",
      result: "not_found", gateId: gate.id, zoneId: gate.zoneId, reason: "Pass not found",
    });
    return { status: 404, body: { ok: false, result: "not_found", error: "Pass not found" } };
  }

  const ev = (await db.select().from(events).where(eq(events.id, p.eventId)).limit(1))[0];
  const presRow = (
    await db.select().from(passPresence)
      .where(and(eq(passPresence.passId, p.id), eq(passPresence.zoneId, gate.zoneId))).limit(1)
  )[0];
  const inside = presRow ? presRow.membersInside : 0;

  // Smart IN/OUT: gate direction wins; "both" gates can auto-detect from presence.
  const reqType = type === "exit" ? "exit" : type === "entry" ? "entry" : "auto";
  let t;
  if (gate.direction === "in") t = "entry";
  else if (gate.direction === "out") t = "exit";
  else t = reqType === "auto" ? (inside > 0 ? "exit" : "entry") : reqType;

  const zoneName = zone ? zone.name : "";
  const enrich = (pass) => ({
    ...pass,
    zoneName: pass.zoneId ? zoneName : "",
    eventName: ev ? ev.name : "",
  });
  const ctx = () => ({
    pass: enrich(p),
    type: t,
    gate: { id: gate.id, name: gate.name, direction: gate.direction },
    zone: { id: zone ? zone.id : null, name: zoneName, capacity: zone ? zone.capacity : 0 },
    insideHere: inside,
  });
  const record = (result, reason, n) =>
    db.insert(scans).values({
      passId: p.id, eventId: p.eventId, guardId: user.id, guardZoneId: user.zoneId,
      type: t, result, gateId: gate.id, zoneId: gate.zoneId, members: n || 1, reason: reason || "",
    });
  const deny = async (result, message, extra = {}) => {
    await record(result, message, 1);
    return { status: 200, body: { ok: false, result, message, ...ctx(), ...extra } };
  };

  if (!ev || ev.status !== "active") return deny("event_closed", "Event is closed");
  if (p.status === "blocked") return deny("blocked", "Pass is blocked");
  if (gate.status !== "open") return deny("gate_closed", "This gate is closed");

  const want = members ? Math.floor(Number(members)) : null;

  if (t === "exit") {
    if (inside <= 0) return deny("no_entry", "No entry recorded in this zone — exit is not possible");
    const n = clamp(want || inside, 1, inside);
    const upd = await db.update(passPresence)
      .set({ membersInside: sql`${passPresence.membersInside} - ${n}`, updatedAt: now })
      .where(and(eq(passPresence.passId, p.id), eq(passPresence.zoneId, gate.zoneId), sql`${passPresence.membersInside} >= ${n}`))
      .returning();
    if (!upd.length) return deny("no_entry", "No entry recorded in this zone — exit is not possible");
    const tot = await db.select({ n: sql`coalesce(sum(${passPresence.membersInside}),0)`.mapWith(Number) })
      .from(passPresence).where(eq(passPresence.passId, p.id));
    const newStatus = tot[0].n > 0 ? "checked_in" : "checked_out";
    await db.update(passes).set({ status: newStatus, updatedAt: now }).where(eq(passes.id, p.id));
    await record("ok", "", n);
    return {
      status: 200,
      body: { ok: true, result: "ok", message: "EXIT ALLOWED", ...ctx(), pass: enrich({ ...p, status: newStatus }),
        members: n, insideHere: inside - n, zoneInside: await zoneInside(db, gate.zoneId, p.eventId) },
    };
  }

  // ---- ENTRY ----
  const rules = await loadRules(db, p);
  const d = decideAccess({ pass: p, gate, rules, now });
  if (!d.allowed) {
    const allowedZones = d.result === "no_permission" ? await allowedZoneNames(db, p, rules) : [];
    return deny(d.result, d.message, { allowedZones });
  }
  if (inside === 0 && p.maxEntries != null && p.entryCount >= p.maxEntries)
    return deny("max_entries", `Entry limit reached (${p.maxEntries})`);
  const remaining = p.members - inside;
  if (remaining <= 0)
    return deny("already_in", p.members > 1
      ? `All ${p.members} members are already inside`
      : "This mumin is already inside (entry already recorded)");
  const n = clamp(want || remaining, 1, remaining);

  const cur = await zoneInside(db, gate.zoneId, p.eventId);
  if (zone && zone.capacity > 0 && cur + n > zone.capacity)
    return deny("zone_full", `${zoneName} is full (${cur}/${zone.capacity})`, { zoneInside: cur });

  // Atomic per-pass guard: two simultaneous scans can never push a pass over its member count.
  await db.insert(passPresence).values({ passId: p.id, zoneId: gate.zoneId, membersInside: 0 }).onConflictDoNothing();
  const upd = await db.update(passPresence)
    .set({ membersInside: sql`${passPresence.membersInside} + ${n}`, updatedAt: now })
    .where(and(eq(passPresence.passId, p.id), eq(passPresence.zoneId, gate.zoneId), sql`${passPresence.membersInside} + ${n} <= ${p.members}`))
    .returning();
  if (!upd.length) return deny("already_in", "This mumin is already inside (entry already recorded)");

  const patch = { status: "checked_in", updatedAt: now };
  if (inside === 0) patch.entryCount = sql`${passes.entryCount} + 1`;
  await db.update(passes).set(patch).where(eq(passes.id, p.id));
  await record("ok", "", n);
  return {
    status: 200,
    body: { ok: true, result: "ok", message: "ENTRY ALLOWED", ...ctx(), pass: enrich({ ...p, status: "checked_in" }),
      members: n, insideHere: inside + n, zoneInside: cur + n, via: d.via },
  };
}

/* ================== routes ================== */

const toInt = (v) => (v === undefined || v === null || v === "" ? null : Math.floor(Number(v)));
const toDate = (v) => (v ? new Date(v) : null);
const DIRS = ["in", "out", "both"];

export function registerAccessRoutes(app, { db, auth, bad }) {
  /* ----- scan (guard) : gate-aware, permission-checked ----- */
  app.post("/api/scan", async (c) => {
    const u = await auth(c);
    if (!u) return bad(c, "Unauthorized", 401);
    const body = await c.req.json().catch(() => ({}));
    const passNo = String(body.pass_no || "").trim();
    if (!passNo) return bad(c, "pass_no required");
    const gateId = u.gateId || toInt(body.gate_id);
    if (u.role === "guard" && u.zoneId && !u.gateId && gateId) {
      const g = (await db.select().from(gates).where(eq(gates.id, gateId)).limit(1))[0];
      if (g && g.zoneId !== u.zoneId) return bad(c, "This gate is not in your zone", 403);
    }
    const r = await processScan(db, { user: u, passNo, gateId, type: body.type, members: body.members });
    return c.json(r.body, r.status);
  });

  /* ----- gates ----- */
  app.get("/api/gates", async (c) => {
    const u = await auth(c);
    if (!u) return bad(c, "Unauthorized", 401);
    let rows = await db
      .select({ id: gates.id, zoneId: gates.zoneId, name: gates.name, direction: gates.direction, status: gates.status, zoneName: zones.name })
      .from(gates)
      .leftJoin(zones, eq(zones.id, gates.zoneId))
      .orderBy(gates.zoneId, gates.id);
    if (u.role !== "master" && u.zoneId) rows = rows.filter((g) => g.zoneId === u.zoneId);
    return c.json({ gates: rows });
  });

  app.post("/api/gates", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const b = await c.req.json().catch(() => ({}));
    const name = String(b.name || "").trim();
    const zoneId = toInt(b.zone_id);
    if (!name || !zoneId) return bad(c, "Gate name and zone required");
    const direction = DIRS.includes(b.direction) ? b.direction : "both";
    const rows = await db.insert(gates).values({ name, zoneId, direction }).returning();
    return c.json({ gate: rows[0] });
  });

  app.put("/api/gates/:id", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const b = await c.req.json().catch(() => ({}));
    const patch = {};
    if (b.name !== undefined) patch.name = String(b.name).trim();
    if (b.zone_id !== undefined) patch.zoneId = toInt(b.zone_id);
    if (DIRS.includes(b.direction)) patch.direction = b.direction;
    if (b.status === "open" || b.status === "closed") patch.status = b.status;
    const rows = await db.update(gates).set(patch).where(eq(gates.id, Number(c.req.param("id")))).returning();
    if (!rows[0]) return bad(c, "Gate not found", 404);
    return c.json({ gate: rows[0] });
  });

  app.delete("/api/gates/:id", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const id = Number(c.req.param("id"));
    await db.update(users).set({ gateId: null }).where(eq(users.gateId, id));
    await db.delete(accessRules).where(and(eq(accessRules.targetType, "gate"), eq(accessRules.targetId, id)));
    await db.delete(gates).where(eq(gates.id, id));
    return c.json({ ok: true });
  });

  /* ----- access profiles (permission templates) ----- */
  const cleanRules = (list) => {
    const out = [];
    const seen = new Set();
    for (const r of Array.isArray(list) ? list : []) {
      const targetType = r.target_type === "gate" ? "gate" : r.target_type === "zone" ? "zone" : null;
      const targetId = toInt(r.target_id);
      if (!targetType || !targetId) continue;
      const effect = r.effect === "deny" ? "deny" : "allow";
      let vf = toDate(r.valid_from);
      let vt = toDate(r.valid_to);
      if (vf && isNaN(vf)) vf = null;
      if (vt && isNaN(vt)) vt = null;
      const key = [targetType, targetId, effect, vf ? vf.getTime() : "", vt ? vt.getTime() : ""].join(":");
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ targetType, targetId, effect, validFrom: vf, validTo: vt, note: String(r.note || "").slice(0, 200) });
    }
    return out;
  };

  const replaceRules = async (scopeType, scopeId, list) => {
    await db.delete(accessRules).where(and(eq(accessRules.scopeType, scopeType), eq(accessRules.scopeId, scopeId)));
    const rows = cleanRules(list).map((r) => ({ ...r, scopeType, scopeId }));
    if (rows.length) await db.insert(accessRules).values(rows);
    return rows.length;
  };

  app.get("/api/profiles", async (c) => {
    const u = await auth(c, ["master", "sub_admin"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const rows = await db.select().from(accessProfiles).orderBy(accessProfiles.id);
    const rc = await db
      .select({ id: accessRules.scopeId, n: sql`count(*)`.mapWith(Number) })
      .from(accessRules).where(eq(accessRules.scopeType, "profile")).groupBy(accessRules.scopeId);
    const pc = await db
      .select({ id: passes.profileId, n: sql`count(*)`.mapWith(Number) })
      .from(passes).where(sql`${passes.profileId} is not null`).groupBy(passes.profileId);
    const rmap = Object.fromEntries(rc.map((x) => [x.id, x.n]));
    const pmap = Object.fromEntries(pc.map((x) => [x.id, x.n]));
    return c.json({ profiles: rows.map((p) => ({ ...p, ruleCount: rmap[p.id] || 0, passCount: pmap[p.id] || 0 })) });
  });

  app.post("/api/profiles", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const b = await c.req.json().catch(() => ({}));
    const name = String(b.name || "").trim();
    if (!name) return bad(c, "Profile name required");
    const dup = await db.select({ id: accessProfiles.id }).from(accessProfiles).where(eq(accessProfiles.name, name)).limit(1);
    if (dup[0]) return bad(c, "A profile with this name already exists");
    const rows = await db.insert(accessProfiles)
      .values({ name, description: String(b.description || ""), color: String(b.color || "#3b82f6") }).returning();
    if (b.rules) await replaceRules("profile", rows[0].id, b.rules);
    return c.json({ profile: rows[0] });
  });

  app.put("/api/profiles/:id", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const id = Number(c.req.param("id"));
    const b = await c.req.json().catch(() => ({}));
    const patch = {};
    if (b.name !== undefined) patch.name = String(b.name).trim();
    if (b.description !== undefined) patch.description = String(b.description);
    if (b.color !== undefined) patch.color = String(b.color);
    let row = (await db.select().from(accessProfiles).where(eq(accessProfiles.id, id)).limit(1))[0];
    if (!row) return bad(c, "Profile not found", 404);
    if (Object.keys(patch).length) row = (await db.update(accessProfiles).set(patch).where(eq(accessProfiles.id, id)).returning())[0];
    if (b.rules !== undefined) await replaceRules("profile", id, b.rules);
    return c.json({ profile: row });
  });

  app.delete("/api/profiles/:id", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const id = Number(c.req.param("id"));
    await db.update(passes).set({ profileId: null }).where(eq(passes.profileId, id));
    await db.delete(accessRules).where(and(eq(accessRules.scopeType, "profile"), eq(accessRules.scopeId, id)));
    await db.delete(accessProfiles).where(eq(accessProfiles.id, id));
    return c.json({ ok: true });
  });

  /* ----- per-pass / per-profile permissions (the admin's control panel) ----- */
  const sd = (v) => {
    if (!v) return null;
    const d = new Date(v);
    return isNaN(d) ? null : d;
  };
  const passPatch = (b) => {
    const p = {};
    if (b.profile_id !== undefined) p.profileId = toInt(b.profile_id);
    if (b.access_mode === "all" || b.access_mode === "rules") p.accessMode = b.access_mode;
    if (b.valid_from !== undefined) p.validFrom = sd(b.valid_from);
    if (b.valid_to !== undefined) p.validTo = sd(b.valid_to);
    if (b.max_entries !== undefined) p.maxEntries = toInt(b.max_entries);
    if (b.members !== undefined) p.members = Math.max(1, toInt(b.members) || 1);
    return p;
  };

  app.get("/api/access/:scope/:id", async (c) => {
    const u = await auth(c, ["master", "sub_admin"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const scope = c.req.param("scope");
    if (scope !== "pass" && scope !== "profile") return bad(c, "Invalid scope");
    const rules = await db.select().from(accessRules)
      .where(and(eq(accessRules.scopeType, scope), eq(accessRules.scopeId, Number(c.req.param("id")))))
      .orderBy(accessRules.id);
    return c.json({ rules });
  });

  // Replace a pass's (or profile's) rules; for a pass, optional pass-level settings in body.pass
  app.put("/api/access/:scope/:id", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const scope = c.req.param("scope");
    const id = Number(c.req.param("id"));
    if (scope !== "pass" && scope !== "profile") return bad(c, "Invalid scope");
    const b = await c.req.json().catch(() => ({}));
    if (scope === "pass") {
      const exists = (await db.select({ id: passes.id }).from(passes).where(eq(passes.id, id)).limit(1))[0];
      if (!exists) return bad(c, "Pass not found", 404);
      const patch = passPatch(b.pass || {});
      if (Object.keys(patch).length) await db.update(passes).set({ ...patch, updatedAt: new Date() }).where(eq(passes.id, id));
    }
    const n = b.rules !== undefined ? await replaceRules(scope, id, b.rules) : null;
    return c.json({ ok: true, rules: n });
  });

  // Bulk: apply profile / settings / rules to many passes at once
  app.post("/api/access/bulk", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const b = await c.req.json().catch(() => ({}));
    let ids = Array.isArray(b.pass_ids) ? b.pass_ids.map(Number).filter(Boolean) : [];
    if (!ids.length) {
      const f = b.filter || {};
      if (!toInt(f.event_id)) return bad(c, "Select passes, or give a filter with event_id");
      const conds = [eq(passes.eventId, toInt(f.event_id))];
      if (f.group) conds.push(eq(passes.group, String(f.group)));
      if (toInt(f.profile_id)) conds.push(eq(passes.profileId, toInt(f.profile_id)));
      ids = (await db.select({ id: passes.id }).from(passes).where(and(...conds)).limit(5000)).map((x) => x.id);
    }
    if (!ids.length) return c.json({ updated: 0 });
    const patch = passPatch(b.apply || {});
    if (Object.keys(patch).length) await db.update(passes).set({ ...patch, updatedAt: new Date() }).where(inArray(passes.id, ids));
    const mode = b.rules_mode;
    if (mode === "replace" || mode === "clear")
      await db.delete(accessRules).where(and(eq(accessRules.scopeType, "pass"), inArray(accessRules.scopeId, ids)));
    if ((mode === "replace" || mode === "add") && Array.isArray(b.rules)) {
      const base = cleanRules(b.rules);
      const rows = ids.flatMap((id) => base.map((r) => ({ ...r, scopeType: "pass", scopeId: id })));
      for (let i = 0; i < rows.length; i += 500) await db.insert(accessRules).values(rows.slice(i, i + 500));
    }
    return c.json({ updated: ids.length });
  });

  // "Can this pass go through each gate right now?" — the admin's what-if matrix
  app.get("/api/access/pass/:id/effective", async (c) => {
    const u = await auth(c, ["master", "sub_admin"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const p = (await db.select().from(passes).where(eq(passes.id, Number(c.req.param("id")))).limit(1))[0];
    if (!p) return bad(c, "Pass not found", 404);
    const rules = await loadRules(db, p);
    const gs = await db
      .select({ id: gates.id, zoneId: gates.zoneId, name: gates.name, direction: gates.direction, status: gates.status, zoneName: zones.name })
      .from(gates).leftJoin(zones, eq(zones.id, gates.zoneId)).orderBy(gates.zoneId, gates.id);
    const matrix = gs.map((g) => {
      const d = decideAccess({ pass: p, gate: g, rules });
      return { gateId: g.id, gateName: g.name, zoneId: g.zoneId, zoneName: g.zoneName, direction: g.direction,
        gateStatus: g.status, allowed: d.allowed, result: d.result || "ok", message: d.message || "", via: d.via || "" };
    });
    const presence = await db.select().from(passPresence).where(eq(passPresence.passId, p.id));
    return c.json({ pass: p, rules, matrix, presence });
  });

  /* ----- live command center ----- */
  app.get("/api/live", async (c) => {
    const u = await auth(c, ["master", "sub_admin"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const evs = await db.select().from(events).orderBy(desc(events.id));
    const wanted = toInt(c.req.query("event_id"));
    const ev = evs.find((e) => e.id === wanted) || evs.find((e) => e.status === "active") || evs[0];
    if (!ev) return c.json({ event: null, zones: [], recent: [], totals: {}, alerts: [], hourly: [] });

    let zs = await db.select().from(zones).orderBy(zones.id);
    if (u.role === "sub_admin" && u.zoneId) zs = zs.filter((z) => z.id === u.zoneId);
    const gs = await db.select().from(gates).orderBy(gates.id);
    const now = Date.now();
    const since5 = new Date(now - 5 * 60e3);
    const since24 = new Date(now - 24 * 3600e3);
    const since12 = new Date(now - 12 * 3600e3);

    const pres = await db
      .select({ zoneId: passPresence.zoneId, n: sql`coalesce(sum(${passPresence.membersInside}),0)`.mapWith(Number) })
      .from(passPresence).innerJoin(passes, eq(passes.id, passPresence.passId))
      .where(eq(passes.eventId, ev.id)).groupBy(passPresence.zoneId);
    const presMap = Object.fromEntries(pres.map((x) => [x.zoneId, x.n]));

    const g5 = await db
      .select({ gateId: scans.gateId, result: scans.result, n: sql`count(*)`.mapWith(Number) })
      .from(scans).where(and(eq(scans.eventId, ev.id), gt(scans.createdAt, since5)))
      .groupBy(scans.gateId, scans.result);

    const agg = await db
      .select({ type: scans.type, result: scans.result, n: sql`count(*)`.mapWith(Number), m: sql`coalesce(sum(${scans.members}),0)`.mapWith(Number) })
      .from(scans).where(and(eq(scans.eventId, ev.id), gt(scans.createdAt, since24)))
      .groupBy(scans.type, scans.result);

    const pstat = await db
      .select({ status: passes.status, n: sql`count(*)`.mapWith(Number) })
      .from(passes).where(eq(passes.eventId, ev.id)).groupBy(passes.status);

    const hourExpr = sql`date_trunc('hour', ${scans.createdAt})`;
    const hrows = await db
      .select({ h: hourExpr, type: scans.type, m: sql`coalesce(sum(${scans.members}),0)`.mapWith(Number) })
      .from(scans)
      .where(and(eq(scans.eventId, ev.id), eq(scans.result, "ok"), gt(scans.createdAt, since12)))
      .groupBy(hourExpr, scans.type);
    const hmap = {};
    for (const r of hrows) {
      const k = new Date(r.h).toISOString();
      hmap[k] = hmap[k] || { hour: k, entries: 0, exits: 0 };
      if (r.type === "entry") hmap[k].entries += r.m;
      else hmap[k].exits += r.m;
    }

    const recent = await db
      .select({
        id: scans.id, createdAt: scans.createdAt, type: scans.type, result: scans.result, reason: scans.reason,
        members: scans.members, passNo: passes.passNo, name: passes.name, gate: gates.name, guard: users.name,
      })
      .from(scans)
      .leftJoin(passes, eq(scans.passId, passes.id))
      .leftJoin(gates, eq(scans.gateId, gates.id))
      .leftJoin(users, eq(scans.guardId, users.id))
      .where(eq(scans.eventId, ev.id)).orderBy(desc(scans.id)).limit(20);

    const alerts = [];
    const zoneOut = zs.map((z) => {
      const inside = presMap[z.id] || 0;
      const pct = z.capacity > 0 ? Math.round((inside / z.capacity) * 100) : null;
      if (pct !== null && pct >= 100) alerts.push({ level: "red", text: `${z.name} is FULL (${inside}/${z.capacity})` });
      else if (pct !== null && pct >= 80) alerts.push({ level: "amber", text: `${z.name} is ${pct}% full (${inside}/${z.capacity})` });
      const zg = gs.filter((g) => g.zoneId === z.id).map((g) => {
        const rows = g5.filter((r) => r.gateId === g.id);
        const ok = rows.filter((r) => r.result === "ok").reduce((a, r) => a + r.n, 0);
        const denied = rows.filter((r) => r.result !== "ok").reduce((a, r) => a + r.n, 0);
        if (denied >= 5) alerts.push({ level: "amber", text: `${g.name}: ${denied} denied scans in last 5 min` });
        return { id: g.id, name: g.name, direction: g.direction, status: g.status, ok5m: ok, denied5m: denied };
      });
      return { id: z.id, name: z.name, capacity: z.capacity, inside, pct, gates: zg };
    });
    const blocked = agg.filter((r) => r.result === "blocked").reduce((a, r) => a + r.n, 0);
    if (blocked) alerts.push({ level: "red", text: `${blocked} scan(s) of BLOCKED passes in last 24h` });

    const sum = (f) => agg.filter(f).reduce((a, r) => a + r.m, 0);
    const pcount = (s) => (pstat.find((x) => x.status === s) || { n: 0 }).n;
    return c.json({
      event: ev,
      zones: zoneOut,
      totals: {
        passes: pstat.reduce((a, r) => a + r.n, 0),
        passesInside: pcount("checked_in"),
        entries24h: sum((r) => r.type === "entry" && r.result === "ok"),
        exits24h: sum((r) => r.type === "exit" && r.result === "ok"),
        denied24h: agg.filter((r) => r.result !== "ok").reduce((a, r) => a + r.n, 0),
      },
      alerts,
      recent,
      hourly: Object.values(hmap).sort((a, b) => a.hour.localeCompare(b.hour)),
      serverTime: new Date().toISOString(),
    });
  });
}
