// Demo data + live crowd simulator (for showing the prototype to BGI).
// Everything it creates is named "... (Demo)" so Reset can remove it without touching real data.
import { eq, and, inArray } from "drizzle-orm";
import * as schema from "../../db/schema.ts";
import { processScan } from "./access.mjs";

const { users, zones, events, passes, scans, gates, accessProfiles, accessRules, passPresence } = schema;

const DEMO_EVENT = "Demo Majlis (Demo)";
const ZONES = [
  ["Main Hall (Demo)", 60],
  ["Balcony (Demo)", 30],
  ["Parking (Demo)", 40],
  ["VIP Lounge (Demo)", 8],
];
const GATES = [
  [0, "Hall Gate 1", "in"],
  [0, "Hall Gate 2", "out"],
  [0, "Hall Gate 3", "both"],
  [1, "Balcony Door", "both"],
  [2, "Parking Entry", "in"],
  [2, "Parking Exit", "out"],
  [3, "VIP Door", "both"],
];
const PROFILES = [
  { name: "General (Demo)", color: "#3b82f6", allow: [0, 2], deny: [] },
  { name: "Family (Demo)", color: "#22c55e", allow: [0, 1, 2], deny: [] },
  { name: "VIP (Demo)", color: "#f59e0b", allow: [0, 1, 2, 3], deny: [] },
  { name: "Volunteer (Demo)", color: "#a855f7", allow: [0, 1, 2], deny: [3] },
];
const FIRST = ["Aliasger", "Murtaza", "Husain", "Taher", "Huzefa", "Juzer", "Shabbir", "Mustafa", "Abbas", "Fatema", "Zainab", "Sakina", "Batul", "Rashida", "Husaina", "Tasneem", "Nafisa", "Khadija"];
const LAST = ["Bhopalwala", "Indorewala", "Ujjainwala", "Ratlamwala", "Dhariwala", "Mandsaurwala", "Khandwawala", "Neemuchwala", "Burhanpurwala", "Sehorewala"];
const CITIES = ["Bhopal", "Indore", "Ujjain", "Ratlam", "Dhar", "Khandwa"];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

async function demoEvent(db) {
  return (await db.select().from(events).where(eq(events.name, DEMO_EVENT)).limit(1))[0] || null;
}

export function registerDemoRoutes(app, { db, auth, bad }) {
  app.post("/api/demo/seed", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    if (await demoEvent(db)) return c.json({ ok: true, already: true, message: "Demo data already exists" });

    const ev = (await db.insert(events).values({ name: DEMO_EVENT, venue: "Demo Venue", eventDate: new Date().toISOString().slice(0, 10) }).returning())[0];
    const zrows = [];
    for (const [name, capacity] of ZONES) {
      const ex = (await db.select().from(zones).where(eq(zones.name, name)).limit(1))[0];
      zrows.push(ex || (await db.insert(zones).values({ name, capacity, description: "Demo zone" }).returning())[0]);
    }
    const grows = await db.insert(gates).values(GATES.map(([zi, name, direction]) => ({ zoneId: zrows[zi].id, name, direction }))).returning();

    const prof = [];
    for (const p of PROFILES) {
      const ex = (await db.select().from(accessProfiles).where(eq(accessProfiles.name, p.name)).limit(1))[0];
      const row = ex || (await db.insert(accessProfiles).values({ name: p.name, color: p.color, description: "Demo profile" }).returning())[0];
      prof.push(row);
      await db.delete(accessRules).where(and(eq(accessRules.scopeType, "profile"), eq(accessRules.scopeId, row.id)));
      const rules = [
        ...p.allow.map((zi) => ({ scopeType: "profile", scopeId: row.id, targetType: "zone", targetId: zrows[zi].id, effect: "allow" })),
        ...p.deny.map((zi) => ({ scopeType: "profile", scopeId: row.id, targetType: "zone", targetId: zrows[zi].id, effect: "deny", note: "Volunteers cannot enter VIP" })),
      ];
      await db.insert(accessRules).values(rules);
    }

    // 90 passes: 56 general, 20 family, 8 VIP, 6 volunteer, 4 blocked
    const plan = [[0, 56, 1], [1, 20, 0], [2, 8, 1], [3, 6, 1]];
    const rowsToInsert = [];
    let seq = 1;
    for (const [pi, count, fixed] of plan)
      for (let i = 0; i < count; i++) {
        const members = fixed ? 1 : 2 + Math.floor(Math.random() * 4);
        rowsToInsert.push({
          passNo: "DM" + String(seq++).padStart(3, "0"),
          name: `${pick(FIRST)} ${pick(LAST)}`,
          group: pick(CITIES),
          eventId: ev.id,
          profileId: prof[pi].id,
          members,
          status: "active",
          issuedBy: u.id,
        });
      }
    for (let i = 5; i < 9; i++) rowsToInsert[i].status = "blocked"; // 4 blocked general passes
    const prows = await db.insert(passes).values(rowsToInsert).returning();

    // Pass-level admin overrides, to show the per-pass control
    const gen = prows.filter((p) => p.profileId === prof[0].id && p.status === "active");
    const vip = prows.filter((p) => p.profileId === prof[2].id && p.status === "active");
    const over = [];
    gen.slice(0, 3).forEach((p) => over.push({ scopeType: "pass", scopeId: p.id, targetType: "zone", targetId: zrows[3].id, effect: "allow", note: "Special invite to VIP Lounge" }));
    vip.slice(0, 2).forEach((p) => over.push({ scopeType: "pass", scopeId: p.id, targetType: "zone", targetId: zrows[1].id, effect: "deny", note: "Balcony not permitted" }));
    if (over.length) await db.insert(accessRules).values(over);
    if (gen[3]) await db.update(passes).set({ validTo: new Date(Date.now() - 3600e3) }).where(eq(passes.id, gen[3].id));
    if (gen[4]) await db.update(passes).set({ maxEntries: 1 }).where(eq(passes.id, gen[4].id));

    return c.json({ ok: true, event: ev, zones: zrows.length, gates: grows.length, profiles: prof.length, passes: prows.length });
  });

  // One tick of the simulator: n random scans through the REAL scan engine.
  app.post("/api/demo/step", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const ev = await demoEvent(db);
    if (!ev) return bad(c, "Create demo data first", 400);
    const body = await c.req.json().catch(() => ({}));
    const n = Math.max(1, Math.min(10, Math.floor(Number(body.n) || 3)));

    const zrows = await db.select().from(zones).where(inArray(zones.name, ZONES.map((z) => z[0])));
    const zoneIds = zrows.map((z) => z.id);
    const grows = await db.select().from(gates).where(inArray(gates.zoneId, zoneIds));
    const prows = await db.select().from(passes).where(eq(passes.eventId, ev.id));
    const pres = await db.select().from(passPresence).where(inArray(passPresence.passId, prows.map((p) => p.id)));
    const insideOf = {};
    for (const r of pres) if (r.membersInside > 0) (insideOf[r.passId] = insideOf[r.passId] || new Set()).add(r.zoneId);
    if (!grows.length || !prows.length) return bad(c, "Demo data is incomplete — reset and create again");

    const out = [];
    for (let i = 0; i < n; i++) {
      const p = pick(prows);
      const inZ = [...(insideOf[p.id] || [])];
      const r = Math.random();
      let g;
      if (inZ.length && r < 0.5) g = pick(grows.filter((x) => x.zoneId === pick(inZ) && x.direction !== "in"));
      else if (inZ.length && r < 0.6) g = pick(grows.filter((x) => x.zoneId === pick(inZ) && x.direction !== "out"));
      else g = pick(grows);
      if (!g) g = pick(grows);
      const res = await processScan(db, { user: u, passNo: p.passNo, gateId: g.id, type: "auto" });
      const b = res.body;
      if (b.ok) {
        const set = (insideOf[p.id] = insideOf[p.id] || new Set());
        if (b.type === "entry") set.add(g.zoneId);
        else if (b.insideHere <= 0) set.delete(g.zoneId);
      }
      out.push({ passNo: p.passNo, name: p.name, gate: g.name, type: b.type || "", ok: !!b.ok, result: b.result, message: b.message || b.error || "" });
    }
    return c.json({ ok: true, scans: out });
  });

  // Remove everything the demo created (only "(Demo)" named records).
  app.delete("/api/demo", async (c) => {
    const u = await auth(c, ["master"]);
    if (!u) return bad(c, "Unauthorized", 401);
    const ev = await demoEvent(db);
    let removed = 0;
    if (ev) {
      const ids = (await db.select({ id: passes.id }).from(passes).where(eq(passes.eventId, ev.id))).map((x) => x.id);
      await db.delete(scans).where(eq(scans.eventId, ev.id));
      if (ids.length) {
        await db.delete(passPresence).where(inArray(passPresence.passId, ids));
        await db.delete(accessRules).where(and(eq(accessRules.scopeType, "pass"), inArray(accessRules.scopeId, ids)));
      }
      await db.delete(passes).where(eq(passes.eventId, ev.id));
      await db.delete(events).where(eq(events.id, ev.id));
      removed = ids.length;
    }
    const zrows = await db.select().from(zones).where(inArray(zones.name, ZONES.map((z) => z[0])));
    const zoneIds = zrows.map((z) => z.id);
    if (zoneIds.length) {
      const grows = await db.select().from(gates).where(inArray(gates.zoneId, zoneIds));
      const gateIds = grows.map((g) => g.id);
      if (gateIds.length) {
        await db.update(users).set({ gateId: null }).where(inArray(users.gateId, gateIds));
        await db.delete(accessRules).where(and(eq(accessRules.targetType, "gate"), inArray(accessRules.targetId, gateIds)));
        await db.delete(gates).where(inArray(gates.id, gateIds));
      }
      await db.update(users).set({ zoneId: null }).where(inArray(users.zoneId, zoneIds));
      await db.delete(accessRules).where(and(eq(accessRules.targetType, "zone"), inArray(accessRules.targetId, zoneIds)));
      await db.delete(zones).where(inArray(zones.id, zoneIds));
    }
    const profs = await db.select().from(accessProfiles).where(inArray(accessProfiles.name, PROFILES.map((p) => p.name)));
    for (const p of profs) {
      await db.delete(accessRules).where(and(eq(accessRules.scopeType, "profile"), eq(accessRules.scopeId, p.id)));
      await db.update(passes).set({ profileId: null }).where(eq(passes.profileId, p.id));
      await db.delete(accessProfiles).where(eq(accessProfiles.id, p.id));
    }
    return c.json({ ok: true, passesRemoved: removed });
  });
}
