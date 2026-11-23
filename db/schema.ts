import { pgTable, serial, text, integer, timestamp, index, uniqueIndex } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  role: text("role").notNull().default("guard"), // master_admin | sub_admin | guard
  name: text("name").notNull(),
  phone: text("phone"),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  zoneId: integer("zone_id"),
  gateId: integer("gate_id"), // guard's assigned gate (optional)
  status: text("status").notNull().default("active"), // active | inactive
  createdBy: integer("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const zones = pgTable("zones", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description").default(""),
  capacity: integer("capacity").notNull().default(0), // 0 = unlimited (people allowed inside at once)
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const events = pgTable("events", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  venue: text("venue").default(""),
  eventDate: text("event_date").default(""),
  status: text("status").notNull().default("active"), // active | ended
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const passes = pgTable(
  "passes",
  {
    id: serial("id").primaryKey(),
    passNo: text("pass_no").notNull().unique(),
    name: text("name").notNull(),
    phone: text("phone").default(""),
    group: text("group").default(""),
    eventId: integer("event_id").notNull(),
    zoneId: integer("zone_id"),
    status: text("status").notNull().default("active"), // active | revoked | blacklisted
    issuedBy: integer("issued_by"),
    note: text("note").default(""),
    // --- admin-controlled access ---
    profileId: integer("profile_id"), // access profile (template) this pass follows
    accessMode: text("access_mode").notNull().default("rules"), // rules | all (all zones/gates)
    validFrom: timestamp("valid_from", { withTimezone: true }),
    validTo: timestamp("valid_to", { withTimezone: true }),
    members: integer("members").notNull().default(1), // family/group pass size
    maxEntries: integer("max_entries"), // null = unlimited re-entries
    entryCount: integer("entry_count").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [index("passes_event_idx").on(t.eventId), index("passes_zone_idx").on(t.zoneId)]
);

export const scans = pgTable(
  "scans",
  {
    id: serial("id").primaryKey(),
    passId: integer("pass_id").notNull(),
    eventId: integer("event_id").notNull(),
    guardId: integer("guard_id").notNull(),
    guardZoneId: integer("guard_zone_id"),
    type: text("type").notNull(), // entry | exit
    result: text("result").notNull().default("ok"), // ok | denied | duplicate | no_permission | zone_full ...
    gateId: integer("gate_id"),
    zoneId: integer("zone_id"),
    members: integer("members").notNull().default(1),
    reason: text("reason").default(""),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [index("scans_pass_idx").on(t.passId), index("scans_event_idx").on(t.eventId), index("scans_created_idx").on(t.createdAt)]
);

export const sessions = pgTable("sessions", {
  id: serial("id").primaryKey(),
  token: text("token").notNull().unique(),
  userId: integer("user_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
});

export const settings = pgTable("settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});

/* ---------- gates, access profiles, admin-controlled access rules ---------- */

export const gates = pgTable(
  "gates",
  {
    id: serial("id").primaryKey(),
    zoneId: integer("zone_id").notNull(),
    name: text("name").notNull(),
    direction: text("direction").notNull().default("both"), // in | out | both
    status: text("status").notNull().default("open"), // open | closed
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [index("gates_zone_idx").on(t.zoneId)]
);

// A reusable permission template (e.g. "VIP", "General Mumin", "Volunteer")
export const accessProfiles = pgTable("access_profiles", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description").default(""),
  color: text("color").default("#3b82f6"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

// Admin decides: for a profile OR a single pass -> allow/deny a zone OR a gate
export const accessRules = pgTable(
  "access_rules",
  {
    id: serial("id").primaryKey(),
    scopeType: text("scope_type").notNull(), // profile | pass
    scopeId: integer("scope_id").notNull(),
    targetType: text("target_type").notNull(), // zone | gate
    targetId: integer("target_id").notNull(),
    effect: text("effect").notNull().default("allow"), // allow | deny
    validFrom: timestamp("valid_from", { withTimezone: true }),
    validTo: timestamp("valid_to", { withTimezone: true }),
    note: text("note").default(""),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [index("access_rules_scope_idx").on(t.scopeType, t.scopeId)]
);

// Who is currently inside which zone (drives anti-passback + live counts + capacity)
export const passPresence = pgTable(
  "pass_presence",
  {
    id: serial("id").primaryKey(),
    passId: integer("pass_id").notNull(),
    zoneId: integer("zone_id").notNull(),
    membersInside: integer("members_inside").notNull().default(0),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    uniqueIndex("pass_presence_uq").on(t.passId, t.zoneId),
    index("pass_presence_zone_idx").on(t.zoneId),
  ]
);
