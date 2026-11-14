import { pgTable, serial, text, integer, timestamp, index, uniqueIndex } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  role: text("role").notNull().default("guard"), // master_admin | sub_admin | guard
  name: text("name").notNull(),
  phone: text("phone"),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  zoneId: integer("zone_id"),
  status: text("status").notNull().default("active"), // active | inactive
  createdBy: integer("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const zones = pgTable("zones", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  description: text("description").default(""),
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
    result: text("result").notNull().default("ok"), // ok | denied | duplicate
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
