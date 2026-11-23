CREATE TABLE "access_profiles" (
	"id" serial PRIMARY KEY,
	"name" text NOT NULL UNIQUE,
	"description" text DEFAULT '',
	"color" text DEFAULT '#3b82f6',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "access_rules" (
	"id" serial PRIMARY KEY,
	"scope_type" text NOT NULL,
	"scope_id" integer NOT NULL,
	"target_type" text NOT NULL,
	"target_id" integer NOT NULL,
	"effect" text DEFAULT 'allow' NOT NULL,
	"valid_from" timestamp with time zone,
	"valid_to" timestamp with time zone,
	"note" text DEFAULT '',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "gates" (
	"id" serial PRIMARY KEY,
	"zone_id" integer NOT NULL,
	"name" text NOT NULL,
	"direction" text DEFAULT 'both' NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "pass_presence" (
	"id" serial PRIMARY KEY,
	"pass_id" integer NOT NULL,
	"zone_id" integer NOT NULL,
	"members_inside" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "profile_id" integer;--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "access_mode" text DEFAULT 'rules' NOT NULL;--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "valid_from" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "valid_to" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "members" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "max_entries" integer;--> statement-breakpoint
ALTER TABLE "passes" ADD COLUMN "entry_count" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "gate_id" integer;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "zone_id" integer;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "members" integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "reason" text DEFAULT '';--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "gate_id" integer;--> statement-breakpoint
ALTER TABLE "zones" ADD COLUMN "capacity" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE INDEX "access_rules_scope_idx" ON "access_rules" ("scope_type","scope_id");--> statement-breakpoint
CREATE INDEX "gates_zone_idx" ON "gates" ("zone_id");--> statement-breakpoint
CREATE UNIQUE INDEX "pass_presence_uq" ON "pass_presence" ("pass_id","zone_id");--> statement-breakpoint
CREATE INDEX "pass_presence_zone_idx" ON "pass_presence" ("zone_id");
--> statement-breakpoint
-- Backfill so existing passes/guards keep working exactly as before
UPDATE "passes" SET "access_mode" = 'all' WHERE "zone_id" IS NULL;--> statement-breakpoint
INSERT INTO "access_rules" ("scope_type","scope_id","target_type","target_id","effect","note")
SELECT 'pass', "id", 'zone', "zone_id", 'allow', 'migrated from old single-zone pass' FROM "passes" WHERE "zone_id" IS NOT NULL;--> statement-breakpoint
INSERT INTO "gates" ("zone_id","name","direction")
SELECT "id", 'Main Gate', 'both' FROM "zones";--> statement-breakpoint
INSERT INTO "pass_presence" ("pass_id","zone_id","members_inside")
SELECT l."pass_id", COALESCE(p."zone_id", l."guard_zone_id"), 1
FROM (
  SELECT DISTINCT ON ("pass_id") "pass_id","type","result","guard_zone_id"
  FROM "scans" ORDER BY "pass_id","created_at" DESC,"id" DESC
) l
JOIN "passes" p ON p."id" = l."pass_id"
WHERE l."type" = 'entry' AND l."result" = 'ok' AND COALESCE(p."zone_id", l."guard_zone_id") IS NOT NULL;
