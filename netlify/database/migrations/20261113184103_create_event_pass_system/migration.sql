CREATE TABLE "events" (
	"id" serial PRIMARY KEY,
	"name" text NOT NULL,
	"venue" text DEFAULT '',
	"event_date" text DEFAULT '',
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "passes" (
	"id" serial PRIMARY KEY,
	"pass_no" text NOT NULL UNIQUE,
	"name" text NOT NULL,
	"phone" text DEFAULT '',
	"group" text DEFAULT '',
	"event_id" integer NOT NULL,
	"zone_id" integer,
	"status" text DEFAULT 'active' NOT NULL,
	"issued_by" integer,
	"note" text DEFAULT '',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" serial PRIMARY KEY,
	"pass_id" integer NOT NULL,
	"event_id" integer NOT NULL,
	"guard_id" integer NOT NULL,
	"guard_zone_id" integer,
	"type" text NOT NULL,
	"result" text DEFAULT 'ok' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" serial PRIMARY KEY,
	"token" text NOT NULL UNIQUE,
	"user_id" integer NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "settings" (
	"key" text PRIMARY KEY,
	"value" text NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY,
	"role" text DEFAULT 'guard' NOT NULL,
	"name" text NOT NULL,
	"phone" text,
	"username" text NOT NULL UNIQUE,
	"password_hash" text NOT NULL,
	"zone_id" integer,
	"status" text DEFAULT 'active' NOT NULL,
	"created_by" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "zones" (
	"id" serial PRIMARY KEY,
	"name" text NOT NULL UNIQUE,
	"description" text DEFAULT '',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "passes_event_idx" ON "passes" ("event_id");--> statement-breakpoint
CREATE INDEX "passes_zone_idx" ON "passes" ("zone_id");--> statement-breakpoint
CREATE INDEX "scans_pass_idx" ON "scans" ("pass_id");--> statement-breakpoint
CREATE INDEX "scans_event_idx" ON "scans" ("event_id");--> statement-breakpoint
CREATE INDEX "scans_created_idx" ON "scans" ("created_at");