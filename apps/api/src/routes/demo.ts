import { randomBytes } from "node:crypto";
import { Router } from "express";
import type { Auth } from "../auth.js";
import type { AppConfig } from "../config.js";
import type { Database } from "../db.js";
import { AppError } from "../errors.js";
import { rateLimit } from "../middleware.js";

// One-click sign-in for the public demo copy (demo.buildory.dev), on only when DEMO_EMAIL is set: the live site never sets it.
// It makes sure the demo admin exists in the demo workspace, stores a one-time sign-in token for that email the way the
// magic-link plugin does, and sends the browser through the normal magic-link verification, which creates the session cookie.
const DEMO_NAME = "Demo Evaluator";

export function demoRoutes(database: Database, config: AppConfig, auth: Auth): Router {
  const db = database.db;
  const router = Router();
  router.get("/enter", rateLimit(db, 30, 60_000, "demo-ip"), async (_req, res) => {
    const email = config.DEMO_EMAIL;
    if (!email) throw new AppError(404, "NOT_FOUND", "Not found");
    const workspace = await db.collection("workspaces").findOne({}, { sort: { createdAt: 1 } });
    if (!workspace) throw new AppError(409, "CONFLICT", "The demo workspace is not set up yet");
    const workspaceId = String(workspace._id);
    const context = await auth.$context;
    const user =
      (await context.internalAdapter.findUserByEmail(email))?.user ??
      (await context.internalAdapter.createUser(
        { email, emailVerified: true, name: DEMO_NAME },
        { method: "magic-link" },
      ));
    const now = new Date();
    const ventureIds = (await db.collection("ventures").find({ workspaceId }).project({ _id: 1 }).toArray()).map(
      (venture) => String(venture._id),
    );
    await db
      .collection("users")
      .updateOne(
        { _id: user.id },
        {
          $set: { workspaceId, email, name: DEMO_NAME, handle: "evaluator", status: "active", updatedAt: now },
          $setOnInsert: { createdAt: now },
        },
        { upsert: true },
      );
    await db
      .collection("memberships")
      .updateOne(
        { workspaceId, userId: user.id },
        {
          $set: { role: "admin", status: "active", ventureIds, updatedAt: now },
          $setOnInsert: { _id: "membership-demo-evaluator", allGroupVentureIds: [], groupIds: [], createdAt: now },
        },
        { upsert: true },
      );
    const token = randomBytes(24).toString("hex");
    await context.internalAdapter.createVerificationValue({
      identifier: token,
      value: JSON.stringify({ email, name: DEMO_NAME }),
      expiresAt: new Date(Date.now() + 60_000),
    });
    res.redirect(
      302,
      `/api/auth/magic-link/verify?token=${token}&callbackURL=${encodeURIComponent("/dashboard/live")}`,
    );
  });
  return router;
}
