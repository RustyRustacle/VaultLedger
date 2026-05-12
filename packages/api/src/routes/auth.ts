import { Router } from "express";
import { z } from "zod";
import { prisma } from "@vaultledger/db";
import { supabase } from "../lib/supabase";
import { validate } from "../middleware/validate";
import { authMiddleware, AuthRequest } from "../middleware/auth";
import { AppError } from "../middleware/errorHandler";

export const authRouter = Router();

const registerSchema = z.object({
email: z.string().email(),
password: z.string().min(8),
name: z.string().min(2).max(100),
tenantName: z.string().min(2).max(100),
tenantSlug: z.string().min(2).max(50).regex(/^[a-z0-9-]+$/),
language: z.string().default("id"),
});

const loginSchema = z.object({
email: z.string().email(),
password: z.string().min(1),
});

authRouter.post("/register", validate(registerSchema), async (req, res) => {
const { email, password, name, tenantName, tenantSlug, language } = req.body;

const existing = await supabase.auth.admin.listUsers();
const userExists = existing.data.users.some((u) => u.email === email);
if (userExists) {
throw new AppError(409, "DUPLICATE", "Email already registered");
}

const { data: authUser, error: authError } = await supabase.auth.admin.createUser({
email,
password,
email_confirm: true,
user_metadata: { name },
});

if (authError || !authUser.user) {
throw new AppError(400, "AUTH_ERROR", authError?.message || "Failed to create user");
}

const tenant = await prisma.tenant.create({
data: {
name: tenantName,
slug: tenantSlug,
language,
},
});

await prisma.tenantMember.create({
data: {
tenantId: tenant.id,
userId: authUser.user.id,
role: "ADMIN",
status: "ACCEPTED",
acceptedAt: new Date(),
},
});

const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({
email,
password,
});

if (signInError || !signInData.session) {
throw new AppError(400, "AUTH_ERROR", signInError?.message || "Failed to create session");
}

res.status(201).json({
success: true,
data: {
user: {
id: authUser.user.id,
email,
name,
},
tenant: {
id: tenant.id,
name: tenantName,
slug: tenantSlug,
},
accessToken: signInData.session.access_token,
refreshToken: signInData.session.refresh_token,
},
});
});

authRouter.post("/login", validate(loginSchema), async (req, res) => {
const { email, password } = req.body;

const { data: authData, error } = await supabase.auth.signInWithPassword({
email,
password,
});

if (error || !authData.user) {
throw new AppError(401, "AUTH_REQUIRED", "Invalid email or password");
}

const memberships = await prisma.tenantMember.findMany({
where: {
userId: authData.user.id,
status: "ACCEPTED",
},
include: {
tenant: true,
},
});

if (memberships.length === 0) {
throw new AppError(403, "FORBIDDEN", "No active tenant membership");
}

res.json({
success: true,
data: {
user: {
id: authData.user.id,
email: authData.user.email,
name: authData.user.user_metadata?.name,
},
tenants: memberships.map((m) => ({
id: m.tenant.id,
name: m.tenant.name,
slug: m.tenant.slug,
role: m.role,
})),
accessToken: authData.session!.access_token,
refreshToken: authData.session!.refresh_token,
},
});
});

authRouter.post("/refresh", async (req, res) => {
const { refreshToken } = req.body;
if (!refreshToken) {
throw new AppError(400, "VALIDATION_ERROR", "Refresh token required");
}

const { data, error } = await supabase.auth.refreshSession({ refresh_token: refreshToken });
if (error || !data.session) {
throw new AppError(401, "AUTH_REQUIRED", "Invalid or expired refresh token");
}

res.json({
success: true,
data: {
accessToken: data.session.access_token,
refreshToken: data.session.refresh_token,
},
});
});

authRouter.post("/logout", authMiddleware, async (req: AuthRequest, res) => {
const token = req.headers.authorization?.split(" ")[1];
if (token) {
const { error } = await supabase.auth.admin.signOut(token);
if (error) {
throw new AppError(500, "LOGOUT_ERROR", error.message);
}
}
res.json({ success: true });
});


