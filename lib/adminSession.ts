import "server-only";

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import type { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export const ADMIN_COOKIE = "mindlet_admin";
export const ADMIN_SESSION_SECONDS = 60 * 60 * 8;

function sessionSecret() {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (!secret) throw new Error("ADMIN_SESSION_SECRET 환경 변수가 설정되지 않았습니다.");
  return secret;
}

function tokenDigest(token: string) {
  return createHmac("sha256", sessionSecret()).update(token).digest("hex");
}

export function setAdminCookie(response: NextResponse, token: string, maxAge: number) {
  response.cookies.set(ADMIN_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge,
  });
}

export function clearAdminCookie(response: NextResponse) {
  setAdminCookie(response, "", 0);
}

/** 무작위 토큰을 발급하고 HMAC 검증값과 만료시간만 DB 에 저장한다. */
export async function createAdminSession() {
  const token = randomBytes(32).toString("base64url");
  const supabase = getSupabaseAdmin();

  await supabase.from("admin_sessions").delete().lt("expires_at", new Date().toISOString());

  const { error } = await supabase.from("admin_sessions").insert({
    token_hash: tokenDigest(token),
    expires_at: new Date(Date.now() + ADMIN_SESSION_SECONDS * 1000).toISOString(),
  });
  if (error) throw error;
  return token;
}

export async function isAdminRequest() {
  try {
    const token = (await cookies()).get(ADMIN_COOKIE)?.value;
    if (!token || token.length > 128) return false;

    const digest = tokenDigest(token);
    const { data, error } = await getSupabaseAdmin()
      .from("admin_sessions")
      .select("token_hash,expires_at")
      .eq("token_hash", digest)
      .maybeSingle();
    if (error || !data) return false;

    const stored = Buffer.from(data.token_hash);
    const expected = Buffer.from(digest);
    return (
      stored.length === expected.length &&
      timingSafeEqual(stored, expected) &&
      new Date(data.expires_at).getTime() > Date.now()
    );
  } catch (error) {
    console.error("admin session check failed", error);
    return false;
  }
}

export async function destroyAdminSession() {
  const token = (await cookies()).get(ADMIN_COOKIE)?.value;
  if (!token || token.length > 128) return;
  const { error } = await getSupabaseAdmin()
    .from("admin_sessions")
    .delete()
    .eq("token_hash", tokenDigest(token));
  if (error) throw error;
}
