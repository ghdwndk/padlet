import "server-only";

import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

export function errorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

export const FORBIDDEN = () => errorResponse("허용되지 않은 요청입니다.", 403);
export const UNAUTHORIZED = () => errorResponse("관리자 인증이 필요합니다.", 401);
export const TOO_MANY = () =>
  errorResponse("요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.", 429);
export const BAD_REQUEST = (message = "잘못된 요청입니다.") =>
  errorResponse(message, 400);
export const SERVER_ERROR = (message: string) => errorResponse(message, 500);

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

/**
 * 상태 변경 요청은 브라우저가 보낸 Origin 이 실제 요청 URL 의 host 와 일치해야 한다.
 * Vercel 은 host 를 접속 도메인으로 설정하므로 로컬·Preview·Production 모두 동작한다.
 */
export function isSameOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;

  try {
    const originUrl = new URL(origin);
    const requestUrl = new URL(request.url);
    return originUrl.host === requestUrl.host;
  } catch {
    return false;
  }
}

export async function readJsonObject(
  request: Request,
): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await request.json();
    if (body && typeof body === "object" && !Array.isArray(body)) {
      return body as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Vercel 은 x-forwarded-for 를 덮어써서 실제 클라이언트 공개 IP 만 전달한다
 * (https://vercel.com/docs/headers/request-headers#x-forwarded-for).
 * 로컬 개발에는 헤더가 없을 수 있어 고정 값으로 대체한다.
 */
export function getClientIp(request: Request) {
  const forwarded = request.headers.get("x-forwarded-for");
  const first = forwarded?.split(",")[0]?.trim();
  return first || request.headers.get("x-real-ip")?.trim() || "unknown";
}

function ipKey(request: Request) {
  return createHash("sha256").update(getClientIp(request)).digest("hex").slice(0, 32);
}

export const LIMITS = {
  create: { name: "create", limit: 20, windowSeconds: 600 },
  deleteRequest: { name: "delete", limit: 30, windowSeconds: 600 },
  deleteFail: { name: "delete-fail", limit: 5, windowSeconds: 600 },
  adminFail: { name: "admin-fail", limit: 5, windowSeconds: 900 },
} as const;

type Limit = (typeof LIMITS)[keyof typeof LIMITS];

function limitKey(rule: Limit, request: Request, scope?: string) {
  return [rule.name, scope, ipKey(request)].filter(Boolean).join(":");
}

/** 요청 1회를 기록하고 한도 이내면 true. 저장소 오류 시 예외를 던져 작업을 중단한다. */
export async function consumeRateLimit(
  rule: Limit,
  request: Request,
  scope?: string,
) {
  const { data, error } = await getSupabaseAdmin().rpc("rate_limit_hit", {
    p_key: limitKey(rule, request, scope),
    p_limit: rule.limit,
    p_window_seconds: rule.windowSeconds,
  });
  if (error) throw error;
  return data === true;
}

/** 증가 없이 한도에 도달했는지 확인한다. */
export async function isRateLimited(
  rule: Limit,
  request: Request,
  scope?: string,
) {
  const { data, error } = await getSupabaseAdmin().rpc("rate_limit_is_blocked", {
    p_key: limitKey(rule, request, scope),
    p_limit: rule.limit,
    p_window_seconds: rule.windowSeconds,
  });
  if (error) throw error;
  return data === true;
}
