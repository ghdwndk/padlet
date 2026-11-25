import { NextResponse } from "next/server";
import {
  ADMIN_SESSION_SECONDS,
  createAdminSession,
  setAdminCookie,
} from "@/lib/adminSession";
import {
  BAD_REQUEST,
  FORBIDDEN,
  LIMITS,
  SERVER_ERROR,
  TOO_MANY,
  consumeRateLimit,
  errorResponse,
  isRateLimited,
  isSameOrigin,
  readJsonObject,
} from "@/lib/apiSecurity";
import { verifyPassword } from "@/lib/password";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    if (await isRateLimited(LIMITS.adminFail, request)) return TOO_MANY();

    const body = await readJsonObject(request);
    if (!body || typeof body.password !== "string" || body.password.length > 200) {
      return BAD_REQUEST();
    }

    const adminHash = process.env.ADMIN_PASSWORD_HASH;
    if (!adminHash) {
      console.error("ADMIN_PASSWORD_HASH 환경 변수가 설정되지 않았습니다.");
      return SERVER_ERROR("관리자 설정을 확인해 주세요.");
    }

    if (!(await verifyPassword(body.password, adminHash))) {
      await consumeRateLimit(LIMITS.adminFail, request);
      return errorResponse("관리자 비밀번호가 일치하지 않습니다.", 401);
    }

    const token = await createAdminSession();
    const response = NextResponse.json({ ok: true });
    setAdminCookie(response, token, ADMIN_SESSION_SECONDS);
    return response;
  } catch (error) {
    console.error("admin login failed", error);
    return SERVER_ERROR("관리자 로그인에 실패했습니다.");
  }
}
