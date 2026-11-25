import { NextResponse } from "next/server";
import { clearAdminCookie, destroyAdminSession } from "@/lib/adminSession";
import { FORBIDDEN, SERVER_ERROR, isSameOrigin } from "@/lib/apiSecurity";

export const runtime = "nodejs";

export async function POST(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    await destroyAdminSession();
  } catch (error) {
    console.error("admin logout failed", error);
    return SERVER_ERROR("로그아웃에 실패했습니다.");
  }

  const response = NextResponse.json({ ok: true });
  clearAdminCookie(response);
  return response;
}
