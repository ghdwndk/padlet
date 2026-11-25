import "server-only";

import { NextResponse } from "next/server";
import { isAdminRequest } from "@/lib/adminSession";
import {
  BAD_REQUEST,
  FORBIDDEN,
  LIMITS,
  SERVER_ERROR,
  TOO_MANY,
  UNAUTHORIZED,
  consumeRateLimit,
  errorResponse,
  isRateLimited,
  isSameOrigin,
  isUuid,
  readJsonObject,
} from "@/lib/apiSecurity";
import { PASTEL_COLORS } from "@/lib/colors";
import { hashPassword, isFourDigitPassword, verifyPassword } from "@/lib/password";
import { getSupabaseAdmin } from "@/lib/supabaseAdmin";

function pickColor(value: unknown): string | null {
  if (value === undefined || value === null || value === "") {
    return PASTEL_COLORS[Math.floor(Math.random() * PASTEL_COLORS.length)];
  }
  return typeof value === "string" && (PASTEL_COLORS as readonly string[]).includes(value)
    ? value
    : null;
}

export async function handleCreateMemo(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    if (!(await consumeRateLimit(LIMITS.create, request))) return TOO_MANY();

    const body = await readJsonObject(request);
    if (!body) return BAD_REQUEST();

    const title = typeof body.title === "string" ? body.title.trim() : "";
    const content = typeof body.content === "string" ? body.content.trim() : "";
    const color = pickColor(body.color);

    if (!title || !content) return BAD_REQUEST("제목과 내용을 모두 입력해 주세요.");
    if (title.length > 80 || content.length > 2000) {
      return BAD_REQUEST("메모가 허용된 길이를 초과했습니다.");
    }
    if (!color) return BAD_REQUEST("허용되지 않은 색상입니다.");
    if (!isFourDigitPassword(body.password)) {
      return BAD_REQUEST("삭제 비밀번호는 숫자 4자리여야 합니다.");
    }

    const passwordHash = await hashPassword(body.password);
    const { data, error } = await getSupabaseAdmin().rpc("create_memo_with_credentials", {
      p_title: title,
      p_content: content,
      p_color: color,
      p_password_hash: passwordHash,
    });
    if (error) throw error;

    return NextResponse.json({ memo: data }, { status: 201 });
  } catch (error) {
    console.error("create memo failed", error);
    return SERVER_ERROR("메모를 저장하지 못했습니다.");
  }
}

export async function handleOwnerDelete(request: Request, id: unknown) {
  if (!isSameOrigin(request)) return FORBIDDEN();

  try {
    const body = await readJsonObject(request);
    if (!body) return BAD_REQUEST();
    if (!isUuid(id) || !isFourDigitPassword(body.password)) {
      return BAD_REQUEST("메모와 숫자 4자리 비밀번호를 확인해 주세요.");
    }

    if (!(await consumeRateLimit(LIMITS.deleteRequest, request))) return TOO_MANY();
    if (await isRateLimited(LIMITS.deleteFail, request, id)) return TOO_MANY();

    const supabase = getSupabaseAdmin();
    const { data: credential, error: readError } = await supabase
      .from("memo_credentials")
      .select("password_hash")
      .eq("memo_id", id)
      .maybeSingle();
    if (readError) throw readError;

    const matches = credential
      ? await verifyPassword(body.password, credential.password_hash)
      : false;

    if (!matches) {
      await consumeRateLimit(LIMITS.deleteFail, request, id);
      return credential
        ? errorResponse("삭제 비밀번호가 일치하지 않습니다.", 403)
        : errorResponse("메모를 찾을 수 없습니다.", 404);
    }

    const { error: deleteError } = await supabase.from("memos").delete().eq("id", id);
    if (deleteError) throw deleteError;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("owner delete failed", error);
    return SERVER_ERROR("메모를 삭제하지 못했습니다.");
  }
}

export async function handleAdminDelete(request: Request, id: unknown) {
  if (!isSameOrigin(request)) return FORBIDDEN();
  if (!(await isAdminRequest())) return UNAUTHORIZED();
  if (!isUuid(id)) return BAD_REQUEST();

  try {
    const { error } = await getSupabaseAdmin().from("memos").delete().eq("id", id);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("admin delete failed", error);
    return SERVER_ERROR("메모를 강제 삭제하지 못했습니다.");
  }
}

export async function handleAdminDeleteAll(request: Request) {
  if (!isSameOrigin(request)) return FORBIDDEN();
  if (!(await isAdminRequest())) return UNAUTHORIZED();

  try {
    const { error } = await getSupabaseAdmin().from("memos").delete().not("id", "is", null);
    if (error) throw error;
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("admin delete-all failed", error);
    return SERVER_ERROR("전체 메모를 삭제하지 못했습니다.");
  }
}

export async function handleAdminList() {
  if (!(await isAdminRequest())) return UNAUTHORIZED();

  try {
    const { data, error } = await getSupabaseAdmin()
      .from("memos")
      .select("id,title,content,color,position,created_at,updated_at")
      .order("created_at", { ascending: false });
    if (error) throw error;
    return NextResponse.json({ memos: data ?? [] });
  } catch (error) {
    console.error("admin list failed", error);
    return SERVER_ERROR("메모 목록을 불러오지 못했습니다.");
  }
}
