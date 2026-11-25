import { handleAdminDeleteAll, handleAdminList } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function GET() {
  return handleAdminList();
}

export async function DELETE(request: Request) {
  return handleAdminDeleteAll(request);
}

export async function POST(request: Request) {
  return handleAdminDeleteAll(request);
}
