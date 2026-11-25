import { handleOwnerDelete } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  return handleOwnerDelete(request, (await params).id);
}
