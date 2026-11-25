import { readJsonObject } from "@/lib/apiSecurity";
import { handleOwnerDelete } from "@/lib/memoHandlers";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await readJsonObject(request.clone());
  return handleOwnerDelete(request, body?.id);
}
