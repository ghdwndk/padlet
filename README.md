# MINDLET

Next.js(App Router) + Supabase + Vercel 기반의 단일 메모 보드입니다. 주소를 아는 사람은 누구나 메모를 조회·작성할 수 있고, 작성자는 4자리 숫자 암호로, 관리자는 별도 로그인 후 메모를 삭제합니다.

## 로컬 실행

1. 프로젝트 폴더를 열고 `node -v`, `npm -v` 확인 (Node.js 22 이상 권장)
2. `npm ci`
3. `.env.example` 을 `.env.local` 로 복사하고 본인의 Supabase 값을 입력
4. **관리자 암호 해시 생성**

   ```bash
   node -e "require('bcryptjs').hash(process.argv[1], 12).then(console.log)" "원하는-관리자-비밀번호"
   ```

   주의: bcrypt 해시에는 `$` 가 들어 있어 `.env.local` 에서는 `\$` 로 이스케이프해야 합니다
   (예: `ADMIN_PASSWORD_HASH=\$2b\$12\$abc...`). Vercel 환경 변수 화면에는 그대로 입력합니다.

5. **세션 비밀값 생성** (`ADMIN_SESSION_SECRET`)

   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
   ```

6. Supabase SQL Editor 에서 DB 상태에 맞는 SQL 실행
   - 신규 빈 DB: `schema.sql`
   - 기존 데이터가 있는 DB: 먼저 백업 후 `migration.sql` 상단의 전제조건과 STEP 0 확인 쿼리를 확인하고 실행
7. `npm run dev` → http://localhost:3000

## 환경 변수 (Vercel에도 동일한 다섯 개 등록)

| 이름 | 용도 |
| --- | --- |
| `NEXT_PUBLIC_SUPABASE_URL` | Supabase 프로젝트 URL |
| `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` | 브라우저 공개 조회 |
| `SUPABASE_SECRET_KEY` | 서버 전용 (작성·삭제·요청 제한·세션) |
| `ADMIN_PASSWORD_HASH` | 관리자 암호 bcrypt 해시 |
| `ADMIN_SESSION_SECRET` | 관리자 세션 HMAC 비밀값 |

레거시 `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` 는 사용하지 않습니다.
비밀값에는 절대 `NEXT_PUBLIC_` 를 붙이지 마세요.

## Vercel 배포

1. GitHub 저장소를 Vercel 프로젝트로 연결
2. Project Settings → Environment Variables 에 위 다섯 변수를 Production/Preview 에 등록
3. 배포 후 보드 조회, 작성, 삭제, 관리자 로그인을 확인

## 보안 구조

- 브라우저는 Publishable key 로 공개 컬럼(`id,title,content,color,position,created_at,updated_at`)만 조회합니다.
- 작성·삭제·관리자 기능은 Node.js 런타임 서버 API 에서 Secret key(`server-only`)로 처리합니다.
- 작성자 암호는 서버에서 bcrypt 해시 후 `memo_credentials` 에 저장하며, 메모와 해시는 RPC 한 번으로 원자적으로 저장됩니다.
- 요청 제한은 Supabase `rate_limits` 테이블과 원자적 RPC 로 처리하며, bcrypt 실행 전에 확인합니다. 저장소 오류 시 작업을 진행하지 않습니다.
  - 작성 IP당 10분 20회, 삭제 요청 IP당 10분 30회, 메모+IP별 삭제 실패 10분 5회, 관리자 로그인 실패 IP당 15분 5회
  - IP 는 `x-forwarded-for` 에서 가져옵니다. Vercel 은 이 헤더를 덮어써 클라이언트 위조를 막습니다 ([문서](https://vercel.com/docs/headers/request-headers#x-forwarded-for)).
- 관리자 세션: 무작위 토큰 → HMAC(`ADMIN_SESSION_SECRET`) 검증값과 만료시간(8시간)만 `admin_sessions` 에 저장. 쿠키는 `HttpOnly`, 프로덕션 `Secure`, `SameSite=Strict`, `Path=/`.
- 모든 상태 변경 API 는 `Origin` 헤더가 요청 URL 의 host 와 일치해야 합니다(없으면 거부).
- RLS 는 모든 앱 테이블에서 활성화되어 있고, 일반 사용자는 `memos` SELECT 만 가능합니다.
