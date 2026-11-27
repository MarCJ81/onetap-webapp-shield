/* ============================================================
   OneTap i18n · KO/EN runtime translation (v1)
   - ?lang=en|ko  >  localStorage 'onetap_lang'  >  navigator.language
   - DOM text and attributes are translated in place and restored on switch.
   - Elements added later by app.js are translated by a MutationObserver.
   - Missing keys are reported to console as "I18N_MISS: <korean>".
   ============================================================ */
(function (root, doc) {
  'use strict';

  var LANG_KEY = 'onetap_lang';
  var COMMON = /*__COMMON__*/ {"닫기":"Close","취소":"Cancel","저장":"Save","저장됨":"Saved","삭제":"Delete","복사":"Copy","복사됨":"Copied","다운로드":"Download","내려받기":"Download","공유":"Share","인쇄":"Print","초기화":"Reset","다시 시도":"Try again","불러오기":"Load","내보내기":"Export","적용":"Apply","추가":"Add","편집":"Edit","수정":"Edit","보기":"View","미리보기":"Preview","설정":"Settings","도움말":"Help","사용법":"Guide","예시":"Example","샘플":"Sample","무료":"Free","유료":"Paid","개인정보":"Privacy","개인정보 처리방침":"Privacy policy","개인정보 처리 안내":"Privacy notice","이용약관":"Terms","홈":"Home","뒤로":"Back","다음":"Next","이전":"Previous","확인":"OK","검색":"Search","필터":"Filter","전체":"All","없음":"None","준비 중":"Coming soon","준비 중입니다":"Coming soon","로딩 중":"Loading","불러오는 중":"Loading","처리 중":"Working","빈칸":"Blank","필수":"Required","선택":"Optional","이름":"Name","제목":"Title","날짜":"Date","시간":"Time","메모":"Note","상태":"Status","결과":"Result","요약":"Summary","상세":"Details","언어":"Language","한국어":"Korean","영어":"English","복사하기":"Copy","링크 복사":"Copy link","전체 복사":"Copy all","다크 모드로 전환":"Switch to dark mode","라이트 모드로 전환":"Switch to light mode","테마 전환":"Toggle theme","라이트/다크":"Light / dark","다크/라이트":"Dark / light","새 탭에서 보기":"Open in new tab","새 창":"New window","본문으로 건너뛰기":"Skip to content","본문으로 바로가기":"Skip to content","맨 위로":"Back to top","더 보기":"Show more","접기":"Collapse","펼치기":"Expand","자주 묻는 질문":"Frequently asked questions","이 브라우저에만 저장됩니다":"Saved only in this browser","이 브라우저에만 저장됩니다 · 서버 전송 0":"Saved only in this browser · zero uploads","서버 전송 없음":"No upload","서버 업로드 없음":"No server upload","100% 브라우저 처리":"100% in-browser","브라우저에서 처리":"Processed in your browser","파일은 서버로 전송되지 않습니다":"Files never leave your device","파일이 서버로 전송되지 않습니다":"Files never leave your device","붙여넣은 코드는 서버로 전송되지 않습니다":"Pasted code never leaves your device"};
  var APP = /*__DICT__*/ {"원탭 웹앱 실드 — 바이브 코딩 웹앱 보안 검사·자동 방어":"OneTap WebApp Shield — security scan and automatic defence for vibe-coded apps","AI로 만든 웹앱의 시크릿 유출·Supabase RLS 누락·XSS·CORS·eval을 86개 규칙으로 3초에 검사하고, 호스팅별 보안 헤더·CSP·GitHub Actions·AI 코딩 규칙까지 원클릭으로 생성합니다. 의존성 CVE는 OSV.dev 실제 조회.":"Scans an AI-built web app for leaked secrets, missing Supabase RLS, XSS, CORS and eval with 86 rules in three seconds, then generates hosting-specific security headers, CSP, GitHub Actions and AI coding rules in one click. Dependency CVEs come from live OSV.dev lookups.","원탭 웹앱 실드":"OneTap WebApp Shield","원탭 웹앱 실드 — 웹앱 보안 검사·자동 방어":"OneTap WebApp Shield — web app security scan and automatic defence","시크릿 유출·RLS 누락·XSS·CORS를 3초에 잡고, 보안 헤더·CSP·CI·AI 규칙을 원클릭 생성. 의존성 CVE는 OSV.dev 실조회.":"Catch leaked secrets, missing RLS, XSS and CORS in three seconds, then generate security headers, CSP, CI and AI rules in one click. Dependency CVEs from live OSV.dev.","원탭 웹앱 실드 홈":"OneTap WebApp Shield home","주요 화면":"Main views","붙여넣은 코드는 서버로 전송되지 않습니다. GitHub·URL·CVE·AI 조회는 해당 서비스로 직접 요청합니다.":"Pasted code never leaves your browser. GitHub, URL, CVE and AI lookups go straight to those services.","테마 전환":"Toggle theme","다크/라이트":"Dark / light","검사 소스":"Source","파일 내용을 그대로 붙여넣으세요. 여러 파일은 '파일·폴더' 또는 GitHub 저장소로 넣으면 문맥까지 함께 봅니다.":"Paste the file contents as they are. For several files, use Files or a GitHub repository so the context is read too.","검사할 코드":"Code to scan","파일 선택 또는 끌어다 놓기":"Choose files or drop them here","심각도 필터":"Severity filter","호스팅 선택":"Choose your host","package.json 내용":"package.json contents","AI 제공자":"AI provider","닫기":"Close","본문으로 바로가기":"Skip to content","스캔":"Scan","방어팩":"Defence pack","의존성 CVE":"Dependency CVEs","AI 리뷰":"AI review","리포트":"Report","로컬 스캔":"Local scan","사용법":"Guide","개 규칙 · 시크릿 엔트로피 · OSV.dev":"rules · secret entropy · OSV.dev","배포 3분 전,":"Three minutes before you deploy,","구멍을 먼저 봅니다":"find the holes first","AI가 만들어 준 코드의 시크릿 유출, Supabase RLS 누락, XSS, CORS 전체 허용을 붙여넣는 즉시 찾아냅니다. 찾은 것마다":"Paste AI-written code and it immediately finds leaked secrets, missing Supabase RLS, XSS and wide-open CORS. For every finding it also builds","복붙용 수정 프롬프트":"a fix prompt you can paste","호스팅별 방어 설정":"hosting-specific defences","까지 만들어 줍니다.":".","붙여넣은 코드 전송 0":"Zero uploads","계정·결제 없음":"No account, no payment","결과는 이 브라우저에만":"Results stay in this browser","파일":"Files","줄":"lines","코드 붙여넣기":"Paste code","파일·폴더":"Files & folders","GitHub 저장소":"GitHub repo","배포 URL":"Deploy URL","취약 예시":"Vulnerable sample","데모 코드 3종":"three demo files","입력하면 자동 검사":"Scans as you type","소스 코드":"Source code","파일 경로":"File path","지우기":"Clear","안전 예시 넣기":"Load the safe sample","0자 · 이 브라우저에서만 분석":"characters · analysed in this browser only","파일 · 폴더 업로드":"Upload files or folders","최대 40개 · 텍스트 파일":"up to 40 text files","파일을 끌어다 놓거나 눌러서 선택":"Drop files here or press to choose","파일은 브라우저 안에서만 읽습니다. 업로드된 파일은 어디로도 전송되지 않습니다.":"Files are read only inside your browser and never sent anywhere.","GitHub 공개 저장소":"Public GitHub repository","API + raw 읽기":"API + raw reads","저장소 주소":"Repository address","비공개·한도 초과 시 토큰 (선택)":"Token for private repos or rate limits (optional)","Fine-grained 토큰 · repo read 권한만":"Fine-grained token · repo read only","토큰은 이 탭의 sessionStorage에만 두고, GitHub API 호출에만 씁니다. 공개 저장소는 토큰 없이도 됩니다(시간당 60회).":"The token stays in this tab's sessionStorage and is used only for GitHub API calls. Public repos need no token (60 calls an hour).","저장소 스캔":"Scan the repository","공개 저장소의 주요 파일 최대 45개를 읽어 로컬과 같은 규칙으로 검사합니다.":"Reads up to 45 key files from the public repository and scans them with the same rules as local.","배포 URL 실측":"Check the live deployment","헤더 · 노출 파일":"headers · exposed files","배포 주소":"Deployment address","실측 점검":"Run the check","브라우저가 읽지 못하는 헤더는":"Headers the browser cannot read are left as","으로 남기고, 터미널 1초 명령을 함께 드립니다. 가짜 초록 체크는 없습니다.":", with a one-second terminal command. No fake green ticks.","보안 점수":"Security score","검사 대기":"Not scanned","코드를 넣으면 즉시 채점합니다.":"Add code and it scores right away.","검사 범위":"Scope","정적 규칙 분석 · 런타임 침투 테스트 아님":"Static rule analysis · not a runtime penetration test","인식된 스택":"Detected stack","방어팩 기본값에 반영":"used as the defence pack defaults","발견 항목":"Findings","파일별 묶기":"Group by file","아직 검사한 코드가 없습니다":"No code scanned yet","위에 코드를 붙여넣거나":"Paste code above or load the","를 불러오세요.":"sample.","이 도구는":"This tool is","정적 분석":"static analysis","입니다. 실제 공격 검증(침투 테스트)이 아니며, 규칙에 없는 로직 취약점·권한 설계 문제는 잡지 못합니다. 중요한 서비스는 별도 보안 리뷰를 받으세요.":". It is not a live attack test, and it cannot catch logic flaws or authorisation design problems outside its rules. Get a separate security review for anything important.","진단에서 끝내지 않습니다":"Not just a diagnosis","찾은 구멍,":"Close the holes you found","설정으로 막습니다":"with configuration","호스팅에 맞는 보안 헤더 파일을 만들고, 쓰는 서비스만 골라 정확한 CSP를 조립합니다. 가드레일 키트(.gitignore · Gitleaks · CI · AI 규칙)는 ZIP으로 한 번에 받으세요.":"Builds the security header file for your host and assembles a precise CSP from just the services you use. The guardrail kit (.gitignore, Gitleaks, CI, AI rules) downloads as one ZIP.","보안 헤더 파일":"Security header file","복사":"Copy",".txt 저장":"Save .txt","CSP 빌더":"CSP builder","쓰는 서비스만 체크":"tick only what you use","style 'unsafe-inline' 허용":"allow style 'unsafe-inline'","(대부분 필요)":"(usually needed)","CSP는":"A CSP is a list of what you","막히는 것을 허용":"allow through","하는 목록입니다. 여기 없는 서비스를 추가하면 그 기능이 콘솔 에러와 함께 차단됩니다. 배포 후 콘솔의 CSP 경고를 보고 서비스를 추가하세요.":". Add a service that is missing here and that feature will be blocked with console errors. After deploying, watch the console's CSP warnings and add services then.","배포 후 1초 확인 (터미널)":"One-second check after deploy (terminal)","명령 복사":"Copy command","개발자 가드레일 키트":"Developer guardrail kit","7개 파일":"7 files","키트 전체 ZIP":"Download the whole kit (ZIP)","OSV.dev 공식 API · 키 불필요":"OSV.dev official API · no key needed","내 package.json,":"My package.json,","실제 CVE로":"against real CVEs","설치된 버전 그대로 OSV.dev에 질의합니다. GHSA/CVE, 심각도, 수정 버전까지. 네트워크가 없으면 내장 참고 DB로 점검하되":"It queries OSV.dev with the exact installed versions: GHSA/CVE, severity and fixed versions. Offline it falls back to a built-in reference DB but makes clear it is","실시간이 아님":"not live","을 숨기지 않습니다.":".","예시":"Sample","OSV.dev로 실제 조회":"Check against OSV.dev","아직 조회하지 않았습니다.":"Nothing looked up yet.","취약점":"Vulnerabilities","조회 결과가 여기에 나옵니다":"Results appear here","왼쪽에 package.json을 넣고 조회하세요.":"Add a package.json on the left and run the check.","규칙이 놓친 맥락까지":"The context rules miss","발견 항목을,":"Have the AI order your","AI가 고치는 순서로":"findings into a fix plan","스캔 요약과 문제 코드를 무료 AI에 보내 우선순위·패치 방향을 받습니다. 코드가 AI 서버로 전송되므로":"It sends the scan summary and the problem code to a free AI for priorities and a patch direction. The code leaves your browser, so it only","동의한 경우에만":"runs once you agree","실행합니다. 내 API 키를 연결하면 더 깊게 봅니다.":". Connect your own API key for a deeper review.","리뷰 요청":"Request a review","무료 체험 5회/일":"5 free runs a day","문제 코드 일부(최대 6,000자)도 함께 전송":"send part of the problem code too (up to 6,000 characters)","코드가 무료 AI 서버로 전송되는 것에 동의합니다":"I agree that the code is sent to the free AI server","(키·토큰은 [REDACTED] 처리)":"(keys and tokens become [REDACTED])","무료 AI로 심층 리뷰":"Deep review with the free AI","동의에 체크하면 버튼이 켜집니다. 무료 체험은 하루 5회, 응답은 최대 700토큰. 전송 전에 키·토큰은 [REDACTED]로 가립니다.":"Ticking the box enables the button. Five free runs a day, answers up to 700 tokens. Keys and tokens are redacted before sending.","내 AI 키 연결 (선택)":"Connect my AI key (optional)","키는 이 브라우저에만":"the key stays in this browser","API 키":"API key","모델":"Model","저장":"Save","삭제":"Delete","연결하지 않아도 무료 체험으로 리뷰할 수 있습니다.":"You can review with the free trial without connecting anything.","아직 리뷰가 없습니다":"No review yet","스캔 후 왼쪽에서 리뷰를 요청하세요.":"After scanning, request a review on the left.","클라이언트·팀에 그대로":"Straight to the client or team","점수와 근거를,":"The score and the evidence,","한 장으로":"on one page","100점 만점 점수·등급·항목별 근거를 Markdown/JSON으로 내보냅니다. 배지 SVG도 함께. 리포트에는 \"정적 분석\"이라는 범위와 미확인 항목이 항상 적힙니다.":"Exports the score out of 100, the grade and the evidence per item as Markdown or JSON, plus a badge SVG. The report always states that this is static analysis and lists what was not confirmed.","리포트 미리보기":"Report preview","Markdown 복사":"Copy Markdown","인쇄":"Print","아직 스캔 결과가 없습니다.":"No scan results yet.","신뢰 배지":"Trust badge","README에 붙이기":"paste it into your README","HTML 복사":"Copy HTML","SVG 저장":"Save SVG","배지는 정적 파일입니다. 저장소에 넣고 상대 경로로 불러오세요. 점수를 서버에서 자동 갱신하지는 않습니다.":"The badge is a static file. Add it to the repo and reference it by relative path; the score is not refreshed by a server.","정적 규칙 엔진은 Gitleaks·TruffleHog 패턴과 OWASP Cheat Sheet·Supabase 공식 가이드를 참고했습니다. 의존성 취약점은":"The static rule engine draws on Gitleaks and TruffleHog patterns, OWASP Cheat Sheets and the official Supabase guides. Dependency vulnerabilities come from","가 출처입니다.":".","개인정보 처리":"Privacy","3분 사용법":"How to use it in three minutes","— 코드를 붙여넣거나, 파일·GitHub 저장소·배포 URL을 넣습니다. 입력하는 즉시 86개 규칙으로 검사합니다.":"— Paste code, or add files, a GitHub repository or a deploy URL. It scans with 86 rules as you go.","고치기":"Fix","— 발견 항목마다":"— For each finding, press","수정 프롬프트 복사":"Copy fix prompt","를 눌러 Cursor·Claude·Lovable에 붙여넣으면 그 자리에서 고칩니다.":" and paste it into Cursor, Claude or Lovable to fix it there.","막기":"Block","— 방어팩에서 호스팅에 맞는 헤더 파일과 CSP를 만들고, 가드레일 키트 ZIP을 저장소 루트에 풉니다.":"— Build the header file and CSP for your host in the defence pack, then unpack the guardrail kit ZIP at the repo root.","확인":"Confirm","— 의존성 CVE는 OSV.dev 실제 조회, 배포 URL은 헤더·노출 파일 실측. 읽지 못한 항목은 \"미확인\"으로 남깁니다.":"— Dependency CVEs come from live OSV.dev, and the deploy URL is checked for headers and exposed files. Anything unreadable stays marked “unconfirmed”.","공유":"Share","— 리포트 탭에서 Markdown/JSON/배지 SVG를 내보냅니다.":"— Export Markdown, JSON or the badge SVG from the Report tab.","알아둘 것":"Worth knowing","붙여넣은 코드는 서버로 가지 않습니다. GitHub·URL·OSV·AI 조회만 해당 서비스에 직접 요청합니다.":"Pasted code never reaches a server. Only GitHub, URL, OSV and AI lookups go directly to those services.","정적 분석은":"Static analysis only catches","규칙에 있는 것":"what is in the rules","만 잡습니다. 로직·권한 설계 취약점은 사람이 봐야 합니다.":". Logic and authorisation design flaws need a human.","브라우저 CORS 때문에 다른 사이트의 보안 헤더는 읽지 못할 수 있습니다. 이때는 터미널 명령을 쓰세요.":"Browser CORS can stop it reading another site's security headers. Use the terminal command then.","발견한 실제 키는":"With a real key found,","먼저 폐기(revoke)":"revoke it first","하세요. 코드에서 지우는 것만으로는 이미 늦습니다.":" — deleting it from the code is already too late.","이 도구는 브라우저에서 실행됩니다. JavaScript를 켜 주세요.":"This tool runs in your browser. Please enable JavaScript.","치명적":"Critical","높음":"High","보통":"Medium","낮음":"Low","참고":"Info","시크릿·키 노출":"Secrets & keys","XSS·DOM 주입":"XSS & DOM injection","인증·권한":"Auth & permissions","DB·RLS":"DB & RLS","API·서버":"API & server","암호화":"Cryptography","설정·헤더":"Config & headers","Git·빌드 위생":"Git & build hygiene","의존성":"Dependencies","정적 웹":"Static web","모범 방어":"Exemplary","안전":"Safe","양호":"Good","경미한 구멍":"Minor holes","주의 필요":"Needs attention","취약":"Vulnerable","위험":"Critical risk","즉시 조치":"Act now","복사했습니다":"Copied","붙여넣은 코드 ·":"Pasted code ·","업로드한 파일":"Uploaded files","저장소":"Repository","접속 실패":"Could not connect","헤더 미확인":"headers unconfirmed","이 오리진의 응답 헤더를 브라우저가 읽지 못했습니다. 아래 내용은 확인된 항목만 반영합니다.":"The browser could not read this origin's response headers, so only confirmed items are reflected below.","규칙에 걸린 항목이 없습니다. 스캔 범위 밖 취약점은 별도 점검이 필요합니다.":"Nothing matched the rules. Vulnerabilities outside the scan scope need a separate check.","— 배포 전 수정이 필요합니다.":" — fix these before deploying.","— 경미한 항목부터 정리하세요.":" — work through the minor items.","카테고리별 발견 없음":"No findings by category","ms · 정적 분석(런타임 아님)":"ms · static analysis (not runtime)","· 제외":"· excluded","· URL 모드(확인된 헤더·노출 파일만 반영)":"· URL mode (only confirmed headers and exposed files)","전체":"All","왜 위험한가":"Why it matters","고치는 법":"How to fix it","규칙":"Rule","값":"Value","근거 문서":"Reference","이 심각도에 해당하는 항목이 없습니다":"Nothing at this severity","스캔 범위 밖 취약점은 별도 점검이 필요합니다.":"Vulnerabilities outside the scan scope need a separate check.","전체 보기로 다른 항목을 확인하세요.":"Switch to All to see the other items.","(파일 없음)":"(no file)","파일을 넣으면 자동 검사":"Scans as soon as files are added","GitHub API 조회":"GitHub API lookup","같은 오리진만 헤더 확인":"headers checked for this origin only","제거":"Remove","개 파일 · 브라우저 안에서만 읽었습니다.":"files · read inside the browser only.","파일은 최대 40개까지":"Up to 40 files","— 900KB 초과로 건너뜀":"— skipped, over 900KB","불러옴":"loaded","저장소 주소를 입력하세요.":"Enter the repository address.","GitHub에서 파일 목록을 가져오는 중…":"Fetching the file list from GitHub…","파일 읽는 중":"Reading files","저장소를 읽지 못했습니다.":"Could not read the repository.","브랜치":"branch","(후보":"(of","개 중 우선":"candidates, took the first","· 실패":"· failed","— 결과는 스캔 탭에 반영됐습니다.":" — the results are on the Scan tab.","GitHub 조회 중 오류:":"Error during the GitHub lookup:","배포 주소를 입력하세요.":"Enter the deployment address.","헤더와 노출 파일을 확인하는 중…":"Checking headers and exposed files…","헤더를 실제로 읽었습니다 (점수":"Headers read for real (score","헤더는 CORS로 읽지 못해 미확인입니다. 터미널 명령을 쓰세요.":"CORS blocked the header read, so they are unconfirmed. Use the terminal command.","응답을 읽지 못했습니다.":"Could not read the response.","실측 중 오류:":"Error during the check:","헤더 확인됨":"Headers confirmed","헤더 제한적(CORS)":"Headers limited (CORS)","헤더 미확인(CORS)":"Headers unconfirmed (CORS)","· 헤더 점수":"· header score","있음":"present","없음":"absent","미확인":"unconfirmed","노출":"exposed","차단":"blocked","확인 불가":"cannot confirm","개 파일":"files","가드레일 키트 ZIP을 내려받았습니다":"Guardrail kit ZIP downloaded","package.json을 먼저 넣어주세요.":"Add a package.json first.","의존성을 찾지 못했습니다(dependencies/devDependencies).":"No dependencies found (dependencies/devDependencies).","OSV.dev 조회 중…":"Querying OSV.dev…","개 패키지":"packages","OSV.dev 실시간 응답":"Live OSV.dev response","내장 참고 DB(오프라인)":"Built-in reference DB (offline)","결과 없음":"No results","· 취약점":"· vulnerabilities","조회 실패:":"Lookup failed:","내장 참고 DB (실시간 아님)":"Built-in reference DB (not live)","네트워크가 없어 내장 참고 DB로 점검했습니다.":"No network, so the built-in reference DB was used.","OSV.dev 기준 알려진 취약점이 없습니다.":"No known vulnerabilities according to OSV.dev.","OSV.dev 실시간 조회 결과입니다.":"These are live OSV.dev results.","알려진 취약점이 없습니다":"No known vulnerabilities","내장 DB 기준입니다. 네트워크가 되면 실제 조회로 다시 확인하세요.":"This is from the built-in DB. Re-check with a live lookup once you are online.","OSV.dev 기준 ·":"Per OSV.dev ·","미상":"unknown","수정 버전":"fixed in","수정 버전 미확인":"fixed version unknown","상세":"Details","외":"more","건은 JSON/리포트에서 확인하세요.":"items are in the JSON or the report.","먼저 스캔하세요. 발견 항목과 스택을 요약해 AI에 보냅니다.":"Scan first — the findings and stack are summarised for the AI.","발견":"Findings","치명적·높음":"critical and high","스택":"Stack","리뷰 생성 중…":"Writing the review…","내 AI로 심층 리뷰":"Deep review with my AI","코드 전송 동의가 필요합니다":"Consent to send the code is required","먼저 스캔하세요":"Scan first","리뷰를 생성하는 중입니다… (최대 30초)":"Writing the review… (up to 30 seconds)","무료 AI 호출 중 오류:":"Error calling the free AI:","· 남은":"· left","AI 응답을 받지 못했습니다.":"No response from the AI.","무료 체험은 배포 도메인(허용된 출처)에서만 열립니다. 지금 주소에서는 내 AI 키를 연결해 사용하세요.":"The free trial only opens on the deployed domain (an allowed origin). Here, connect your own AI key instead.","무료 체험 한도입니다. 내 Gemini 키를 연결하면 계속할 수 있습니다.":"That is the free trial limit. Connect your own Gemini key to continue.","무료 Gemini 키 발급":"Get a free Gemini key","Gemini 오류:":"Gemini error:","OpenAI 오류:":"OpenAI error:","Claude 오류:":"Claude error:","AI 연결 실패:":"AI connection failed:","(브라우저 CORS·키 권한을 확인하세요)":"(check browser CORS and the key's permissions)","연결됨 ·":"Connected ·","· 키는 이 브라우저(localStorage)에만 있습니다.":"· the key stays in this browser (localStorage).","API 키를 입력하세요":"Enter an API key","이 브라우저에만 저장했습니다":"Saved in this browser only","연결을 해제했습니다":"Disconnected","업로드 파일":"Uploaded files","서버 보안 헤더: 브라우저 CORS로 미확인 (터미널 curl로 확인 필요)":"Server security headers: unconfirmed (browser CORS) — check with curl in a terminal","서버 보안 헤더 점수:":"Server header score:","공개된 파일:":"Exposed files:","GitHub 저장소:":"GitHub repository:","· 읽은 파일":"· files read","OSV.dev 취약점":"OSV.dev vulnerabilities","건 (":"items (","내장 DB":"built-in DB","실시간":"live","아직 스캔 결과가 없습니다. 스캔 탭에서 코드를 검사하세요.":"No scan results yet. Scan some code on the Scan tab.","점수":"Score","등급":"Grade","대상":"Target","리포트를 내려받았습니다":"Report downloaded","헤더 파일을 복사했습니다":"Header file copied","헤더 파일을 저장했습니다":"Header file saved","CSP를 복사했습니다":"CSP copied","터미널 명령을 복사했습니다":"Terminal command copied","리포트 Markdown을 복사했습니다":"Report Markdown copied","배지 HTML을 복사했습니다 (SVG 저장 후 같은 폴더에 두세요)":"Badge HTML copied (save the SVG and keep it in the same folder)","배지 SVG를 저장했습니다":"Badge SVG saved","복사할 리뷰가 없습니다":"No review to copy","AI 리뷰를 복사했습니다":"AI review copied","수정 프롬프트를 복사했습니다 — AI 코딩 도구에 붙여넣으세요":"Fix prompt copied — paste it into your AI coding tool","저장했습니다":"saved","자 ·":"characters ·","줄 · 이 브라우저에서만 분석":"lines · analysed in this browser only","# 웹앱 보안 리포트":"# Web app security report","**보안 점수":"**Security score","/ 100 · 등급":"/ 100 · grade","- 스캔 일시:":"- Scanned at:","- 스캔 대상:":"- Scanned:","붙여넣은 코드":"Pasted code","- 취약점:":"- Vulnerabilities:","- 추정 스택:":"- Likely stack:","- 도구: OneTap WebApp Shield v":"- Tool: OneTap WebApp Shield v","(정적 규칙 엔진)":"(static rule engine)","> 이 리포트는 소스·설정 파일에 대한 정적 분석 결과입니다. 런타임 침투 테스트나 실제 공격 검증이 아니며, 규칙에 없는 취약점은 잡지 못할 수 있습니다.":"> This report is the result of static analysis of source and configuration files. It is not a runtime penetration test or a live attack, and may miss vulnerabilities outside its rules.","## 심각도 요약":"## Severity summary","| 심각도 | 건수 |":"| Severity | Count |","## 발견 항목":"## Findings","규칙에 걸린 항목이 없습니다. (스캔 범위 밖의 취약점은 별도 점검이 필요합니다.)":"Nothing matched the rules. (Vulnerabilities outside the scan scope need a separate check.)","- 위치:":"- Location:","- 코드:":"- Code:","- 수정:":"- Fix:","## 추가 점검":"## Further checks","## 미확인 · 한계":"## Unconfirmed and limits","브라우저에서 다른 도메인의 응답 헤더를 읽지 못한 경우(CORS), 서버 헤더는 \"미확인\"으로 남습니다.":"Where the browser cannot read another domain's response headers (CORS), the server headers stay “unconfirmed”.","의존성 CVE는 OSV.dev 조회 결과이며, 실제 설치된 버전과 다를 수 있습니다.":"Dependency CVEs come from OSV.dev and may differ from what is actually installed.","로직·비즈니스 규칙 취약점(예: 남의 주문 조회)은 정적 규칙으로 잡지 못합니다.":"Logic and business-rule flaws (for example reading someone else's order) are not caught by static rules.","와":" and ","API 키 + Supabase RLS 누락":"API key + missing Supabase RLS","서비스 키가 .env와 코드에 박힌 채, RLS를 켜지 않은 테이블을 배포한 전형적인 바이브 코딩 앱.":"A textbook vibe-coded app: service keys baked into .env and the code, a table shipped without RLS.","키 노출 · RLS":"Key exposure · RLS","XSS + CORS + eval 백엔드":"XSS + CORS + eval backend","innerHTML·dangerouslySetInnerHTML, 모든 origin 허용, eval API, 열린 Firestore 규칙이 한 번에.":"innerHTML and dangerouslySetInnerHTML, every origin allowed, an eval API and open Firestore rules at once.","안전한 대조군":"Safe control","RLS·파라미터 바인딩·HttpOnly 쿠키·허용 origin·보안 헤더·.gitignore까지 갖춘 기준선.":"A baseline with RLS, parameter binding, HttpOnly cookies, an allowlist of origins, security headers and a .gitignore.","안전 예시":"Safe sample","정적 배포에 가장 간단. public 폴더에 넣으면 빌드 후 루트로 복사됩니다.":"Simplest for a static deploy: put it in public/ and it is copied to the root after the build.","Nginx · 직접 서버":"Nginx · own server","웹폰트":"Web fonts","jsDelivr 폰트":"jsDelivr fonts","분석":"Analytics","광고 추적":"Ad tracking","AI 프록시":"AI proxy","Google 로그인":"Google sign-in","결제":"Payments","토스페이먼츠":"Toss Payments","포트원(아임포트)":"PortOne (I'mport)","에러 수집":"Error tracking","YouTube 임베드":"YouTube embeds","영상":"Video","지도":"Maps","카카오맵":"Kakao Maps","네이버 지도":"Naver Maps","이미지":"Images","Tawk.to 상담":"Tawk.to chat","채팅":"Chat","시크릿·키·DB·소스맵 차단":"Block secrets, keys, DB files and source maps","Gitleaks 기본 규칙 + 오탐 allowlist":"Gitleaks default rules plus a false-positive allowlist","pre-commit 훅":"pre-commit hook","커밋 전 시크릿 차단":"Block secrets before they are committed","Gitleaks · OSV · Semgrep 자동 실행":"Gitleaks, OSV and Semgrep run automatically","AI 코딩 에이전트용 규칙":"Rules for AI coding agents","규칙 파일 연결":"Wire the rule files in","서버 또는 직접 서버":"Server or own server","파일 내용을 그대로 붙여넣으세요. 여러 파일은 '파일·폴더' 또는 GitHub 저장소로 넣으면 문맥까지 함께 봅니다. 예) const supabase = createClient(url, 'sb_secret_...') el.innerHTML = req.query.q app.use(cors())":"Paste the file contents as they are. For several files, use Files or a GitHub repository so the context is read too.\n\nExample)\nconst supabase = createClient(url, 'sb_secret_...')\nel.innerHTML = req.query.q\napp.use(cors())"};
  var PATTERNS = /*__PATTERNS__*/ [[new RegExp("^파일 내용을 그대로 붙여넣으세요\\.[\\s\\S]*$", ""), "Paste the file contents as they are. For several files, use Files or a GitHub repository so the context is read too.\n\nExample)\nconst supabase = createClient(url, 'sb_secret_...')\nel.innerHTML = req.query.q\napp.use(cors())"],[new RegExp("^(\\d+)자 · (\\d+)줄 · 이 브라우저에서만 분석$", ""), "$1 characters · $2 lines · analysed in this browser only"],[new RegExp("^(\\d+)자 · 이 브라우저에서만 분석$", ""), "$1 characters · analysed in this browser only"]];

  var DICT = {};
  var k;
  for (k in COMMON) if (Object.prototype.hasOwnProperty.call(COMMON, k)) DICT[k] = COMMON[k];
  for (k in APP) if (Object.prototype.hasOwnProperty.call(APP, k)) DICT[k] = APP[k];

  var HANGUL = /[\u1100-\u11FF\u3130-\u318F\uAC00-\uD7A3]/;
  var SKIP_TAG = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEXTAREA: 1, CODE: 1, SVG: 1 };
  var ATTRS = ['placeholder', 'aria-label', 'title', 'alt'];
  var state = { lang: 'ko' };
  var records = [];
  var missing = {};
  var missingList = [];
  var observer = null;

  /* ---------- language ---------- */
  function detect() {
    try {
      var q = new URLSearchParams(root.location.search).get('lang');
      if (q === 'ko' || q === 'en') return q;
    } catch (e) { /* very old browser */ }
    try {
      var saved = root.localStorage.getItem(LANG_KEY);
      if (saved === 'ko' || saved === 'en') return saved;
    } catch (e) { /* private mode */ }
    var nav = root.navigator.language || root.navigator.userLanguage || 'ko';
    return /^ko/i.test(nav) ? 'ko' : 'en';
  }

  /* ---------- lookup ---------- */
  function report(text) {
    if (missing[text]) return;
    missing[text] = 1;
    missingList.push(text);
    if (root.console && console.warn) console.warn('I18N_MISS: ' + text);
  }

  /* Pattern with capture translation: captures that still hold Korean are looked up too. */
  function applyPattern(core, p) {
    if (!p[0].test(core)) return null;
    var m = p[0].exec(core);
    var caps = [], i, ok = true;
    for (i = 1; i < m.length; i++) {
      var c = m[i];
      if (c == null) { caps[i] = ''; continue; }
      if (HANGUL.test(c)) {
        var t = lookupSmall(c.trim());
        if (t == null) { ok = false; caps[i] = c; } else { caps[i] = t; }
      } else { caps[i] = c; }
    }
    var out = p[1].replace(/\$(\d+)/g, function (all, n) { return caps[+n] != null ? caps[+n] : all; });
    if (!ok || HANGUL.test(out)) return null;
    return out;
  }

  function tr(raw) {
    if (typeof raw !== 'string' || !HANGUL.test(raw)) return raw;
    var m = /^(\s*)([\s\S]*?)(\s*)$/.exec(raw);
    var lead = m[1], core = m[2], tail = m[3];
    if (!core) return raw;
    var hit = DICT[core];
    if (hit == null && /\s{2,}|\n/.test(core)) hit = DICT[core.replace(/\s+/g, ' ').trim()];
    if (hit != null) return lead + hit + tail;

    /* Korean date: 2026년 11월 27일 -> November 27, 2026 */
    var dt = /^(\d{4})\s*년\s*(\d{1,2})\s*월\s*(\d{1,2})\s*일$/.exec(core);
    if (dt) {
      var MO = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
      var mm = parseInt(dt[2], 10);
      if (mm >= 1 && mm <= 12) return lead + MO[mm - 1] + ' ' + parseInt(dt[3], 10) + ', ' + dt[1] + tail;
    }

    /* money in Korean format: 81만 원 / 2,980,750원  ->  {0} template */
    var money = takeMoney(core);
    if (money.map.length) {
      var tpl = money.text;
      var th = DICT[tpl];
      if (th == null && /\s{2,}|\n/.test(tpl)) th = DICT[tpl.replace(/\s+/g, ' ').trim()];
      if (th == null && /^\{0\}$/.test(tpl.trim())) th = '{0}';
      if (th != null) return lead + putMoney(th, money.map) + tail;
      for (var mi = 0; mi < PATTERNS.length; mi++) {
        var mo = applyPattern(tpl, PATTERNS[mi]);
        if (mo != null) return lead + putMoney(mo, money.map) + tail;
      }
    }
    for (var i = 0; i < PATTERNS.length; i++) {
      var pout = applyPattern(core, PATTERNS[i]);
      if (pout != null) return lead + pout + tail;
    }
    var seg = trSegments(core);
    if (seg != null) return lead + seg + tail;
    report(core);
    return raw;
  }


  /* Korean money -> token template; values are formatted as ₩1,234,567 */
  function won(n) { return '₩' + n.toLocaleString('en-US'); }
  function takeMoney(core) {
    var map = [];
    var out = core.replace(/([\d,]+)\s*만(?:\s*([\d,]+))?\s*원/g, function (all, a, b) {
      var n = parseInt(a.replace(/,/g, ''), 10) * 10000 + (b ? parseInt(b.replace(/,/g, ''), 10) : 0);
      map.push(won(n));
      return '{' + (map.length - 1) + '}';
    });
    out = out.replace(/([+\-]?[\d,]+)\s*원/g, function (all, a) {
      map.push('₩' + a);
      return '{' + (map.length - 1) + '}';
    });
    return { text: out, map: map };
  }
  function putMoney(s, map) {
    return s.replace(/\{(\d+)\}/g, function (all, i) { return map[+i] != null ? map[+i] : all; });
  }

  /* A small unit: dictionary hit or pattern hit, no whitespace trimming. */
  function lookupSmall(unit) {
    var hit = DICT[unit];
    if (hit != null) return hit;
    for (var i = 0; i < PATTERNS.length; i++) {
      var pout = applyPattern(unit, PATTERNS[i]);
      if (pout != null) return pout;
    }
    return null;
  }

  function trPipe(line) {
    var parts = line.split(/\s*\|\s*/);
    var out = [];
    for (var i = 0; i < parts.length; i++) {
      var t = lookupSmall(parts[i].trim());
      if (t == null) return null;
      out.push(t);
    }
    return out.join(' | ');
  }

  function trSegments(core) {
    if (core.indexOf('\n') > -1) {
      var lines = core.split('\n');
      var out = [];
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (!line.trim()) { out.push(line); continue; }
        var t = line.indexOf('|') > -1 ? trPipe(line) : lookupSmall(line.trim());
        if (t == null) { if (root.__I18N_DEBUG) (root.__I18N_SEGFAIL = root.__I18N_SEGFAIL || []).push(line); return null; }
        out.push(t);
      }
      return out.join('\n');
    }
    if (core.indexOf('|') > -1) return trPipe(core);
    return null;
  }

  /* ---------- DOM walking ---------- */
  function skipped(el) {
    while (el) {
      if (el.nodeType === 1) {
        if (SKIP_TAG[el.tagName]) return true;
        if (el.getAttribute && (el.hasAttribute('data-i18n-skip') || el.getAttribute('contenteditable') === 'true')) return true;
        if (el.classList && el.classList.contains('onetap-lang')) return true;
      }
      el = el.parentNode;
    }
    return false;
  }

  function trText(node) {
    var v = node.nodeValue;
    if (!v || !HANGUL.test(v)) return;
    var out = tr(v);
    if (out !== v) {
      records.push({ n: node, v: v });
      node.nodeValue = out;
    }
  }

  function trAttrs(el) {
    var i, at, v, out;
    for (i = 0; i < ATTRS.length; i++) {
      at = ATTRS[i];
      if (!el.hasAttribute(at)) continue;
      v = el.getAttribute(at);
      if (!v || !HANGUL.test(v)) continue;
      out = tr(v);
      if (out !== v) {
        records.push({ e: el, a: at, v: v });
        el.setAttribute(at, out);
      }
    }
    if (el.tagName === 'INPUT' && el.hasAttribute('value') && el.type !== 'checkbox' && el.type !== 'radio' && el.type !== 'hidden') {
      v = el.getAttribute('value');
      if (v && HANGUL.test(v)) {
        out = tr(v);
        if (out !== v) {
          records.push({ e: el, a: 'value', v: v });
          el.setAttribute('value', out);
          if (el.value === v) el.value = out;
        }
      }
    }
    if (el.tagName === 'INPUT') {
      var ty = (el.type || '').toLowerCase();
      if (ty === 'button' || ty === 'submit' || ty === 'reset') {
        v = el.value;
        if (v && HANGUL.test(v)) {
          out = tr(v);
          if (out !== v) { records.push({ e: el, a: 'value', v: v }); el.value = out; }
        }
      }
    }
  }

  function walk(node) {
    if (node.nodeType === 3) { trText(node); return; }
    if (node.nodeType !== 1) return;
    if (node.tagName !== 'SCRIPT' && node.tagName !== 'STYLE' && node.tagName !== 'SVG' &&
        !(node.classList && node.classList.contains('onetap-lang'))) trAttrs(node);
    if (skipped(node)) return;
    if (node.tagName === 'META') return;
    for (var c = node.firstChild; c; c = c.nextSibling) walk(c);
  }

  function trMeta() {
    var list = doc.querySelectorAll('meta[name="description"], meta[property="og:title"], meta[property="og:description"], meta[name="twitter:title"], meta[name="twitter:description"]');
    for (var i = 0; i < list.length; i++) {
      var el = list[i], v = el.getAttribute('content');
      if (v && HANGUL.test(v)) {
        var out = tr(v);
        if (out !== v) { records.push({ e: el, a: 'content', v: v }); el.setAttribute('content', out); }
      }
    }
  }

  function trJsonLd() {
    var list = doc.querySelectorAll('script[type="application/ld+json"]');
    for (var i = 0; i < list.length; i++) {
      var el = list[i];
      try {
        var data = JSON.parse(el.textContent);
        var changed = fixJson(data);
        if (changed) el.textContent = JSON.stringify(data);
      } catch (e) { /* leave as is */ }
    }
  }

  function fixJson(o) {
    var changed = false, i;
    if (Array.isArray(o)) {
      for (i = 0; i < o.length; i++) if (fixJson(o[i])) changed = true;
      return changed;
    }
    if (!o || typeof o !== 'object') return false;
    for (var key in o) {
      if (!Object.prototype.hasOwnProperty.call(o, key)) continue;
      var v = o[key];
      if (typeof v === 'string' && HANGUL.test(v)) {
        var out = DICT[v.trim()];
        if (out != null) { o[key] = out; changed = true; }
      } else if (v && typeof v === 'object') {
        if (fixJson(v)) changed = true;
      }
    }
    return changed;
  }

  /* ---------- apply / restore ---------- */
  function trFieldValues() {
    var list = doc.querySelectorAll('input, textarea');
    for (var i = 0; i < list.length; i++) {
      var el = list[i];
      var ty = (el.type || 'text').toLowerCase();
      if (ty === 'checkbox' || ty === 'radio' || ty === 'hidden' || ty === 'file' || ty === 'date' || ty === 'number') continue;
      if (el === doc.activeElement) continue;
      var v = el.value;
      if (!v || !HANGUL.test(v)) continue;
      var out = tr(v);
      if (out !== v) { records.push({ e: el, a: 'prop:value', v: v }); el.value = out; }
    }
  }

  function applyEn() {
    var title = root.__onetapTitle || (root.__onetapTitle = doc.title);
    walk(doc.body);
    trFieldValues();
    trMeta();
    trJsonLd();
    doc.documentElement.lang = 'en';
    var t = DICT[title] || DICT[title.trim()];
    doc.title = t || title;
  }

  function restoreKo() {
    for (var i = records.length - 1; i >= 0; i--) {
      var r = records[i];
      if (r.n) { if (r.n.nodeValue !== r.v) r.n.nodeValue = r.v; }
      else if (r.e) {
        if (r.a === 'value' || r.a === 'prop:value') { if (r.e.value !== r.v) r.e.value = r.v; }
        else if (r.e.getAttribute(r.a) !== r.v) r.e.setAttribute(r.a, r.v);
      }
    }
    var title = root.__onetapTitle;
    if (title) doc.title = title;
    doc.documentElement.lang = 'ko';
  }

  /* ---------- language switch UI ---------- */
  function buildSwitch() {
    var wrap = doc.createElement('div');
    wrap.className = 'onetap-lang';
    wrap.setAttribute('role', 'group');
    wrap.innerHTML = '<button type="button" data-onetap-lang="ko" aria-pressed="true">KO</button>' +
      '<button type="button" data-onetap-lang="en" aria-pressed="false">EN</button>';
    var box = doc.querySelector('.top-actions') || doc.querySelector('.topbar__inner') ||
      doc.querySelector('.topbar-inner') || doc.querySelector('.topbar-in') ||
      doc.querySelector('.topbar') || doc.querySelector('header');
    if (box) {
      if (box.classList.contains('top-actions')) box.insertBefore(wrap, box.firstChild);
      else {
        var act = box.querySelector('.top-actions');
        if (act) box.insertBefore(wrap, act); else box.appendChild(wrap);
      }
    } else {
      wrap.style.cssText = 'position:fixed;top:10px;right:10px;z-index:99999;background:rgba(255,255,255,.9);color:#111';
      doc.body.appendChild(wrap);
    }
    wrap.addEventListener('click', function (ev) {
      var b = ev.target.closest('[data-onetap-lang]');
      if (!b) return;
      setLang(b.getAttribute('data-onetap-lang'));
    });
    return wrap;
  }

  var CSS = '.onetap-lang{display:inline-flex;flex:none;align-items:center;padding:2px;border:1px solid currentColor;border-radius:999px;opacity:.72;transition:opacity .15s;vertical-align:middle;align-self:center}' +
    '.onetap-lang:hover,.onetap-lang:focus-within{opacity:1}' +
    '.onetap-lang button{appearance:none;-webkit-appearance:none;border:0;background:transparent;color:inherit;font:inherit;font-size:10.5px;font-weight:700;letter-spacing:.04em;line-height:1;padding:5px 6px;border-radius:999px;cursor:pointer;min-width:26px;text-align:center}' +
    '.onetap-lang button[aria-pressed="true"]{background:rgba(128,128,128,.3)}' +
    '@media (max-width:520px){.onetap-lang button{padding:4px 4px;font-size:10px;min-width:22px}.onetap-lang{margin-left:2px}}';

  function injectCss() {
    var s = doc.createElement('style');
    s.id = 'onetap-lang-css';
    s.textContent = CSS;
    (doc.head || doc.documentElement).appendChild(s);
  }

  function paintSwitch() {
    var bs = doc.querySelectorAll('[data-onetap-lang]');
    for (var i = 0; i < bs.length; i++) {
      bs[i].setAttribute('aria-pressed', bs[i].getAttribute('data-onetap-lang') === state.lang ? 'true' : 'false');
    }
    var wrap = doc.querySelector('.onetap-lang');
    if (wrap) wrap.setAttribute('aria-label', state.lang === 'ko' ? '언어' : 'Language');
  }

  /* ---------- observe ---------- */
  function startObserver() {
    if (observer || !root.MutationObserver) return;
    observer = new MutationObserver(function (muts) {
      if (state.lang !== 'en') return;
      for (var i = 0; i < muts.length; i++) {
        var m = muts[i];
        if (m.type === 'characterData') { trText(m.target); continue; }
        if (m.type === 'attributes') { if (m.target.nodeType === 1 && !skipped(m.target)) trAttrs(m.target); continue; }
        for (var j = 0; j < m.addedNodes.length; j++) walk(m.addedNodes[j]);
      }
    });
    observer.observe(doc.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['placeholder', 'aria-label', 'title', 'alt'] });
  }

  function setLang(lang) {
    state.lang = lang === 'en' ? 'en' : 'ko';
    try { root.localStorage.setItem(LANG_KEY, state.lang); } catch (e) { /* private mode */ }
    if (state.lang === 'en') {
      applyEn();
      startObserver();
    } else {
      if (observer) { observer.disconnect(); observer = null; }
      restoreKo();
    }
    paintSwitch();
    try { doc.dispatchEvent(new CustomEvent('onetap:lang', { detail: { lang: state.lang } })); } catch (e) { /* old */ }
  }

  function boot() {
    injectCss();
    buildSwitch();
    state.lang = detect();
    if (state.lang === 'en') {
      applyEn();
      startObserver();
    } else {
      doc.documentElement.lang = 'ko';
    }
    paintSwitch();
    root.ONETAP_I18N = {
      lang: function () { return state.lang; },
      setLang: setLang,
      t: tr,
      missing: function () { return missingList.slice(); },
      dict: DICT
    };
  }

  if (doc.readyState === 'loading') doc.addEventListener('DOMContentLoaded', boot);
  else boot();
})(window, document);
