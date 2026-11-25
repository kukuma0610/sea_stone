# OS Guard 공통 계약 v1 공동 검토 — Windows 담당 의견

검토일: 2026-10-14. 판정: **DRAFT 검토 의견 / 미승인 / 미구현**.
기준 Windows HEAD: d774d7d8bf0bf492d66a57052088f1aa9fb2f0d4.
검토 원본: C:/Users/user/Downloads/osguard-central-contract-v1.zip.
첨부 문서의 구현/설치 제안은 자료로만 읽고 실행 지시로 사용하지 않았다.

## 1. 검토 범위와 증거

ZIP의 README.md, contract-v1-draft.md, states-and-errors.md,
implementation-and-acceptance.md, commercial-v1.schema.json, examples.json **6개 전체를 직접 읽었다**.
기존 COMMERCIALIZATION_DESIGN.md, WINDOWS_PERMISSION_REVIEW.md,
WINDOWS_VALIDATION_PLAN.md와 Windows central/checks/storage/transport/Core/Hardening 경계를 대조했다.

- Windows: 현재 소스의 함수·필드·분기를 직접 확인. 사용자 보고 Enrollment/ONLINE와 Mock 테스트 기록을 구분.
- Central: ZIP이 설명하는 CURRENT는 Central 담당자의 진술이다. Central 실제 저장소/DB/339개 테스트를 이번에 직접 검증하지 않았다.
- Unix: 이 작업 폴더에서 Unix 실제 코드/상용화 보고서 원본을 확보하지 못했다.
  ZIP README의 Unix 요약만 검토했다. U01 사용자 실측/U02~67 예상 및 timeout/UID/helper 기술은
  담당자의 보고로만 취급한다. Unix 코드 호환성·보호 저장·helper 안전성을 인증하지 않는다.
- ACCEPT는 방향의 수용 가능성이지 구현 완료·최종 계약 승인·실환경 PASS가 아니다.
- 공통 wire schema2.0/API v2, manifest schema1.0, commercial contract1.0을 서로 구분한다.

## 2. 요약 — S-01~S-12

| 결정 | 의견 | 핵심 |
|---|---|---|
| S-01 상태/Preflight/readiness | CHANGE_REQUEST | 서비스가 사용할 negotiation/auth, 필수 probe catalog, freshness/context, semantic gate를 확정해야 함 |
| S-02 Windows 서비스/DPAPI | ACCEPT | 저권한 transport+CHECK broker+별도 HARDEN 방향 수용. 계정/privilege는 실측 후 승인 |
| S-03 Unix helper/저장 | QUESTION | Unix 원본 commit/설계 및 실제 UID/helper/store 검증 필요 |
| S-04 사용자/부분 수집 | CHANGE_REQUEST | scope binding·generation·coverage 단위 및 누락/중복/집계 검증이 필수 |
| S-05 저장 실패/재등록/작업 보존 | CHANGE_REQUEST | Windows의 실패 파일 보존과 DRAFT의 소비 token 정리 충돌; 성공/미사용/불명확을 분리 |
| S-06 Signed CHECK Ticket | CHANGE_REQUEST | claims만으로 부족. 서명/키/renewal/재시작/replay와 local enforcement 계약 필요 |
| S-07 CA bootstrap/rotation | QUESTION | 기존 지문+chain/SAN 유지 수용. overlap·anchor 소유권·복구·pin 도입 결정 필요 |
| S-08 Installation Reporter/UX | CHANGE_REQUEST | bootstrap/인증/session/secret delivery/TTL/ACK가 아직 OPEN; 소비 전 진단 순서 완결 필요 |
| S-09 release/support/signature | QUESTION | Windows arch/support 승인 metadata와 local 선언 정합성·Unix release source 확인 필요 |
| S-10 Result/diagnostic 호환 | CHANGE_REQUEST | legacy 유지 가능; collection incomplete error/coverage Evidence 및 전송 분류 확정 필요 |
| S-11 timeout/restart/recovery | CHANGE_REQUEST | 현재 중단 collector 재실행 거부와 ticket renewal/lease/종료 reconciliation을 명문화 |
| S-12 제품 복구/제거 | ACCEPT | 고정 product allowlist·소유 자원만 복구·OS 변경 승인 경계 수용 |

**ACCEPT 2 / CHANGE_REQUEST 7 / QUESTION 3**.
아래 요청은 계약 보완 의견이며 코드/API에 반영하지 않았다.

## 3. 기존 설계와의 호환성

| 영역 | 판단 | 코드 근거/필요 변경 |
|---|---|---|
| 기존 Enrollment/HB/Inventory | 유지 가능 | central/service.py:116,149,180. 신규 report를 기존 payload에 덧붙이지 않음 |
| Result/Evidence/ACK | 유지 가능 | central/service.py:328-390. Evidence bytes/hash/IDs→Result ACK→Completion 순서 유지 |
| canonical PASS/FAIL/NA/UNABLE | 변경 불필요 | checks/w01.py~w64.py, central/contract.py:113. 신규 readiness를 취약점 판정으로 쓰지 않음 |
| Manifest schema1.0/64개 mapping | 변경 불필요 | central/contract.py:57, central/manifest-windows-64-2026-v1.json. 새 helper/scope policy는 별도 signed catalog/descriptor 후보 |
| 서비스/broker/helper | 설계 호환, 현재 미구현 | COMMERCIALIZATION_DESIGN.md §3/4, WINDOWS_VALIDATION_PLAN.md §6. CHECK 재사용과 transport/OS 권한 분리 |
| 신규 commercial claim wrapper | **현재 parser와 직접 호환 안 됨** | service.py:279의 기존 /tasks/claim은 flat Task. contract.py:113은 flat action CHECK 검증. 승인 후 별도 route/adapter 필요 |
| 설치/Preflight/report/receipt | 방향 구현 가능, 현재 없음 | __main__.py는 foreground CLI. storage.py의 로컬 enrollment_receipt는 새 EnrollmentReceipt upload와 다른 것 |
| 고객 무명령 설치 UX | 조건부 구현 가능 | signed Installer/SCM/provisioning/신뢰 bootstrap/recovery UI를 공동 개발해야 가능. 현재 Python 명령을 자동 설치로 포장하면 안 됨 |

새 helper가 도입된다고 W-code 기준/판정 함수를 바꿀 필요는 없다.
다만 현재 collector의 target context/부분 가시성을 측정하고 승인된 adapter/probe 설계를 추가해야 한다.
신규 진단 필드를 기존 Result.current_value/error가 dict라는 이유로 무제한 넣는 방식은 거부한다.

## 4. 결정별 상세 의견

### S-01 — CHANGE_REQUEST

근거: __main__.py:17-47 / service.py:149,180,279 /
contract.py:57,113 / ZIP 계약 §2~5, Schema ReportBase/PreflightReport/ReadinessReport.

충돌/누락:
- proposed GET /api/v2/commercial-contract는 VIEW 사용자 session 인증이다.
  상시 operating Bearer 서비스가 이 사용자 endpoint로 버전 negotiation을 할 수 있다고 가정하면 안 된다.
- 현재 Global gate catalog/version, boot/context generation, probe freshness/challenge는 설명에만 있다.
- Schema는 probes=[] / state=READY / enrollment_gate=READY 형태를 구조적으로 제한하지 않는다.
- catalog/helper null, stale scope, 잘못된 platform인데 PROBED라고 적는 보고를 shape만으로 허용할 수 있다.

권장:
서비스가 사용할 명시적 negotiation/auth 경로 또는 signed bootstrap policy를 결정.
실제 service identity에서 OS/release/integrity/store+reload/outbox/trust/time/autostart 필수 probe 목록을
고정된 catalog/version으로 확인하고 중앙 정책과 일치시킨다.
신선도는 received_at만으로 계산하지 말고 boot/context/challenge/측정 지연 및 scope 변경으로 무효화.
GLOBAL 통과+ITEM 제한이면 등록은 PARTIAL로 허용하되, 설치/온라인/점검 준비를 별도로 표시.
commercial cohort는 기존 raw/advanced claim도 gate를 우회하지 못하게 하고,
로컬 signed policy가 ticket 필수 실행을 강제해야 한다. 미지원이라고 legacy 실행으로 자동 downgrade 금지.

보안 위험: low-privilege Agent가 빈/정적/오래된 probe로 권한 실행을 여는 것.
추가 후보: 공통 execution_context_ref, boot_instance_ref, probe_catalog_version, challenge_id.
전부 opaque/versioned 관측 binding이며 실행할 계정/privilege 지시로 사용하지 않는다.

### S-02 — ACCEPT

근거: central/storage.py:27,52,82 / __main__.py foreground /
COMMERCIALIZATION_DESIGN.md §3~5 / W-47 common.py:842.

방향 수용: 저권한 Windows 서비스가 credential/통신을 소유하고,
CHECK broker는 고정 read-only operation만, HARDEN은 별도 승인 경계로 유지.
CurrentUser DPAPI를 실제 service identity에서 저장/reload/재부팅 검증한다.
현재 owner/SYSTEM DACL이 installer-created 경로에서 service SID를 자동 허용하는 것은 아니므로
명시적인 runtime SID ACL/profiles를 구현·시험해야 한다.
가상 계정/LocalService/privileged broker의 구체 선택과 SeRestore 활성화는 실측 후 승인.
설치 UAC 동의는 HARDEN 승인으로 승격하지 않는다.

보안 위험: 파일 복사/LOCAL_MACHINE fallback, SYSTEM 전체 네트워크 parser, Session0 업무 사용자 오인.
ACCEPT가 특정 LocalSystem 계정/privilege/서비스 설치를 승인하는 것은 아니다.

### S-03 — QUESTION (Unix 담당자 회신 필요)

근거: ZIP README 'Ubuntu 담당자 보고서', implementation §5/6; 로컬 Unix source 없음.
확인 요청: 실제 release commit, 보고서 원본, service UID/profile, 0600 외 암호화 및 복구 책임,
helper peer auth·local allowlist·mount/NSS/container scope·timeout/부분scan 결과.
Windows와 UID/권한 enum을 같게 만들 필요는 없다. 공통 진단 taxonomy/identity reference/coverage를 공유하면 된다.
Unix 0600 plaintext를 CurrentUser DPAPI와 동등한 보호 저장 완료로 표시하지 않는다.
자동 chown/chmod는 signed 제품 소유 경로·설치 승인 범위에만 한정하며 외부 OS 권한 repair 금지.

### S-04 — CHANGE_REQUEST

근거: common.py:728,842,980,1007,1018 /
checks/w47.py:26 / WINDOWS_PERMISSION_REVIEW.md 전체표 /
Schema Scope/Coverage/ReadinessItem/ExecutionTicketClaims.

충돌/누락:
- ELIGIBLE+PROBED+COMPLETE지만 USER binding_id=null 또는 counts 전부 null인 형태가 Schema에 허용될 수 있다.
- item_scopes의 item_id 중복/누락/초과 및 item_ids와의 집합 일치가 구조적으로 강제되지 않는다.
- COMPLETE의 수량 단위(사용자/세션/파일/볼륨/역할)와 기준 universe가 없으면 부분 목록을 COMPLETE로 보일 수 있다.
- 현재 W-47 SPI는 호출자 사용자이며 서비스 HKCU는 업무 사용자와 다르다.
  W-37/58/61/62도 count만으로 전체 visibility 증명 불가.
- Preflight coverage와 실제 job의 runtime coverage는 동일 관측이 아니다.

권장:
scope policy가 정의하는 unit/대상 universe/generation을 고정하고 opaque binding을 신뢰한 local resolver에 연결.
USER ELIGIBLE는 실제 사용자/session binding·collector context가 확인된 경우만.
COMPLETE의 counts 또는 수량 대신 완료를 증명하는 별도 승인 규칙을 항목별로 정의.
unknown expected/누락/접근불가가 있으면 COMPLETE로 허용하지 않는다.
서명 item_ids=item_scopes의 유일 집합, manifest membership, family/platform, scope 권한을 양측 검증.
사용자 세션이 없어도 임의 NA로 바꾸지 않는다.
W34/60의 기존 NA와 W63 비도메인 UNABLE은 그대로 유지.
ELIGIBLE는 실행 가능성이지 KISA PASS 또는 자동판정 가능의 의미가 아니다.

보안 위험: 서비스 사용자 설정·보이는 일부 파일을 업무 사용자 전체 PASS로 확장.
Windows 추가 후보: token_elevation_type/integrity_level, target_context_ref,
privilege_observation(present/enabled), coverage unit. Unix 대응은 UID/capability/namespace/mount scope.
공통 envelope를 훼손하지 않고 승인된 typed context/OS-details에만 추가한다.

### S-05 — CHANGE_REQUEST

근거: __main__.py:75-86 / service.py:116-147 / storage.py:119 /
ZIP 계약 §6, states registration 전이.

실제 충돌:
현재 Windows는 Enrollment→보호 save→HB/Inventory/HB ACK 후 registration file을 삭제하고,
실패하면 보존한다. 동일 enrollment receipt이면 운영 요청만 재개한다.
DRAFT는 201 뒤 저장 실패에도 **소비된 registration token 정리 + 비밀 없는 journal 보존**을 요구한다.
현재 보호 save 뒤 별도 reload 검증/새 upload receipt는 없다.
로컬 enrollment_receipt dict는 중앙 durable-store proof DTO와 혼동하면 안 된다.

권장:
(a) 명확한 미사용 실패: protected registration 파일을 TTL/권한/횟수 제한 아래 보존.
(b) 201+durable save/reload 성공: token 제거; 운영 ACK 복구는 secret-free journal + 보호 credential/outbox로 재개.
(c) 201+저장 실패: token 소비 사실 확인 후 정리; session journal/report로 RECOVERY_REQUIRED.
(d) 응답 유실/소비 불명확: 자동 재사용/재전달 금지. MANAGE의 중앙 확인 결과로 revoke/reissue;
    파일 quarantine/삭제 기준·TTL을 명시하고 고객에게 token 복사 작업을 요구하지 않는다.
어떤 상태에서 무엇을 보존하는지 표로 확정하고 credential/outbox 손상을 자동 삭제하지 않는다.
재등록 gate는 active job/미ACK/reconciliation을 **중앙 transaction에서** 검사해야 한다.
새 agent_id에 old result/evidence/outbox를 retag하지 않는다.
저장 실패 후 in-memory token으로 완료 receipt/HB를 보내지 않는다.
Rotation의 CC-01 grace를 Enrollment old 즉시 폐기와 혼동하지 않는다.

보안 위험: 등록 유실·orphan credential·진행 작업 손실·token 장기 보관/잘못된 재사용.
대안은 secret-free recovery journal이며 secret 재반환 API/raw secret DB 저장은 기본안으로 요청하지 않는다.

### S-06 — CHANGE_REQUEST

근거: service.py:279,328 / contract.py:113 /
hardening/runner.py ApprovalGate / ZIP §1/3, ExecutionTicketClaims.

현재에는 signed ticket verifier/local durable replay journal가 없다.
새 claim wrapper를 기존 flat task parser로 받아 실행하면 안 된다.
Claims JSON의 purpose=CHECK는 서명된 authorization가 아니다.

권장 공동 확정:
- 실제 JWS/서명 envelope·알고리즘 allowlist·typ/issuer/audience·kid/key 등록/회전/폐기·최대 크기.
- unsigned/alg=none/알고리즘 혼동/외부 jku 또는 x5u·미승인 key/동일명의 duplicate JSON field 거부.
- broker는 신뢰 배포한 key만 사용하고 TLS CA private key/operating token을 서명키로 재사용하지 않음.
- item 집합·scope·readiness·server/agent/job/attempt·criteria·package/policy/service identity 일치 검증.
- signed not_after는 job/lease 상한 이하, issued_at 순서·clock skew·시간 이동·boot/restart 처리 정의.
- batch ticket의 중복 수신은 이미 완료한 item을 재실행하지 않는다.
  ticket ID만 통째로 한 번 소비하면 ACK 유실 후 남은 item 복구가 막히므로
  attempt/item/scope 기준 STARTED/OBSERVED/ACK 상태와 ticket renewal의 관계를 정한다.
- offline broker의 즉시 revoke 한계를 UI/정책에 명시하고 짧은 TTL만으로 충분한지 승인.
- CHECK ticket으로 HARDEN/ROLLBACK/권한 profile 변경 불가, client command/path/script/argv 거부.

JWS를 채택한다면 알고리즘/issuer/audience/type 혼동 방어는
[RFC8725](https://www.rfc-editor.org/rfc/rfc8725.html)의 검증 원칙을 적용한다.
특정 alg/TTL을 이 검토에서 임의 확정하지 않는다.
보안 위험: 침해된 transport를 통한 특권 confused-deputy, replay 재실행, 시간/renewal 우회.
이 미결정 사항은 상용 privileged broker 출시 차단 조건이다.

### S-07 — QUESTION

근거: transport.py:38-101 / __main__.py:48-69 / ZIP 계약 §8.

수용 가능한 현재 원칙: 독립 신뢰 경로의 DER SHA256 확인 → 올바른 서비스 trust context →
runtime chain/hostname/IP SAN 검증; HTTP/verify=false 금지. 매 요청 pin 의무 추가는 아직 하지 않는다.

결정 요청:
CA overlap 기간·승인 root digest 세대·새 leaf/anchor 적용 순서·rollover ACK·old anchor 제거 조건,
old root 만료/폐기 때문에 연결 불가한 기기의 signed bootstrap recovery,
사용자 ROOT와 서비스/LocalMachine 또는 product bundle 선택 및 소유/공유 여부.
계정 이동 후 installer Administrator ROOT을 서비스가 자동 공유한다고 가정하지 않음.
서명키 rotation과 CA rotation은 별도 trust domain.
Unix pin 요청이 CA/leaf 어느 pin인지, 운영 pin을 필수로 바꿀지 joint 결정 필요.
boilerplate 'CA 교체' 보고만으로 머신 trust를 자동 추가/삭제하지 않는다.

보안 위험: MITM bootstrap, 인증서 교체 lockout, 공유 root 삭제.

### S-08 — CHANGE_REQUEST

근거: __main__.py:48-84 / transport.py:53 / ZIP 계약 §2/3/5,
Schema ReportBase/InstallationEvent/PreflightReport.

방향 수용: Enrollment token과 reporter auth 분리; installer 관측을 ONLINE/READY 증명으로 쓰지 않음.
현재 Windows CLI는 registration file을 읽고 ACL 적용한 뒤 검증/수집한다.
token 전 Preflight와 signed bootstrap/session secret download는 신규 기능이다.

권장:
signed public package/신뢰 bootstrap/민감 registration+reporter inbox의 정확한 format과
signature/URL/server/package/session/expiry binding·1회 download/재발급/no-store/OS 안전 전달을 명문화.
user-download만으로 low-privilege service가 session credential를 안전하게 얻었다고 가정하지 않음.
실제 service DPAPI reload probe가 준비돼야 token 소비 gate를 열 수 있다.
Reporter에는 해당 session의 reports만; HB/Inventory/claim/rotate/user API 금지.
PreflightReport의 phase/agent_id/session/auth 유형을 endpoint별로 제한하고
installer가 다른 Agent의 RUNTIME READY를 인증된 관측처럼 제출하지 못하게 한다.
Installer→runtime 인계 뒤 completion report 권한/Reporter TTL 만료·재발급/sequence gaps·지연 사건 처리를 정의.
offline 설치는 로컬 보호 journal·중앙 UNKNOWN으로 유지; 비인증 공개 upload나
고객에게 토큰/credential 복사·PowerShell/chmod/chown 수동 복구를 기본 UX로 요구하지 않음.
미합의 reporter로 운영 상태를 조작하는 대신 초기 UI를 UNKNOWN으로 두는 것은 허용.

보안 위험: 설치 secret 유출, reporter 권한 확대/DoS, session 혼동·허위 완료.

### S-09 — QUESTION

근거: release.py, 승인 JSON supported_os, contract.py:57 /
ZIP README Windows arch 및 implementation §4/5.

local identity 이름은 유지 가능. 별도 manifest registry 신설 불필요.
하지만 ZIP은 Central support metadata architecture=null/PENDING이라고 명시하고,
Windows JSON은 AMD64를 선언한다. identity 승인과 account/arch/domain 제품 지원 승인을 구분해야 한다.
현재 제한된 Administrator VM 결과를 새 service 계정 지원으로 자동 승격하지 않는다.

요청: 승인 package digest·signer·helper/policy/timeout 버전 source-of-truth와
Windows architecture 관측(AMD64)/publisher 지원(x86_64 등 표기) normalization 정책·승인 증거.
예시 0…0 digest/candidate helper는 실제 registry 참조로 승인될 수 없음.
검토된 Windows HEAD/실제 배포 버전과 Unix source commit/artifact 일치 확인 필요.
Release의 nullable helper/policy/timeout은 미검증 legacy 관측에는 허용 가능하지만
commercial privileged CHECK ELIGIBLE/ticket에는 실제 승인 값이 필요.
기존 Manifest schema1.0을 새 release metadata 전부를 넣는 저장소로 임의 확장하지 않는다.

보안 위험: 배포 artifact와 module 이름만 같은 악성/구버전 코드 실행, 미검증 OS 지원 확대.

### S-10 — CHANGE_REQUEST

근거: service.py:328-390 / contract.py:141 safe_observation /
ZIP 계약 §7, states taxonomy, Schema Diagnostic/WindowsDetails/UnixDetails.

유지 가능한 것: canonical enum, NOT_REQUIRED, 정상 manual UNABLE/COMPLETED,
실제 수집 실패 UNABLE/FAILED, Evidence hash/byte_length/ID 및 Result ACK→Completion.
기존 reason_code/W47 normal boolean은 소급 변경하지 않는다.

변경 필요:
현재 FAILED는 reason_code WINDOWS_API_UNAVAILABLE/COLLECTOR_ERROR로만 분류하고,
다른 error_reason은 current_value.diagnostic_reason에 마스킹하여 넣으며 Result.error=null일 수 있다.
DRAFT의 partial UNABLE/COMPLETED/COLLECTION_INCOMPLETE+error 규칙은 현재 전송기와
자동으로 같아지지 않는다. 부분 수집의 실패/정상 종료 의미를 명확히 합의해야 한다.
새 diagnostic canonical code는 현재 W-code reason_code를 대체하는 것이 아니라 별도 매핑으로 보존.
warning을 PASS/FAIL/NA Result.error에 넣지 않는 방향은 수용.
job/item/attempt로 진단을 연결하는 허용 필드·report→Result 상관관계 및 coverage Evidence 구조를 확정.
diagnostic_id 참조 유효성/동일 자산·platform 및 cause/category/remediation의 fixed taxonomy도 검증.

Windows 추가 필드와 Unix capabilities는 관측값이며 실행할 privilege 지시가 아니다.
cause.message는 max500이어도 token/PII/명령/HTML 등 안전하다는 보장이 없으므로
고정 UI template+허용된 안전 인자+수집원 별 마스킹 적용.
Source/error native code가 현재 수집되지 않았으면 만들어 넣지 않는다.

보안 위험: 부분 수집 전체 PASS, raw exception leak, 경고로 기존 DTO를 깨뜨림,
성공 결과의 재전송 때 진단을 추가해 원문 멱등성 위반.

### S-11 — CHANGE_REQUEST

근거: contract.py:90 Lease / service.py:56,279,328,392-452 /
common.py:1082,1109 timeout / ZIP §1/7, implementation failure matrix.

현재: monotonic lease와 RTT 차감, completed_item_ids 제외, 동일 원문 outbox 유지.
하지만 collecting=True로 중단된 항목은 동일 attempt 자동 재실행을 거부한다.
모니터 thread의 갱신이 native collector를 강제 종료하지는 못한다.
재시작한 단조시계를 이전 프로세스 deadline으로 해석하지 않는다.

권장:
COLLECTOR/HELPER/TRANSPORT/LEASE의 정책 버전·시간/출력/child-process 예산을 합의.
signed ticket not_after·lease·job expiry의 최소 상한으로 **broker 자체**가 실행/새 제출을 차단.
별도 broker process/Windows Job Object 또는 Unix process group의 bounded 종료·자식 정리,
read-only temp file/이미 관측한 결과의 durable journal 경계를 정의.
중단 ITEM은 안전 재관측 허용/거부 정책 및 audit를 명문화하고 code마다 임의 retry하지 않는다.
관측 완료/전송 유실은 원문 재송신, 관측 중단/불명확은 reconciliation으로 분리.
새 ticket 발급/renewal은 completed item replay 허가가 아니다.
ACK retry·Completion replay의 기존 허용 조건은 보존하되 lease 만료 후 신규 작업/새 원문 금지.
clock skew/rollback/boot 및 timeout renewal 이후 signed deadline 동기화 수단을 확정.

보안 위험: collector 무한 실행·stale 권한 유지·중복 측정/전송·강제종료 시 outbox 유실.
현재 Windows30초/20초 및 보고된 Unix10초/15초를 공통 확정값으로 채택하지 않는다.

### S-12 — ACCEPT

근거: COMMERCIALIZATION_DESIGN.md §6/8 / WINDOWS_VALIDATION_PLAN.md §6 /
ZIP states §4 및 contract §8.

제품 소유 경로·signed 동일 artifact·local repair allowlist·상한/cooldown·감사 이력 조건 수용.
OS 보안정책/GPO/PAM/firewall/보호 ACL/role 설치는 제품 자동 복구로 우회하지 않음.
credential/outbox 손상 시 자동 삭제·재등록·판정 변환 금지.
uninstall offline revoke pending, 공유 CA/타 제품 자원 보존 방향 수용.
구체 auto-repair 권한/경로·승인 lifetime은 구현 전 별도 catalog로 확정해야 한다.

## 5. Schema가 허용해도 runtime에서 차단해야 하는 사례

아래는 직접 읽은 schema 제약의 구조상 공백과 semantic 검사 요구다.
표준 Draft2020-12 validator로 허용 판정을 실행한 것은 아니다.

| 사례 | Schema 근거/공백 | runtime 필수 처리 |
|---|---|---|
| READY + 빈 probes | PreflightReport.probes minItems 없음 | required catalog 전체 없으면 enrollment gate BLOCKED |
| NOT_RUN + enrollment_gate READY | 각 enum 간 상관 제약 없음 | 보고 무효, installer success로 승격 금지 |
| ELIGIBLE USER binding_id=null | Scope.NullableId | 승인 사용자/session binding 없으면 실행 불가 |
| COMPLETE counts 모두 null 또는 expected1/observed2/omitted0 | 개별 숫자만 minimum0 | item별 unit/universe/합계 또는 완료 규칙 검증 |
| W-01 두 ReadinessItem, duplicate diagnostic_id | object array의 id별 uniqueness 없음 | 중복 거부, 참조 누락/교차자산 거부 |
| windows Release + U-01 또는 UnixDetails | 개별 definition shape만 연결 | family/platform/manifest membership exact match |
| mismatched item_scopes / USER scope 혼합 축약 | item_scopes id별 uniqueness/집합 제약 없음 | signed item_ids와 exact unique mapping, scope 권한 확인 |
| issued_at 이후가 아닌 not_after / 매우 긴 TTL | Instant format만 있음 | trusted clock·정책TTL·lease/job upper bound 확인 |
| schema-valid claims지만 unsigned/틀린 audience/key | Claims는 서명 token DTO가 아님 | signature/key/purpose/audience/binding/replay 필수 |
| old observed_at, 뒤늦은 신규 message/ACK | 시간관계·boot·challenge 공백 | 수신시각으로 fresh를 만들지 않음; STALE/UNKNOWN |
| RELOAD true지만 다른 계정/credential ID | EnrollmentReceipt는 boolean/Id만 확인 | authenticated current binding+service reload proof context 확인 |
| cause.message에 token, approval NONE+OS repair | string shape와 enum만 확인 | secret/PII filtering·fixed cause/repair authorization policy |
| reporter Preflight RUNTIME / 다른 Agent ID | 일부 report 조합의 auth cross-check는 별도 | endpoint/session principal/phase/Agent binding exact |
| Lifecycle ONLINE+credential NONE 또는 READY+version MISMATCH | 상태 축 간 cross-field 검증 없음 | Central-derived gating만으로 계산, 실행 허가 금지 |

추가: JSON parser duplicate object key 처리, URI처럼 보이는 Id의 경로 활용 금지,
외부 ref/key fetch, payload/output size 및 clock format assertion은 boundary에서 명시한다.
transport report의 상태/privilege/profile/repair 필드는 OS 변경 명령이 아니다.
이 사례를 schema 문제로 전부 해결할 수는 없으며 반드시 endpoint authorization·DB FK·정책과 함께 검증한다.

## 6. 고객 설치 UX 검토

목표 흐름(다운로드→1회 설치 UAC/sudo→service/CA/manifest 구성→등록→ONLINE→CHECK→원인/복구)은
설계상 가능하지만 아직 현재 기능이 아니다.
고객에게 credential blob 복사·명령 실행·chmod/chown을 기본 설치 절차로 요구하지 않는 방향 수용.

출시 전 필요한 선행 조건:
1. 승인 서명된 package/trust bootstrap와 민감 install bundle 안전 전달.
2. 실제 service identity의 DPAPI/Unix store self-test/reload, registration consumption policy.
3. Installer가 실패 단계를 UI로 전달하고 reporter/네트워크 불가면 UNKNOWN 및 안전 재시도.
4. privileged broker local fixed policy+signed task+scope/coverage 검증.
5. old active jobs/outbox·credential migration·CA update·uninstall 복구 UX.
6. readiness/Result/diagnostic 공통 UI를 설치됨/온라인/점검준비와 분리.

Windows 내부 구현 순서는 기존 승인 방향 **Service → Installer → Preflight → CHECK Broker** 유지.
Central 문서의 개발 phase는 교차 의존성 gate로 해석하고 최종 제품의 실제 설치 시점에는
Preflight/store/broker 준비가 완료되지 않으면 token 소비/privileged CHECK를 열지 않는다.
중간 단계의 서비스 설치 성공을 상용 제품 완료로 발표하지 않는다.

## 7. Central에 요청할 수정 우선순위

| 우선 | 요청 | 담당/결정 |
|---|---|---|
| P0 | S-01/S-08 operating Agent와 installer가 실제 사용하는 negotiation/bootstrapping auth/DTO 정리 | Central+양 Agent |
| P0 | S-05 registration secret vs journal의 성공·실패·응답유실 처리 표와 active jobs의 atomic re-enroll gate | Central+Windows+Unix+운영 |
| P0 | S-06 완전한 signed claim wrapper/JWS 검증·key lifecycle·local enforcement·batch replay/renewal 정책 | Central+양 Agent+보안 |
| P0 | S-04 binding/coverage unit/freshness/context, 필수 semantic negative vectors | 양 Agent+Central |
| P1 | S-10 partial/error/coverage Evidence·진단 상관관계와 taxonomy 표 | Central+양 Agent |
| P1 | S-11 interrupted collecting/late result/Completion retry/clock restart 시험 | 양 Agent+운영 |
| P1 | S-07/S-09 trust/support/artifact·계정·architecture 승인 증거와 rollover 복구 | release+운영+보안 |
| P1 | S-03 Unix 원본 코드/설계/실측 기준 commit 회신 | Unix 담당자 |

v1 초안을 지금 승인하지 않는다. ACCEPT 항목도 전체 security gate 미결정 상태에서 상용 설치/실행을 허가하지 않는다.

## 8. 검토 검증 기록

- ZIP 6개 전체 열람, JSON2개 파싱, 예시7개 definition 존재 확인.
- Schema 표면 제약과 source 함수/line 대조. runtime semantic/서명/FK/auth 검증은 실행하지 않음.
- 환경에 jsonschema 표준 validator 없음. 설치하지 않았고 metaschema/완전 schema 인수 PASS를 주장하지 않음.
- Unix source·Central 실제 저장소/DB/테스트·Windows 서비스/VM E2E는 이번 작업에서 미검증.
- Agent/CHECK/HARDEN/API/wire/OS 변경 없음. 검토 문서만 추가, commit/push 없음.

