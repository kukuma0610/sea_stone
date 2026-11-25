# Windows Agent 상용화 설계 검토 (승인 전 제안)

기준일: 2026-10-14. 검토 HEAD: d774d7d8bf0bf492d66a57052088f1aa9fb2f0d4.
원본: Downloads/OSGuard_Windows64_B6ED9CB6EC9D_B4EC88.xlsx (2개 시트 전체).
항목별 자료: [WINDOWS_PERMISSION_REVIEW.md](WINDOWS_PERMISSION_REVIEW.md).
현재 단계는 설계 제출이며 새 서비스/계정/설치/권한/CA 변경, 코드 수정, commit/push 없음.

## 1. 확인된 상태와 확인하지 않은 상태

| 증거 | 확인 범위 | 확인하지 않은 것 |
|---|---|---|
| 사용자 제공 VM 결과 | Administrator로 Enrollment/DPAPI/Heartbeat/Inventory/ONLINE 성공 | TokenElevation, 비관리자, LocalSystem/가상 서비스 계정, 최신 CHECK 실제 E2E |
| 소스 검토 | 64개 CHECK와 registry, 승인 JSON 및 기본 경로, Central 보호 state/회전/ACK 경로 | 64개 권한별 실측, 모든 역할/도메인의 effective 정책 |
| 기존 개발 테스트 | 단위·Mock 통합 테스트, 이전 개발 PC DPAPI 저장/재로드 실측 기록 | 해당 서비스 계정 프로필/재부팅 후 DPAPI, 실제 CA trust 및 서비스 lifecycle |
| 첨부 Excel | 코드 기반 NOT_TESTED 분석, 64개 행 존재 | 실제 권한 필수 여부를 확정하는 자료가 아님 |

권한은 계정 이름으로 판정하지 않는다. 동일 계정도 토큰 상승 상태, enabled privileges,
서비스 SID, 객체 DACL, WMI namespace/provider, 세션, 32/64bit registry view에 따라 달라진다.
[UAC/WMI 공식 설명](https://learn.microsoft.com/en-us/windows/win32/wmisdk/user-account-control-and-wmi)

현재 지원 선언은 WINDOWS / version10.0.20348 / build20348 / AMD64.
schema1.0, platform windows, module_version windows-2026.1,
manifest_id manifest-windows-64-2026-v1 및 W-01~W-64 mapping을 유지.
manifest 지원 선언은 에디션/도메인/역할 전부 검증 완료라는 의미가 아니다.

## 2. 현재 설치·실행 구조의 문제점 (수정 승인 전 목록)

| 우선순위 | 실제 코드 근거 | 제품 영향 |
|---|---|---|
| P0 | central/__main__.py는 foreground CLI, SCM service lifecycle 없음 | 로그아웃/콘솔 종료 후 운영 보장 없음 |
| P0 | CurrentUser DPAPI, state DACL owner/SYSTEM | 설치 Administrator와 서비스 계정 불일치 시 해독/ACL 실패; installer-owned 디렉터리가 서비스 SID에 자동 허용되는 구조 아님 |
| P0 | W-47 HKCU/SystemParametersInfoW current_user | Session0 서비스 사용자를 실제 업무 사용자로 오인할 수 있음 |
| P0 | W-09 secedit, W-62 SeRestorePrivilege, protected/role ACL | 단일 관리자/비관리자 구분표만으로 완전 수집/커버리지 보장 불가 |
| P1 | powershell.exe, secedit.exe bare name; 환경변수/서비스 CWD 및 module search 사용 | 고권한 실행기 도입 전에 실행 경로/모듈 탐색 및 DLL/패키지 무결성 통제 필요 |
| P1 | 일부 SilentlyContinue/Test-Path/EnumValue OSError 처리 | 실패가 부재/부분 목록으로 가려질 가능성; W-23/31/43/58/61 등 별도 결함 검증 필요 |
| P1 | 오류 CLI는 CentralError.code 또는 예외 type 중심 | KeyError/권한/정책 부재/환경 제약을 사용자 조치로 연결하기 어려움 |
| P1 | secedit export에 /mergedpolicy 없음; legacy audit 조회 | 모든 domain effective policy/advanced audit 증거로 취급하면 안 됨 |
| P1 | local_runner.spec/build.ps1은 local CHECK EXE만 생성 | Central service EXE/approved JSON data packaging/Installer/업데이트/제거 미구현 |
| P1 | 승인 및 snapshot 경로는 기존 Hardening/Core의 로컬 구조 | Central HARDEN capability/서명 approval/서비스 간 authorization 계약은 별도 필요 |
| P2 | 단순 config/manifest 읽기·경로 보호; signed release 검증 없음 | 설치/업데이트 위변조 및 호환성 사전 탐지 필요 |
| P2 | 네트워크 thread/collector timeout/lease 경계 | SCM stop·reboot·중단/lease 만료의 재시작 reconciliation 실제 검증 필요 |

위 위험을 이번에 수정하지 않았다. KISA 판정 변경/기본값 추정으로 권한 문제를 숨기지 않는다.

## 3. 서비스 실행 계정 및 권한 구조 권고

| 방안 | 보안성 | 구현 난이도 | 판단 |
|---|---|---|---|
| Agent 전체 LocalSystem | 네트워크/JSON/증적 처리 결함이 시스템 권한으로 연결; W-47 대상 문제는 해결 안 됨 | 초기 구성 상대적으로 단순, 이후 권한 축소/사용자 범위 문제 큼 | 최종 제품 기본안으로 비권장 |
| 저권한 Agent + 권한 CHECK 실행기 + 별도 승인 HARDEN 경계 | 원격 수송과 OS 접근 분리; broker 검증이 새로운 핵심 공격면 | 높음; IPC/서비스 토큰/세션/배포 통합 필요 | 권장 |

### 제안 구성

- OSGuardAgent: 별도 가상 서비스 계정 NT SERVICE\\OSGuardAgent 후보.
  Administrators 미가입, 불필요한 rights 미부여. HTTPS 및 Core orchestration/DPAPI/outbox 담당.
  필요시 LocalService+고유 service SID 대안이나 여러 LocalService 프로세스의 동일 계정 DPAPI 공유 위험과 ACL을 비교.
  실제 virtual-account 프로필/DPAPI 재부팅 보존은 승인 전 VM 필수 검증.
- OSGuardCheckBroker: 가상 계정+정확한 읽기 위임으로 가능한 항목부터 측정.
  현 경로의 secedit/protected ACL 때문에 필요한 경우 **네트워크 기능 없는 제한된 LocalSystem broker** 후보.
  서비스 required privileges/제한 SID를 수집 경로별로 최소화하여 시험. SeRestore를 통신 서비스 전체에 부여하지 않음.
  current collector가 필요로 하지 않는 SeDebug/SeTcb/SeBackup을 포괄 부여하지 않음.
- OSGuardHardeningBroker: CHECK broker와 별도 서비스/프로세스/IPC namespace·allowlist·authorization.
  현재 SEMI_AUTO 18개/FAIL·승인·snapshot·reCHECK·rollback의 보안 불변식 유지.
  설치 UAC 동의는 이후 HARDEN 조치의 동의가 아니다. AUTO 추가 금지.
- IPC: 로컬 named pipe, 명시 DACL로 Agent service SID와 허가된 관리자만, 원격 client 거부,
  서버/클라이언트 identity와 peer process image/token 검증, 메시지 크기·nonce·수명·replay 제한.
  요청에는 code/job_id/attempt/manifest binding만; 외부 command/경로/script/PowerShell 받지 않음.
  broker가 자신의 신뢰한 local mapping을 사용. 실행 모드에 따라 write operation 자체를 분리.
- 저권한 서비스는 Program Files의 exe/module/manifest를 수정할 수 없어야 함.
  service change-config 권한은 관리자만, unquoted service binary path 금지.
  broker는 credential/token 전달받지 않음. 단, LocalSystem은 머신 지배 권한이므로
  이 분리가 악성 SYSTEM으로부터 DPAPI 비밀을 완전히 보호하는 경계라고 주장하지 않음.

[서비스 계정](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts),
[LocalSystem 위험](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account),
[서비스 접근 권한](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights),
[Named pipe ACL](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

### 자동 실행과 장애 복구

SCM의 자동 시작(네트워크 대기는 Agent backoff), SERVICE_RUNNING/STOP_PENDING/STOPPED 상태 보고,
stop event와 bounded grace 종료 구현. 비정상 crash는 지연/상한 있는 SCM recovery restart 정책.
계속되는 TLS/credential/preflight 오류는 재시작 폭주 대신 차단 상태+안내.
재시작 후 오래된 monotonic lease를 재사용하지 않고 Central과 revalidate.
같은 message_id/outbox 원문·증적 ACK를 유지하고 이미 완료한 항목 재실행/attempt 재태깅 금지.
foreground python.exe를 sc create로 등록만 하는 방식은 SCM protocol 구현을 대체하지 않는다.

## 4. W-47 및 사용자 범위

LocalSystem/LocalService/virtual account의 HKCU/SPI 조회는 로그인 업무 사용자와 다르다.
서비스 계정 수집값으로 사용자 전체 PASS/FAIL을 Central에 보내지 않도록 context validation을 별도 설계한다.
현재 CHECK 판정 자체는 바꾸지 않는다.

제안: W-47는 승인된 사용자 범위 정책(all interactive sessions/지정 사용자/정책 대상) 확정 후
사용자 세션의 서명된 소형 read-only collector에서 같은 CHECK를 실행하거나, 검증된 사용자 context로 실행.
WTSQueryUserToken은 LocalSystem+SeTcb가 필요한 고신뢰 API이므로 단순한 impersonation만으로
SPI가 올바른 데스크톱/세션을 관측한다고 가정하지 않는다.
Session0, 다중 RDP, disconnected session, 로그인 사용자 없음, 다른 사용자 GPO, 서버 core를 시험.
온라인 세션 없으면 NOT_OBSERVED/UNABLE 제안 사유이며 임의 PASS/NA 금지.
offline hive를 임의 load하거나 사용자 로그인/잠금 상태를 변경하지 않는다.
W-35 system DSN, W-37 Task ACL, W-58 profile visibility, W-62 autostart 사용자 scope도 동일하게 coverage를 기록.

[서비스 세션 격리](https://learn.microsoft.com/en-us/windows/desktop/services/interactive-services),
[WTSQueryUserToken 요구](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)

## 5. DPAPI·등록·계정 변경

### 신규 설치 기본안

1. 관리자 UAC 승인 후 서명된 installer가 서비스 identity/파일/ACL을 구성.
2. **실제 서비스 실행 계정**에서 CurrentUser DPAPI self-test 및 저장/재로드/재시작 검증.
3. 관리자가 신뢰한 등록 파일과 공개 CA/별도 확인한 지문을 installer에 제공.
4. registration token은 argv/environment/평문config/로그에 넣지 않고 인증된 일회 IPC 또는
   서비스 SID 전용 임시 inbox로 인계. 해당 inbox는 동시 사용자·link/TOCTOU·재사용 차단.
5. 실제 서비스 계정이 HTTPS Enrollment → DPAPI 저장 → Heartbeat/Inventory ACK 수행.
   저장/운영 성공 확인 전 파일을 지우지 않으며, 불명확한 Enrollment 응답은 자동 토큰 재사용 금지.
6. 등록·ONLINE은 Central의 실제 상태에서 별도 확인. Installer 종료 후에도 서비스 유지.

CurrentUser DPAPI는 같은 logon credential/보통 같은 머신에 종속된다.
기존 Administrator blob을 service 계정에 복사해도 해결되지 않는다.
LOCAL_MACHINE 전환은 같은 머신의 다른 사용자도 복호화 가능한 범위로 확대하므로 기본 해결책으로 사용하지 않는다.
[DPAPI 공식 계약](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

### 기존 등록에서 서비스로 전환

권장: Central에서 controlled re-enrollment 승인 → 진행 작업/미ACK outbox를 먼저 정리/취소 합의 →
서비스 계정에서 새 등록. server_id 보존 및 기존 Agent/credential 폐기 시점은 Central 계약대로 검증.
기존 DPAPI 데이터는 임의 삭제/새 계정에서 해독 시도하지 않는다. 새 운영 연결 확인 후 이전 런타임 중지·자격 제거.
응답 유실 시 이전 blob의 token 복사/자동 재등록을 하지 않고 새 registration 발급 절차로 복구.
agent_id 유지가 꼭 필요하면 Central의 계정 이전 authorization과 로컬 고신뢰 일회 전달/rotation 절차를
**별도 합의**한다. 단순 blob/전체 outbox 복사 또는 설치 로그에 plaintext 전달 금지.

계정 변경은 동일 기기라도 새 profile/DPAPI identity lifecycle이다.
프로필 유실·서비스 삭제/재생성·비밀번호 강제 reset·reimage는 복구/재등록 runbook 필요.
현재 owner/SYSTEM DACL은 installer owner 기준일 수 있으므로 명시적인 runtime service SID ACL과
owner 설정을 설계하고, 다른 계정이 credential/outbox/state를 읽지 못하는 시험을 한다.

### 회전 및 비밀 보호

기존 CC-01 새 token 보호 저장 → 새 token 운영 요청 → Central ACK 확인 → old 제거 순서 유지.
응답 유실/grace 복구/old revoked/new expired/중복 rotation을 실제 서비스 재시작과 함께 시험.
중앙 권한 확인 외 arbitrary execution 입력은 계속 거부한다.
token/registration/private key/password는 argv·로그·dump·evidence에 배제, 코드별 allowlisted field만 수집.
W-47 password_protected 같은 정상 boolean은 그대로 유지.
crash dump/서비스 진단 ZIP/PowerShell transcript/WER의 비밀 노출도 검사. credential 암호화는
메모리와 dump까지 자동 보호하지 않는다.

## 6. Installer·업데이트·제거

제안 배치:
- Program Files\\OS Guard\\Agent: 서명된 service host/Agent runtime/CHECK/manifest/공개 CA,
  일반 사용자 및 저권한 서비스에는 read/execute만.
- ProgramData\\OS Guard\\Agent: config, state, logs, bounded spool.
  각각 runtime service SID 기반 DACL; credential state는 CurrentUser DPAPI+ACL, temp/output까지 보호.
- HARDEN snapshot은 별도 실행기 SID/관리자 승인 경로의 보호 저장소. 조회용 로그와 섞지 않음.

신뢰할 설치 입력은 Central origin URL, registration/server binding, 별도 trusted CA fingerprint,
서명된 release descriptor/API·agent·module·manifest·OS 호환표.
신뢰하지 않은 HTTPS에서 CA/지문을 같이 받아 자체 승인하는 방식 금지.
installer가 공개 CA DER hash를 검증하고 대상 서비스가 보는 Trust Store에 승인된 인증서만 적용.
현재 코드는 CurrentUser ROOT이므로 설치 Administrator ROOT에 추가한 뒤 서비스에서도 보인다고 가정하지 않는다.
LocalMachine ROOT 주입은 machine-wide trust 변경: 설치 승인 범위에 명시하고 소유 지문/사용 관계 기록.
삭제 시 공유 CA를 무조건 제거하지 않으며 다른 제품/서비스 사용 여부를 확인한다.
runtime TLS chain/hostname/IP SAN 검증과 redirect 차단 유지, verify=False 금지.

Installer transaction: validate 서명/OS/경로 → staged 파일 → service/SID/ACL →
preflight → registration → 운영 ACK → 최종 start/완료. 실패 시 OS Guard가 생성한 자원만 안전 복구.
필요 Server roles/IIS/FTP/Defender/도메인/GPO/ExecutionPolicy를 제품 편의를 위해 설치·완화하지 않는다.

업데이트는 서명/호환성/기존 credential account 유지/state schema migration snapshot/원자 교체/
실패 시 이전 Agent 복구. 미ACK 데이터 삭제 또는 새 message_id로 세탁 금지.
제거는 Central decommission/revoke 정책+오프라인 처리 합의, 승인된 제품 전용 경로만 제거.
인증정보/보고서 보존 기간 선택은 별도 고지; service account/CA/사용자 파일 무조건 삭제 금지.
이번에는 Installer 기술/pywin32/native service host 선택·소프트웨어 설치를 수행하지 않았다.

## 7. Preflight (등록 토큰 사용 전)

| 검사 | 방식/성공 조건 | 실패 처리 |
|---|---|---|
| OS/release | Version/Build/ProductType/arch/edition/manifest64·module exact match·signature | UNSUPPORTED 또는 SUPPORT_UNVERIFIED; 가입 토큰 소비 금지 |
| 계정/UAC | service identity SID, TokenElevation/TokenElevationType, integrity, enabled privileges | 설치 권한과 runtime 부족을 분리; UAC 변경/관리자 그룹 자동 추가 금지 |
| SCM | installer가 필요한 SC_MANAGER_CREATE_SERVICE/change-config 가능 여부, 기존 자원 충돌 | 승인 안내; 상대/미인용 service path 금지 |
| collector readiness | secedit temp export·WMI/provider·IIS/DNS role·명령/모듈 경로·read ACL | 항목별 READY/BLOCKED/PARTIAL 제안; 누락 역할을 임의 설치하지 않음 |
| W-47 scope | 사용자 session 대상·capability·SPI context | scope 미확인 차단/UNABLE; 로그인 사용자 생성하지 않음 |
| TLS | DNS/TCP/time/검증된 CA trust/chain/SAN TLS handshake (Enrollment 전) | 인증서/지문/시간 문제 안내; 미합의 health endpoint를 만들어 전송하지 않음 |
| DPAPI/store | 실제 runtime 계정의 임시 비밀 self-test/암호화 저장·재로드/ACL 및 reparse 검사 | NO_PLAINTEXT_FALLBACK; enrollment 전 차단 |
| state/log/tmp | runtime SID의 파일 read/write/atomic replace·lock·disk quota 가능 | 제품 전용 디렉터리만 승인된 ACL 복구; 외부 OS ACL 변경 금지 |
| 중앙 binding | URL/server_id/family/header/expiry/format 및 재등록 승인 | token 소비 전 오류 표시; 허용 헤더 임의 변경 금지 |

역할 미설치 때문에 일부 CHECK가 UNABLE이어도 전체 등록이 반드시 실패해야 하는지 정책 합의 필요.
온라인 가능 상태와 점검 준비 상태는 별개이며, 일부 점검 불가를 ONLINE 성공으로 숨기지 않는다.
Preflight probe도 OS 정책 변경 금지. secedit 임시 export/DPAPI test 데이터만 보호된 제품 경로에서 정리.

## 8. 오류·진단 공통 계약 (전부 DRAFT, 현재 API에 추가하지 않음)

제안 레코드:
schema_version, diagnostic_id, occurred_at, platform, server_id/agent_id,
operation_id/job_id/attempt_id(해당 시), stage, code, severity,
affected_item_ids, target_scope, required_access,
retryable, auto_recoverable, approval_required, remediation_key, recovery_outcome.
required_access는 Windows privilege/ACL 이름 또는 Unix uid/capability로 표현하되 공통 UI는 remediation_key를 번역.
원문 exception/token/command/data는 필드에 넣지 않는다. OS 사용자 식별 증적은 마스킹 원칙 유지.

제안 상태(현 API health/registration state를 덮어쓰지 않음):
install_state NOT_INSTALLED/INSTALLING/INSTALLED/FAILED;
preflight_state NOT_RUN/READY/PARTIAL/BLOCKED;
check_readiness READY/PARTIAL/BLOCKED.
ONLINE는 연결 상태일 뿐 READY/PASS와 같지 않음.

| 공통 원인 코드 후보 | Windows 구체 사유 예 | 자동 복구/승인 |
|---|---|---|
| ACCESS_DENIED | TOKEN_NOT_ELEVATED / OBJECT_DACL_DENIED / REQUIRED_PRIVILEGE_MISSING | OS ACL/권한은 승인·설계 필요 |
| TARGET_CONTEXT_MISMATCH | USER_SESSION_SCOPE_MISMATCH / DOMAIN_POLICY_NOT_VERIFIED | 대상/범위 합의; 임의 context fallback 금지 |
| DEPENDENCY_UNAVAILABLE | ROLE_NOT_INSTALLED / MODULE_UNAVAILABLE | 역할 자동 설치 금지 |
| COLLECTION_INCOMPLETE | TASK_VISIBILITY_PARTIAL / PROFILE_COVERAGE_UNKNOWN | coverage 불명확 결과 UNABLE |
| CONFIG_INVALID | MANIFEST_MISSING / MANIFEST_BINDING_MISMATCH / STATE_PATH_INVALID | signed bundled manifest만 안전 기본 경로 복구 가능 |
| CREDENTIAL_UNAVAILABLE | DPAPI_ACCOUNT_MISMATCH / CREDENTIAL_EXPIRED / REENROLL_REQUIRED | re-enrollment/rotation 승인 절차 |
| TLS_VALIDATION_FAILED | CA_FINGERPRINT_MISMATCH / CERT_CHAIN_UNTRUSTED / SAN_MISMATCH | trust 완화 금지 |
| TRANSIENT_IO_FAILURE | NETWORK_TIMEOUT / PRODUCT_STORE_BUSY | bounded retry, 기존 message_id 유지 |

자동 복구 허용 후보: 자체 lock 충돌의 bounded 재시도, 제품 전용 temp 정리,
승인·검증된 자체 파일 재배치, 서비스 crash 재시작, 네트워크 retry.
금지: 보안정책/GPO/보호 ACL/도메인/방화벽/CA 추가를 오류 숫자 줄이기 위해 무승인 변경,
UNABLE→PASS/NA, 토큰 재발급/폐기를 임의 처리.

Central/Unix와 합의할 사항:
1. diagnostic endpoint vs 기존 Inventory.collection/Result.error 허용 범위, schema/version/max size/ACK/message id.
2. 설치/등록/Online/부분 readiness를 분리한 공통 상태와 UI.
3. 공통 원인 코드 taxonomy, Windows/Unix subtype·remediation key·로그 masking·보존 정책.
4. 사용자 scope/coverage/effective-domain-policy 표현. W-47 per-user aggregation 기준.
5. Agent/API/manifest/module release와 OS/support source-of-truth, signed release 배포/업데이트 책임.
6. 서비스 identity로 재등록·이전 등록 revoke·migration authorization·오프라인 uninstall 정책.
7. HARDEN의 승인 주체/actor/RBAC/plan digest/action scope/TTL/nonce/서명/anti-replay.
   통신 서비스가 전달한 approved=true만으로 특권 broker 실행을 허용하지 않음.
8. SCM shutdown/lease expiry/collector timeout/outbox reconciliation, reconnect/backoff 및 재시도 가능 오류.
9. registration package 신뢰 전달, 소비/응답 유실/재발급 semantics와 ONLINE 검증.
현재 Central capability는 CHECK이며 로컬 Hardening과 별도다. 새 HARDEN HTTP 계약을 여기서 확정하지 않는다.

## 9. 변경 예정 파일·순서 (현재는 구현하지 않음)

| 순서 | 기존/신규 후보 파일 | 목적 | 난이도/주요 위험 |
|---|---|---|---|
| 0 | 테스트/VM validation 자료 | 최신 manifest PARTIAL1 실제 E2E baseline부터 확보 | 중; 잘못된 성공 가정 |
| 1 | tests/test_*permissions.py (신규), tests/service_vm_matrix 자료 | 64개 account/token/role/domain/session coverage 실측 | 높음; GPO/프로필 차이 |
| 2 | agent/preflight/*, agent/diagnostics/* (신규), central/__main__.py/contract.py | token 전 진단·안전 오류 DTO; wire 수정은 공통 합의 후 | 중~높음; 정보 유출/등록 소비 |
| 3 | agent/service/*, agent/broker/* (신규), central/service.py/core/service.py | SCM lifecycle, read-only IPC dispatcher, same CHECK 재사용 | 높음; 특권 상승/타임아웃 |
| 4 | central/storage.py/transport.py/__main__.py | 실제 service DPAPI/SID ACL, trust/등록 계정 분리 | 높음; credential 유실/CA 신뢰 확대 |
| 5 | packaging/*, 전용 Central spec/build script, installer/* (신규) | signed Agent/manifest bundle·service/계정·자동 설정 | 높음; update/rollback/공유자원 손상 |
| 6 | checks/common.py + 영향 항목의 별도 검증 테스트 (승인 후만) | safe executable path/위임·사용자context/부분수집 검증 | 높음; 판정/evidence 회귀 |
| 7 | core/state.py, hardening 승인 경계/보호 snapshot 저장 (승인 후만) | durable signed approval/별도 broker authorization | 높음; 무승인 조치/원복 유실 |
| 8 | recovery/upgrade/uninstall 자료·테스트 | crash/powerloss/account migration/오프라인 제거 | 높음; 서버등록·outbox 손실 |

현재 구현되지 않은 파일명은 후보 설계이며 존재하는 CLI/제품 기능으로 소개하지 않는다.
상용화 경로를 먼저 완성했다고 주장하지 않음. 판정·HARDEN action 변경은 별도 근거/승인 필요.

## 10. 실제 검증 계획과 승인 게이트

- 같은 Server2022 Build20348 AMD64 VM snapshot 기반:
  일반 사용자, 관리자 filtered token, UAC 상승 관리자, LocalService, 가상서비스계정,
  읽기 위임 broker/LocalSystem을 **각각** 측정. IsUserAnAdmin만으로 전체 privilege를 증명하지 않음.
- 각 W-code: collector 성공/오류·Win32 status/HRESULT, identity/세션/privilege enabled 상태,
  대상 수/제외 수/coverage, status/manual_review/error, masked evidence 비교. 동일 대상 데이터인지 확인.
- 역할별: IIS/FTP/DNS/SNMP 없음/있음/중지/구성 없음/조회 실패.
  registry absent/ACL denied를 구분, 도메인 없음/멤버/DC·GPO 제한·policy 부재를 별도 검증.
- W-47: Service Session0, 다중 RDP, 로그아웃/잠금/접속해제, 서로 다른 user policy;
  다른 계정의 설정을 성공 결과로 오인하지 않는지.
- W-37/58/61/62: 일부 visible 목록, 숨겨진/미로드 profile·미확인 FileSystem·mapped drives;
  정상 빈 목록과 수집 실패/불완전 목록이 같은 PASS로 해석되지 않는지.
- 실제 서비스 계정 DPAPI: installer 인계 → 새 계정 저장 → 로그아웃/재부팅/서비스재시작,
  old/new 회전의 저장/ACK/폐기 단계별 장애, 계정 변경/삭제·profile 손실.
- SCM recovery, sleep/network offline/TLS 만료/SAN mismatch/디스크 full/lock conflict/악성reparse,
  broker pipe spoof/unauthorized client/script injection/approval replay 차단.
- Installer clean install/재설치/update rollback/uninstall/orphan cleanup. 자기 자원 이외 변화 없어야 함.
- Central PARTIAL1 → 실제 CHECK → Evidence ACK → Result ACK → Completion ACK,
  다음 FULL64. 단위 Mock 통과를 실제 서비스/Windows E2E로 승격하지 않음.
- HARDEN 검증은 기존 explicit approval/FAIL 조건·보호 snapshot/rollback에 한정해 별도 격리 VM 단계에서만.
  본 설계 작업은 실제 점검/하드닝/OS 설정 변경을 수행하지 않는다.

완료 게이트: 권한표 실측 완료 → 공통 contract 승인 → service identity/DPAPI 검증 →
설치/수송/read-only CHECK lifecycle → 사용자 scope coverage →
보안 테스트/업데이트·제거 복구 → 제품 지원범위·서명 릴리스 승인.

