# Windows Server 2022 검증 준비 계획

작성일: 2026-10-14. 대상 HEAD: d774d7d8bf0bf492d66a57052088f1aa9fb2f0d4.
설계/권한표: COMMERCIALIZATION_DESIGN.md, WINDOWS_PERMISSION_REVIEW.md.
이 문서는 실행 준비 자료다. 서비스/계정/OS 정책/코드/wire protocol 변경 및 실제 E2E 실행 없음.
Central 공통 계약 확정 후 구현 순서는 **Windows Service → Installer → Preflight → CHECK Broker**로 유지한다.

## 0. 지금 가능한 것과 아직 불가능한 것

| 검증 | 현재 가능 여부 | 필요한 조건 |
|---|---|---|
| 일반/관리자 프로세스 local FULL64 | 기존 local_runner로 가능 | 실제 Server2022 격리 VM, 이미 승인·준비된 계정 |
| W-47 현재 호출자 비교 / W-62 CIM query | 기존 collector + 읽기 전용 조회로 가능 | 세션/실효 토큰 관측 병행 |
| 최신 Manifest PARTIAL1 Central E2E | 기존 central once/run으로 가능 | 실제 등록 상태/credential/CA/1개 CHECK 작업 |
| 실제 서비스 계정 FULL64/DPAPI 재시작·재부팅 | 아직 PENDING_IMPLEMENTATION | 계약 승인 및 SCM service host/해당 계정 provisioning |
| 저권한 IPC/CHECK Broker/Installer 보안 경계 | 아직 PENDING_IMPLEMENTATION | 단계별 구현과 승인된 VM 시험 |
| HARDEN 새 권한 경계 | 이번 검증 범위 밖 | 별도 계약/명시 승인; 기존 action 판정 변경 금지 |

foreground Python을 다른 사용자로 실행하거나 snapshot을 복사한 결과를 서비스 검증으로 인정하지 않는다.

## 1. VM 준비·보존 기준

- 격리 VM snapshot과 복원 성공 확인, 최신 소스 commit/Manifest hash 및 테스트 시각 기록.
- Windows Server2022 Build20348 AMD64 우선. edition/ProductType/domain/GPO 및 역할 상태를 기록.
- 계정 생성/role 설치/서비스 등록/privilege 부여가 필요하면 별도 관리자 승인된 fixture 단계로 분리.
  현재 단계에서는 해당 설정을 변경하지 않는다.
- 비교 중에는 OS 정책/계정 목록/역할/서비스 상태를 고정. 변경된 환경의 결과를 권한 차이로 해석하지 않는다.
- 결과는 results/의 VM 전용 보호 디렉터리, 실행 context별 별도 JSON.
  실제 결과와 Mock fixture 혼합 금지. 원문 계정/SID/StartupCommand/credential/토큰은 공유 자료에 넣지 않는다.
- 일반 계정에 결과 디렉터리 쓰기 권한이 없으면 그 계정의 승인된 제품 테스트 폴더를 사용.
  보안 정책/SAM/사용자 홈 ACL을 점검 편의를 위해 완화하지 않는다.
- live Central 등록 identity/DPAPI state는 등록한 계정에서만 사용; 권한 비교용 FULL64는 offline runner 사용.

## 2. 64개 항목 권한 검증 matrix

첨부 WINDOWS_VALIDATION_MATRIX.csv는 64개 W-code × 6개 context = 384개 **NOT_RUN** 행.
service 계정은 후보이며 실제 provisioning 후 identity SID와 profile을 기록해야 한다.

| context | 대상 | 확인 사항 |
|---|---|---|
| STANDARD_USER | 일반 인증 사용자 | 실제 TokenUser, 비상승/privileges/세션 |
| ADMIN_FILTERED | Administrators 구성원·비상승 토큰 | 소속만으로 분류하지 않고 TokenElevationType/deny-only SID 확인 |
| ADMIN_ELEVATED | UAC 명시 상승 관리자 | TokenElevation/IntegrityLevel/privileges enabled 상태 |
| LOCAL_SERVICE | 실제 LocalService 서비스 프로세스 | Session0, service SID, user profile, object ACL |
| VIRTUAL_AGENT_SERVICE | 실제 NT SERVICE\\OSGuardAgent 후보 | 관리자 그룹 미가입, SID/DACL/profile/DPAPI |
| PRIVILEGED_CHECK_SERVICE | 검증용 특권 CHECK 서비스 후보 | LocalSystem 여부 및 제한 token/privilege 목록 기록 |

내장 Administrator가 현재 UAC 구성상 filtered token을 만들지 못하면 ADMIN_FILTERED를 NOT_TESTABLE로 기록한다.
테스트를 맞추려고 UAC/AdminApprovalMode/GPO를 바꾸지 않는다. 같은 머신의 동등한 승인된 관리자 fixture를 별도로 준비한다.
[토큰 조회 필드](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class):
TokenUser, TokenGroups, TokenPrivileges, TokenElevationType, TokenElevation, TokenIntegrityLevel, TokenSessionId.

### 기존 CLI로 실행하는 기본 순서 (VM에서만, 여기서는 실행하지 않음)

프로젝트 windows-agent 디렉터리에서 계정별 별도 프로세스 실행:
```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Version,BuildNumber,OSArchitecture,ProductType,LastBootUpTime
Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain,DomainRole
whoami /priv
python -m agent.local_runner --output .\results\rights-standard.json
```

관리자 비상승/상승은 각 프로세스에서 output을 rights-admin-filtered.json / rights-admin-elevated.json으로 변경.
상승 프로세스는 사용자가 Windows UI에서 '관리자 권한으로 실행'을 명시 승인.
whoami /priv는 사전 힌트이며 Python/PowerShell child/service 실제 실행 token이 같다는 최종 증명은 아니다.
서비스 3개 context는 SCM host 구현 후 같은 runner/collector를 실제 서비스 context에서 호출하는
검증 harness를 준비해야 한다. 아직 존재하지 않는 CLI/service 이름으로 실행 명령을 만들지 않는다.

### 각 행의 필수 기록

code, context, run_id, tested_at_utc, vm_id(가명), source_commit, manifest_sha256,
OS/version/build/edition/arch/domain/role, process bitness, user identity(가명), session_id,
elevation/elevation_type/integrity, required privilege present/enabled,
collector_success, status(PASS/FAIL/NA/UNABLE), reason_code/error_reason,
manual_review, target_count/expected_count/excluded_count/coverage,
native error code 또는 HRESULT(확보 가능한 경우), masked evidence 저장 경로.

기존 CHECK JSON에는 없는 token/coverage 필드는 **별도 로컬 검증 기록**에만 둔다.
wire/Result 필드를 임의 추가하지 않는다. 기존 error_reason에 native code가 없으면 확인 안 됨으로 기록,
정확한 errno/HRESULT를 추측하지 않는다. 실패 한 항목 때문에 뒤 항목이 중단되지 않았는지 확인.

권한 차이 / 정상 manual_review / 역할 미적용 / policy absent / 구현 coverage 오류를 구분.
ELEVATED가 UNABLE을 반환했다고 LocalSystem 권한을 바로 부여하지 않는다.
같은 target coverage를 확인한 뒤 필수 읽기 ACL/privilege를 결정.
표준권한에서 성공한 일부 목록을 전체 커버리지 성공으로 확정하지 않는다.

## 3. W-47 실제 사용자 세션 검증

현재 함수 screen_saver_inventory는 HKCU 및 현재 호출자의 SystemParametersInfoW GET이다.
서비스 context에서 같은 값이 나와도 로그인 업무 사용자 설정을 읽었다고 가정하지 않는다.

1. 기준 사용자 A/B의 로그인·RDP·disconnected/locked 상태와 session_id를 기록.
2. 해당 사용자 프로세스에서 local_runner를 실행하고 W-47의 sources/effective/current_user 증적 추출.
3. HKCU Control Panel\\Desktop 및 HKCU/HKLM SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop의
   ScreenSaveActive/ScreenSaverIsSecure/ScreenSaveTimeOut를 존재/부재/오류 및 REG_SZ 타입으로 읽기 대조.
4. 서비스 구현 후 service context의 동일 CHECK를 실행하고 service SID/Session0/SPI 호출자를 기록.
5. 서비스 사용자의 데이터가 A/B 결과로 보고되면 scope 검증 FAIL. 기존 FAIL 판정을 조용히 PASS/NA로 변경하지 않는다.
6. 사용자 없음, 다중 RDP, 같은 사용자 여러 세션, 사용자별 GPO, 비활성/미로드 profile을 각각 측정.
7. 사용자 세션 collector를 향후 검토할 때 read-only GET만 허용하고 target SID/session binding을 확인.
   impersonation만으로 HKCU/SPI/desktop 대상이 모두 일치한다고 가정하지 않는다.

이 단계의 기대값은 '어떤 사용자를 읽었는지 확인'이지 PASS 강제 전환이 아니다.
현재 수동검토 분기는 유지. Central의 사용자 범위/집계 규격 합의 전 per-user Result wire 변경 금지.
읽기 위해 hive load, 자동 로그인, 화면보호기 값 설정, 사용자의 세션 전환을 임의 수행하지 않는다.

## 4. W-62 SeRestorePrivilege 검증

[Win32_StartupCommand 공식 요구](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-startupcommand):
호출 프로세스는 SeRestorePrivilege가 필요하다. 현재 collector는 privilege를 검증/활성화하지 않는다.

1. 각 context에서 실제 token에 SeRestorePrivilege가 있는지/활성화됐는지 기록.
2. 현재 collector가 실행하는 PowerShell child의 token도 가능하면 관측; parent의 privilege만으로 추정하지 않음.
3. 기존 local FULL 결과 W-62와 아래 읽기 조회의 성공/오류/개수를 대조:
```powershell
whoami /priv
(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | Measure-Object).Count
(Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction Stop | Measure-Object).Count
```
4. raw Command/arguments/UserSID는 외부 보고 자료에 저장하지 않는다.
   fixture의 알려진 항목이 실제 목록에 포함되는지 로컬에서 대조하고 최소 마스킹 식별자/개수만 기록.
5. privilege 없음, 있음+disabled, 있음+enabled를 구분해 측정한다.
   enabled variant가 현재 token에 없으면 NOT_TESTABLE이며 자동 권한 부여로 만들지 않는다.
6. 향후 broker privilege 활성화 시험은 별도 승인된 test harness에서 현재 보유 token만 대상으로 진행.
   OS 사용자 권한/GPO를 변경하거나 통신 서비스 전체에 SeRestore를 주지 않는다.
7. 성공한 조회도 SYSTEM/User/HKU 및 실행 계정의 가시성을 확인해야 한다.
   현재 W-62는 업무 필요성 수동검토이므로 수집 성공과 보안 판정을 분리한다.

## 5. 실제 서비스 계정 CurrentUser DPAPI 검증 (서비스 구현 후)

[DPAPI 계약](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)에 따라
같은 runtime identity에서 protect/unprotect한다. 다른 계정 blob 복사/LOCAL_MACHINE fallback 금지.

| 시험 | 절차 | 합격 조건 |
|---|---|---|
| 최초 보호 저장 | service 계정으로 기존 DPAPI/ProtectedState를 별도 test state에 호출, 비실제 비밀 probe 사용 | 보호 파일에 평문 없음, 정확한 재로드 |
| 프로세스 재시작 | 서비스 종료/같은 identity 재시작 | 정상 복호화 및 process lock 해제/재획득 |
| 로그아웃 | installer Administrator와 일반 사용자가 로그아웃한 뒤 확인 | 서비스 유지, 같은 DPAPI state 사용 |
| 재부팅 | 승인된 격리 VM 재부팅 후 서비스 자동 시작 | 같은 account/profile로 재로드·운영 HB ACK |
| 타 계정 접근 | 일반 사용자/다른 service context에서 test blob 접근 | DACL/DPAPI 실패; plaintext fallback 없음 |
| installer 소유 경로 | installer-created 디렉터리에서 runtime SID 접근 확인 | owner-only DACL이 runtime을 차단하는 오류 탐지 |
| 계정 변경 | 별도 fixture에서 새 서비스 identity로 기존 test state 접근 | 자동 복구/권한 완화 금지, controlled re-enrollment 안내 |
| 회전 장애 | Mock로 저장 전/저장 후/새 credential ACK 전후 장애, 이후 승인된 실제 회전 시험 | new 보호→new 성공 요청→old 폐기; 응답 유실 old 보존 |
| 동시 runtime | 같은 test state를 두 instance가 열기 | 두 번째 차단, state/outbox 손상 없음 |

계정/provisioning과 서비스 자동 시작 기능은 현재 없다. 이 계획을 실제 완료로 표시하지 않는다.
현재 실제 credential에 대해 계정 변경/서비스 삭제/profile 삭제를 실험하지 않는다.
test용 등록 자산과 state를 따로 사용; 실제 운영 token을 로그/CLI/environment로 전달하지 않는다.
outbox/receipt/agent binding도 재시작 후 일치하는지 확인. stale lease는 재조회한다.

## 6. Service/Installer 구현 준비와 보안 경계

공통 계약 승인 전 API/코드 구현 없음. 이후 순서는 사용자 지정대로:

1. Windows Service: SCM lifecycle/STOP/recovery/automatic start를 구현.
   저권한 runtime 계정 SID·프로필·DPAPI 및 기존 Central orchestration을 검증.
   아직 권한 broker가 없는 동안 elevated CHECK를 저권한 service가 완전 지원한다고 표시하지 않는다.
2. Installer: 서명된 Agent/manifest/CA·Program Files readonly·ProgramData runtime SID ACL,
   설치 UAC 동의·실제 service 계정 registration 인계·업데이트/제거 ownership을 구현.
   모든 사람이 수정 가능한 exe/module/config/pipe를 SYSTEM이 신뢰하지 않도록 한다.
3. Preflight: 등록 token 사용 전 OS/identity/manifest/TLS trust/DPAPI/store/readiness 검증.
   role/GPO/보안정책을 무승인 변경하지 않고 구체적 조치를 안내.
4. CHECK Broker: local fixed allowlist mapping·IPC SID ACL·remote client 거부·size/timeout/lease binding.
   network token/임의command/외부script/변경 경로를 전달하지 않는다.
   필요 privilege는 계정별 실측 결과로 결정.
5. 별도 HARDEN 경계는 기존 동작을 변경하지 않은 채 추가 계약 승인 단계에서 검토.
   최초 설치 동의와 조치 승인은 별개이며 통신 service의 approved=true만 믿는 구조 금지.

보안 시험: unauthorized pipe client/가짜 service process/manifest 변조/service binary path hijack,
credential state ACL/reparse, 승인지연·replay·변경값 mismatch, read-only boundary,
stop·crash·network offline·disk full/업데이트 롤백.
LocalSystem broker는 고신뢰 구성요소이며 악성 SYSTEM으로부터 credential을 완전히 보호하는 경계는 아니다.

## 7. 최신 Manifest PARTIAL CHECK 1개 실제 E2E (지금 기존 CLI로 가능)

### 사전 조건

- 해당 VM에서 등록 성공한 **같은 Windows 계정**으로 실행. 다른 계정에 DPAPI state 복사 금지.
- 사용자 보고 ONLINE baseline과 실제 Central 등록 자산/server_id/agent_id를 확인.
- repo 최신 소스 d774d7d 이상 또는 검증한 해당 release와 함께 실제 JSON 배포.
- manifest schema1.0/platform windows/module_version windows-2026.1/
  manifest_id manifest-windows-64-2026-v1, 64개 mapping 및 지원 OS 일치.
- config에 manifest_file이 명시됐으면 그 경로 파일이 존재해야 한다.
  잘못된 명시 경로는 기본 경로로 fallback하지 않는다.
  키를 생략하면 agent/central에 포함된 승인 파일을 사용한다.
- 승인 CA fingerprint/실제 trust/URL/SAN, 올바른 protected state 경로 유지.
- 이 Agent가 받을 다른 pending CHECK/HARDEN 작업이 없어야 한다. Central의 task scope를 직접 확인.

### 실행 순서

windows-agent 디렉터리에서:
```powershell
git rev-parse HEAD
python -c "import json; from pathlib import Path; from agent.central import __main__ as entry; from agent.central.contract import Manifest; p=Path(entry.__file__).with_name('manifest-windows-64-2026-v1.json'); m=Manifest(json.loads(p.read_text(encoding='utf-8'))); print(m.id, m.version, len(m.items))"
python -m agent.central online --config C:\OSGuard\central-config.json --once
```

기본 파일 출력은 manifest-windows-64-2026-v1 / windows-2026.1 / 64.
명시 manifest_file을 사용하는 경우 그 파일도 따로 읽어 동일 identity를 확인한다.
원격 task의 criteria_snapshot_id는 Central 값 그대로여야 하며 로컬에서 생성하지 않는다.

1. Central UI의 기존 작업 생성 기능에서 테스트 자산에 **PARTIAL, item_ids=[W-02]** 1개 CHECK 생성.
   중앙에 seeded된 동일 manifest/module·Windows family·기준 snapshot을 선택.
   planned_item_count=1, 신규 attempt의 completed_item_ids=[]를 확인.
2. 같은 계정에서 실행:
```powershell
python -m agent.central once --config C:\OSGuard\central-config.json
```
3. job이 아직 없으면 정상 204 및 No task (204). 성공으로 위장하지 않고 작업 발행/대상 binding을 확인.
4. 작업이 있으면 기존 W-02 Guest collector가 실제 호출되고 Evidence → Result → COMPLETED ACK 순서.
   출력 CHECK completion ACK verified는 전송 흐름 ACK이지 KISA PASS 자체가 아님.
5. Central에서 job_id/attempt_id, item_ids=[W-02], 실제 masked evidence, result/evidence ID 참조,
   canonical status·manual_review·error 및 COMPLETED를 확인.
6. 임의로 Guest 설정을 바꾸지 않고 실제 local W-02 결과와 비교.
   Guest 계정 미발견/권한 오류면 실제 UNABLE 그대로 평가. 근거 없는 Mock/PASS 대체 금지.
7. Central 완료 후 동일 테스트 작업을 재발행/재태깅하지 않고 중복 result/evidence 미생성 확인.
   이후 원하는 상시 실행은 run이지만 다른 pending job을 받을 수 있으므로 첫 시험은 once 사용.

증적 기록: 소스/manifest hash → ONLINE → Central PARTIAL 작업 대상/범위 →
masked Evidence/Result 및 identity binding → Completion ACK.
Central 로그/DB/UI의 기존 허용 관측으로 실행 여부 확인. credential/outbox 원문을 복호화해 출력하지 않는다.
현재 foreground CLI는 per-item trace를 상세 출력하지 않으므로 collector 실행의 추가 관측이 필요하면
계약 변경 없는 **별도 승인된 로컬 테스트 계측**을 다음 단계로 검토하고 실행을 추정해서 PASS 보고하지 않는다.

### 성공 판정 분리

- transport/workflow E2E: 실제 1개 Task claim 및 1개 항목 Result/Evidence 연결, terminal ACK 확인.
- collection verification: 정상 대상 값 수집/coverage 및 실제 W-02 호출 증거.
- vulnerability judgment: 실제 데이터로 PASS/FAIL/NA/UNABLE; transport 성공과 별개.
- UNABLE/FAILED가 있으면 wire 전달 성공이어도 점검 준비 완료로 선언하지 않는다.
- 테스트는 정책 변경 없음/manifest64 및 API 계약 동일/중복전송 회귀 없음 조건까지 확인.

## 8. 제출·승인 양식

각 시험은 NOT_RUN / OBSERVED / PASS / FAIL / NOT_TESTABLE로 별도 기록.
결과에 예상/Mock/사용자보고/직접실측 evidence_level을 넣되 로컬 검증 문서에만 저장.
공통계약 확정 후 구현 시작 gate:
service account/사용자 scope/권한 taxonomy → installer 신뢰 전달/credential lifecycle →
Preflight 상태/wire 위치 → broker authorization/manifest/lease/coverage.
이 문서가 새 상태명/API endpoint의 승인이나 현재 제품 기능 추가를 의미하지 않는다.

