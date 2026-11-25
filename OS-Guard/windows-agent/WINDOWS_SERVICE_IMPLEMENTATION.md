# Windows 로컬 Service / 개발용 Installer 구현 결과

작성: 2026-10-27. 기반 HEAD: d774d7d. **개발용·무서명·운영 배포 금지**.
실제 추가 코드는 agent/windows_service/, packaging/, service_host.spec/service_setup.spec, build-service.ps1,
tests/test_windows_service.py에 한정한다. 기존 CHECK/HARDEN/Core/Central 코드 및 wire 수정 없음.
기존 설계 문서·diagnostics 자료는 그대로 보존했다.

## 1. 구현한 것과 닫아둔 것

| 기능 | 현재 상태 |
|---|---|
| Native SCM host | StartServiceCtrlDispatcherW/RegisterServiceCtrlHandlerExW/SetServiceStatus로 START_PENDING/RUNNING/STOP_PENDING/STOPPED 구현 |
| 자동 시작 | SCM AUTO_START 구성. 사용자 콘솔/로그인 세션의 foreground에 의존하지 않음. 실제 로그아웃/재부팅은 VM 미검증 |
| 실패 recovery | 재시작 30초, 120초, 이후 NONE / reset 24시간인 개발용 설정. reboot/외부 command action 없음 |
| 종료 | stop event, 진행 중 bounded 읽기/전송 완료 대기, STOP_PENDING checkpoint 갱신. state close 후 STOPPED |
| 연결 장애 | 기존 CentralAgent의 Heartbeat/Inventory만 선택적으로 재사용. bounded exponential wait·Retry-After, 인증/TLS 실패는 BLOCKED 유지 |
| Credential/outbox | 기존 CurrentUser DPAPI/ProtectedState 재사용, 서비스 SID ACL 주입. 기존 작업/미ACK 데이터 삭제·retag 없음 |
| 계정 후보 | virtual / local-service 중 명시 선택. 운영 기본 계정 미확정, LocalSystem 설치 옵션 없음 |
| 로컬 설치 UI | 개발용 설치 EXE, UAC requireAdministrator, 후보 선택/무서명 개발 동의, 고정 서비스/경로만 구성 |
| 파일/ACL | Program Files 코드 read/execute, ProgramData 제품 state write; SYSTEM/Administrators 및 고유 service SID DACL |
| 같은 버전 재설치 | 코드 hash·SCM binding·계정이 같은 경우 멱등 확인, 기존 state 덮어쓰기 없음 |
| 업데이트 | 코드 digest/계정이 다르면 승인된 migration 필요로 거부. 자동 업그레이드는 미구현 |
| 제거 | 서비스 중지/제거 및 검증된 제품 코드 경로만 제거. 예상 외 파일·빈 디렉터리 있으면 보존/거부. state·credential·CA·Central 등록 자동 삭제 없음 |
| 설치 실패 복구 | 이번 transaction이 새로 만든 서비스/제품 root만 정리. 중지 실패 시 파일/state 보존 |
| 로컬 Preflight | OS/계정 SID+service SID/SCM 설정/권한 관측/manifest/hash/제품 경로 atomic IO/DPAPI reload/TLS 준비 |
| 승인 전 게이트 | ready=null, LOCAL_ONLY_POLICY_UNAPPROVED. 새로운 Central report/Preflight READY 판정 없음 |
| CHECK/HARDEN | 서비스에서 Claim/CHECK/HARDEN 호출 없음. checker callback도 명시 거부. broker는 이번에 설치/구현하지 않음 |
| 자동 onboarding | registration token 전달·CA trust 등록·자동 Enrollment 모두 비활성화 |

SCM RUNNING은 프로세스가 살아 있다는 뜻이며 Online/CHECK-ready/Preflight PASS를 의미하지 않는다.
transport_enabled=false가 설치 초기값이다. 서비스는 로컬 관측을 남기고 대기한다.
명시적으로 운영 연결 설정을 제공하는 개발 경로도 기존 HB/Inventory만 사용하며 CHECK는 열리지 않는다.
기존 API health=READY 의미를 신규 commercial readiness로 바꾸지 않았다.

## 2. 계정·DPAPI 보안

- virtual 후보: NT SERVICE\\OSGuardAgentDev. LocalService 후보: NT AUTHORITY\\LocalService.
- 고정 service 이름: OSGuardAgentDev. 실제 운영 이름/계정/credential lifecycle은 미승인.
- 설치 시 service SID를 켜고 required privileges를 SeChangeNotifyPrivilege로 제한한다.
  SeRestore/SeDebug/SeTcb/SeImpersonate 또는 관리자 그룹을 추가하지 않는다.
- runtime은 기대 account SID와 고유 service SID token membership을 확인한다.
  Administrator로 직접 시작한 probe가 service credential 저장 검증을 대신하지 못한다.
- Native token query로 4개 민감 privilege의 present/enabled를 로컬 관측한다.
- state는 실제 서비스 identity에서 DPAPI protect/unprotect한다. 다른 계정 blob 복사,
  LOCAL_MACHINE scope 전환, plaintext fallback 없음.
- dpapi-probe.dpapi는 테스트용 비밀만 사용하고 기존 ciphertext를 유지한다.
  재시작/재부팅 전후 existing_probe_sha256과 reload 성공으로 동일 자료의 해독 여부를 비교할 수 있다.
- LocalService는 다른 LocalService 서비스와 동일 user context를 공유한다.
  고유 service SID DACL은 접근 범위를 좁히지만 독립 DPAPI user identity라고 주장하지 않는다.
- 가상 계정 profile/DPAPI의 실제 reboot lifecycle은 VM 검증 전이다.
- 유효한 기존 state와 active attempt가 있더라도 서비스는 아직 Claim/resume CHECK를 하지 않는다.
  정책 승인 후 reconciliation 경로를 연결해야 하며 과거 작업을 임의 성공/폐기하지 않는다.

## 3. 빌드와 실제 산출물

기존 build/.venv의 PyInstaller 6.22.3을 사용하며 새 dependency는 설치하지 않았다.
개발 PC: Windows 11 Education / Build 26100 / Python3.14.7 x64.
Server2022 호환성/프로필/서비스 실측을 이 빌드 성공으로 대신하지 않는다.

개발 빌드 명령:
```powershell
.\build-service.ps1
```

산출물:
- dist/os-guard-agent-service/os-guard-agent-service.exe 및 _internal/
- dist/os-guard-agent-dev-setup/os-guard-agent-dev-setup.exe 및 _internal/
- dist/os-guard-agent-dev-setup.zip (설치 폴더 전체 전달용)
- build/service-payload.zip (빌드 내부용)
- 승인 manifest JSON을 service runtime data asset에 포함한다.
- 초기 onefile 시험 산출물은 build/obsolete-service-setup-onefile.exe에 보관했다.
  이 파일은 사용하지 말고 위 **onedir 설치 폴더 전체**를 사용한다.

setup EXE만 단독 복사하면 안 된다. ZIP을 완전히 해제하고 EXE를 실행한다.
서비스는 onedir이며 임시 onefile extraction에 의존하지 않는다.
설치기도 상승 프로세스의 임시 onefile DLL extraction을 피하도록 onedir로 구성했다.
무서명 개발 폴더는 신뢰한 전달/쓰기 제한된 staging이 필요하다.
checksum은 서명/신뢰 root가 아니다. 상용 publisher 서명·MSI/WiX·B2 package gate는 미구현이다.

## 4. 격리 VM에서만 실행할 실제 절차 (개발 PC에서는 실행하지 않음)

개발용 설치 가드:
비도메인 Windows Server2022 Build20348 / ProductType3 / AMD64.
다른 OS/DC/도메인 가입 또는 조회 불명은 설치하지 않는다. 제품 지원 승인 범위 확대가 아니다.

1. VM snapshot·원래 서비스/제품 경로 부재를 확인한다.
2. ZIP 전체를 신뢰한 경로로 전달하고 압축을 푼다.
3. os-guard-agent-dev-setup.exe 실행 → UAC 승인.
4. virtual 또는 local-service 후보를 명시 선택하고 무서명 개발 동의 체크.
5. 로컬 서비스 설치 버튼 클릭. 기존 credential을 복사하지 않는다.
6. Windows 서비스 관리 UI에서 OSGuardAgentDev의 시작/중지/재시작을 확인한다.
7. ProgramData/OS Guard Development Agent/logs/service-status.json에서 관측을 확인한다.
8. 로그아웃/RDP 종료 전후, 재부팅 전후 서비스 PID/상태와 DPAPI reload·기존 probe hash를 비교한다.
9. 동일 후보/동일 패키지 재설치 시 ALREADY_INSTALLED_STATE_PRESERVED 확인.
10. 제거 버튼은 서비스와 코드만 제거한다. state/credential은 그대로 남는다.
    보존 state가 남은 환경의 깨끗한 재설치는 승인된 계정/profile/migration 정책 전까지 거부한다.
11. 다른 후보를 시험할 때 기존 state를 임의 삭제/이전하지 말고 별도 clean VM 또는 원래 snapshot을 사용한다.

실제 로컬 위치는 Windows Known Folder API로 결정하며 환경변수 ProgramFiles/ProgramData를 신뢰하지 않는다:
- Program Files/OS Guard Development Agent: 서비스 EXE, manifest, 설치 marker, service-local.json.
- Common AppData/OS Guard Development Agent: probe/, runtime/, logs/.
- runtime/central-state.dpapi: 향후 해당 서비스 계정에서만 provisioning된 운영 state 사용.

개발자용 읽기 진단은 python -m agent.windows_service --preflight --config <service-local.json>.
기대 서비스 identity가 아니면 DPAPI probe는 SKIP하며 다른 계정 자료를 쓰지 않는다.
최종 고객에게 Python 명령을 요구하는 설치 흐름은 아니다.
--probe-tls는 공개 CA와 검증된 설정이 준비된 경우 인증 없는 TLS handshake만 수행한다.
인증 토큰/Enrollment/CA import를 수행하지 않는다.

## 5. 로컬 설정의 한계

설치기는 service-local.json을 생성하지만 중앙 주소/CA/registration token을 넣지 않는다.
transport_enabled=true와 central_config를 승인된 관리자가 구성하는 개발 경로가 있다.
이 경우 설정 파일은 보호된 설치 root 내부여야 하며 state_dir는 해당 제품 data/runtime과 정확히 같아야 한다.
다른 Administrator state 경로를 참조하면 NO_ADMINISTRATOR_STATE_MIGRATION으로 차단한다.
운영 credential이 실제 service identity에 없으면 SERVICE_CREDENTIAL_NOT_PROVISIONED로 대기한다.
토큰을 저장/복사하거나 등록 파일을 읽어 이 조건을 자동 해결하지 않는다.
TLS 실패나 state 오류는 log code만 남기고 restart storm/credential 삭제로 해결하지 않는다.

설치/제거는 고정 SCM 이름·root·EXE·인수만 사용한다.
허용 payload inventory·hash·Manifest identity를 확인하고 ZIP traversal/ADS/link/중복 파일을 거부한다.
제품 경로 밖 삭제/공유 CA 제거/외부 service 변경/OS role 설치 없음.
설치 rollback이 service 중지 실패 등으로 끝나지 않으면 새 제품 자원도 보존하여 개발 조사 대상으로 둔다.

## 6. 직접 테스트와 미검증 항목

직접 수행:
- 신규 Mock 테스트 **35개 PASS**: service/installer/preflight/lifecycle/security boundary.
- 기존 240개 포함 전체 unittest **275개 PASS**, compileall·diff·신규 파일 whitespace 검사 PASS.
- 개발 PC의 네이티브 read-only TokenUser/LocalService SID/TokenPrivileges/SCM query 바인딩.
  OSGuardAgentDev가 없음을 확인했으며 서비스 생성은 하지 않았다.
- PyInstaller service/installer 빌드 PASS, 번들 manifest/payload checksum·64개 CHECK import 포함 확인 PASS.
  Frozen service --help 종료코드0 확인. PE manifest는 service=asInvoker, setup=requireAdministrator.
  설치 EXE Authenticode 상태는 NotSigned이며 상용 승인/실제 서비스 실행 성공으로 표시하지 않음.
- Native SCM create/config/recovery/stop는 Mock에서만 호출.
- 실제 서비스 계정 DPAPI, 로그아웃/RDP, reboot, install/uninstall는 **SKIP**.
  이유: 접근 가능한 독립 Server2022 VM/접속 정보가 제공되지 않았음.
- draft-review2 원본은 프로젝트/Downloads 및 기존 v1 ZIP에서 확인하지 못함.
  B2 경로나 DTO를 이전 초안에서 임의 승인/구현하지 않았다.

추가 VM 안전 시험:
- 두 후보를 각각 clean VM에서 install/start/stop/restart/autostart/profile/DPAPI 검증.
- Native required privileges 실제 제거 결과, service SID 접근·다른 계정 접근 차단.
- 잘못된 계정·기존 state·손상된 probe·disk full·lock·reparse·zip tamper·start 실패.
- SCM crash 두 번 재시작/세 번째 NONE, 수동 정상 stop는 recovery를 일으키지 않는지.
- TLS/auth 오류는 local BLOCKED, network/429는 중단 가능한 backoff인지.
- 서비스 stop 중 Inventory 기존 timeout 읽기와 ACK가 끝날 때까지 checkpoint 보고.
  installer는 최대150초 관측 대기하며 강제 kill하지 않는다.
- 제거의 예기치 않은 파일/빈 폴더 보존, rollback 실패 자원 보존.
- 기본 서비스 경로가 W47/SPI/W62/Claim/HARDEN을 호출하지 않음.
- 프로브 PASS가 실제 commercial READY로 전송되지 않음.

## 7. Central B2-4~5와 합의·연동할 입력/API

현재 유지하는 운영 wire: 기존 /agent-api/v2/heartbeat와 /inventory 및 ACK.
Foreground Enrollment/Claim/Result/Evidence는 기존 코드에 보존되어 있지만 새 서비스에서는 호출하지 않는다.

승인 후 필요한 계약:
1. 서명된 Windows package descriptor: package_id/version/digest/signer·검증 key/manifest/schema/module/support/arch.
2. installation session의 실제 create/download/report API·권한/nonce/expiry/단일 전달/ReportAck DTO.
3. registration secret과 bootstrap(public CA/fingerprint/URL/server binding)의 안전 분리/인계 형식.
4. 실제 service identity_ref·DPAPI reload receipt·소비/응답유실/re-enrollment/old job 보존 정책.
5. CA bootstrap·Trust Store scope·rotation/overlap. installer Administrator ROOT을 서비스에 자동 복사하지 않음.
6. Preflight catalog/version/freshness/challenge와 readiness/typed diagnostics의 endpoint·멱등·오류 표준.
7. Signed CHECK Ticket wrapper/JWS/key rotation/replay/lease/identity/scope/local policy.
   승인되기 전 service CHECK 활성화와 신규 privileged broker 설치는 금지.
8. 운영 계정/프로필/default 선정, 서비스 이름, 서명/MSI/update/uninstall/decommission 정책.

계약 파일을 받으면 먼저 DTO/endpoint/보안 gate를 대조한 뒤 연결한다.
지금 로컬 observation JSON은 상용화 공통 report DTO 또는 Agent API payload가 아니다.

