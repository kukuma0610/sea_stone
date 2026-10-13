# Central 연동 계층 (WAC-01~13 / CC-01~04)

기준: 제공된 `agent-integration-contract (3).md`, `cc-implementation (3).md`,
`agent-contract-review-summary (3).md`, `windows-agent-change-request (4).md`.
과거 WAC의 즉시 credential 폐기 설명보다 CC-01 grace 계약을 우선한다.

`agent.central.CentralAgent`와 `python -m agent.central`이 실제 연결 경로다.
기존 `agent.client.AgentClient/MockApi`는 기존 개발용 테스트 호환 경로로 보존한다.
로컬 64개 CHECK, local_runner, AgentCore, 승인 기반 Hardening은 변경하지 않는다.
중앙 capability는 CHECK만 제공한다.

## 실제 실행 전 필요한 입력

- CHECK에는 승인된 Windows 릴리스 local manifest가 필요하다. 이제
  agent/central/manifest-windows-64-2026-v1.json을 배포 소스에 함께 포함한다. 등록/online은 승인된
  platform=windows, module_version=windows-2026.1, manifest_id=manifest-windows-64-2026-v1을 보고한다.
  이 등록 identity는 지원 OS 범위를 확대하거나 CHECK 실행 manifest를 대체하지 않는다.
- 정상 공개 CA와 별도 신뢰 경로로 확보한 DER SHA256 지문.
- Central이 발급한 민감 registration JSON. 원문 token은 argv/config/로그에 넣지 않는다.
- 같은 Windows 실행 계정의 전용 state 디렉터리. Service/Installer/계정 선택은 미합의다.

`central-config.example.json`은 수정해야 하는 비밀값 없는 예시이며 실행 가능한 배포 설정이 아니다.
manifest는 schema_version=1.0, platform=windows, 승인된 manifest_id/module_version,
supported_os의 family/version/build/architecture, 64개 items를 요구한다.
각 item은 실제 W-code, `module=agent.checks.wXX`, implemented=true, actions=[CHECK]를 사용한다.
로컬 파일의 module 문자열은 검증만 하며 동적 import/원격 파일 실행에 사용하지 않는다.
이번 CHECK Manifest는 사용자 승인 identity와 64개 실제 mapping을 사용한다.
지원 범위는 WINDOWS / 10.0.20348 / Build 20348 / AMD64로 제한한다.
동일 Build 내 모든 역할/에디션/도메인 구성의 검증 완료나 모든 항목의 자동판정을 뜻하지 않는다.
Central의 실제 seed 내용은 이번 작업에서 직접 조회하지 않았으므로 실제 Task identity/기준 snapshot과
E2E 단계에서 최종 확인한다. KISA criteria projection은 로컬 실행 manifest와 별개다.

## 실제 CHECK 실행 manifest 경로

run/once의 config에서 manifest_file을 생략하면 agent/central에 함께 배포한 승인 JSON을 자동 사용한다.
명시한 manifest_file이 없거나 잘못되었으면 자동 fallback하지 않고 차단한다.
상대 경로는 config 파일 디렉터리 기준이다. 사용자에게 JSON을 작성하게 하지 않는다.
예시 config의 C:/OSGuard/manifest-windows-64-2026-v1.json을 사용하려면 승인 파일을 그 위치로 복사하거나,
실제 저장소의 절대 경로를 설정한다. 기존 파일을 확인 없이 덮어쓰지 않는다.

```powershell
# manifest_file을 생략한 기존 등록용 config도 기본 승인 JSON을 사용한다.
python -m agent.central run --config C:\OSGuard\central-config.json
```

무작업이면 Heartbeat/Inventory 후 Claim 204를 정상 처리하고 대기한다.
실제 Task는 동일 manifest_id/module_version이어야 하며 기존 CHECK 모듈만 실행한다.
os-guard-local-check.exe는 Central Agent가 아니다. 향후 별도 EXE 패키징에서는 이 JSON을
agent/central의 data asset으로 함께 포함해야 하며, 이번 작업은 소스 배포 파일/기본 경로를 제공한다.

## 공식 foreground 명령

프로젝트 windows-agent 디렉터리에서 실행한다. 실제 중앙/VM에서는 이번 개발 중 실행하지 않았다.

```powershell
python -m agent.central enroll --config C:\OSGuard\central-config.json --registration-file C:\OSGuard\registration.json
python -m agent.central online --config C:\OSGuard\central-config.json --once
python -m agent.central online --config C:\OSGuard\central-config.json
python -m agent.central once --config C:\OSGuard\central-config.json
python -m agent.central run --config C:\OSGuard\central-config.json
python -m agent.central rotate --config C:\OSGuard\central-config.json
python -m agent.central recover-rotation --config C:\OSGuard\central-config.json
```

처음 공개 CA를 등록할 때만 enroll에 `--trust-ca`를 명시하면 지문 검증 후 **현재 사용자 ROOT**에 등록한다.
자동 관리자 권한 상승/LocalMachine trust 변경은 하지 않는다. CA 등록은 OS 신뢰 변경이므로
신뢰한 관리자 전달 경로를 확인한 뒤 명시적으로 실행해야 한다.
기존 credential이 있으면 재등록을 거부하며 의도적인 교체는 `--re-enroll`로 선택한다.
Enrollment 응답 검증 및 DPAPI 저장 → Heartbeat → Inventory → inventory_version Heartbeat ACK
확인 후에만 registration 파일을 삭제한다. 실패 시 파일을 보존한다.
credential이 저장된 뒤 통신 실패한 경우 동일 enrollment_id/server_id/URL의 보호된 receipt로
운영 요청만 재시도한다. 토큰을 재사용하여 Enrollment를 반복하지 않는다.
Enrollment 응답 유실/소비 불명확/409 TOKEN_ALREADY_USED의 경우 파일 보존은 토큰 재사용 보장이
아니다. 자동 Enrollment retry 없이 Central 관리자에게 새 등록 파일 발급을 요청한다.

## 등록부터 ONLINE까지만 검증

Central 담당자에게 받은 URL, 공개 CA PEM, **별도 신뢰 경로의 DER SHA256 지문**으로
central-config.json을 준비한다. 등록 파일에 공개 CA 자체는 포함되지 않으므로 별도 제공이 필요하다.
등록/online에서는 manifest_file을 생략할 수 있다. config에는 토큰/비밀번호를 넣지 않는다.
등록 파일 자체의 CA 지문만을 신뢰하지 않고 config 지문 및 실제 공개 CA와 대조한다.
CA 신뢰 등록은 최초에 승인한 경우만 --trust-ca를 명시한다. 이후 같은 Windows 실행 계정으로
실행해야 CurrentUser DPAPI state를 읽을 수 있다. Service 실행 계정 변경 시 단순 파일 복사는 불가하다.

```powershell
python -m agent.central enroll --config C:\OSGuard\central-config.json --registration-file C:\OSGuard\os-guard-registration.json
python -m agent.central online --config C:\OSGuard\central-config.json
```

enroll은 등록과 운영 ACK 확인 후 종료한다. Central 화면 ONLINE을 유지하려면 online을 실행한다.
online은 Heartbeat/Inventory만 처리하며 Claim/CHECK/Evidence/Hardening은 호출하지 않는다.
한 주기 확인에는 --once를 사용한다. ACK는 Central 화면 ONLINE을 직접 조회한 증명이 아니므로
관리자 화면에서 등록 자산/agent identity 및 ONLINE 상태를 별도로 확인한다.
전용 진입점은 agent/central/__main__.py이며 os-guard-local-check.exe는 이 용도로 사용하지 않는다.
별도 EXE/서비스 설치는 이번 변경에 포함하지 않는다. foreground 계층과 보호 state는 분리되어 있다.

## 보호 저장·회전

기본 저장은 [CurrentUser DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
이며 LOCAL_MACHINE 플래그와 평문 fallback을 사용하지 않는다.
state 디렉터리·파일 DACL은 owner/SYSTEM으로 제한한다. symlink/reparse를 거부하며
credential/outbox/attempt/ACK는 암호화된 한 state 파일에 원자적으로 저장한다.
동시 프로세스는 전용 lock 파일로 차단한다. 계정 변경·서비스 계정 이동의 복구 정책은 OPEN이다.

rotate201 → old/new/grace 보호 저장 → new Heartbeat ACK → pending old 자료 제거 순서다.
응답 유실에서는 old를 보존하고 rotate를 자동 재소비하지 않는다.
new 확인 전 재시작은 보호 저장된 new/old 자료를 유지한다. 명시적 recover-rotation은 old 요청을
시험하며 Central received_at이 grace 이후인 경우에만 recovery 완료로 기록한다.
이미 폐기된 old는 Central이 거부한다. 토큰 원문은 콘솔에 반환하지 않는다.

## CHECK·증적·ACK·복구

Claim 전체 바인딩/버전/계획/중복/완료 목록/실행형 필드 검증 후 정확한 잔여 코드만 실행한다.
204는 정상 무작업이며 다음 poll만 새 message를 사용한다.
CC-02 server_time/duration에서 전체 RTT를 차감한 monotonic deadline을 사용한다.
worker 동안 별도 thread가 Heartbeat/lease renewal을 수행한다.
만료/갱신 실패 뒤 새 collector/신규 제출은 거부한다. 실행 중 native collector 강제 kill 정책은 OPEN이며
현재는 반환 결과를 만료 후 제출하지 않고 실행을 중단 상태로 보존한다.

모든 논리 요청은 송신 전에 고정 message_id/sent_at/payload/증적 bytes를 보호 저장한다.
Evidence hash/길이/ID ACK → Result accepted/duplicate ID ACK → COMPLETED message ACK 순서다.
응답 유실·재시작은 고정 원문을 재송신하며 이미 완료된 코드와 저장된 관측을 재실행하지 않는다.
collector 도중 프로세스가 중단된 항목은 같은 attempt에서 추측 재실행하지 않는다.
ATTEMPT_STALE이면 이전 원본을 보호 reconciliation 영역에 격리하고 다음 poll에서 새 claim을 요청한다.
이전 데이터를 새 attempt로 위장 제출하지 않는다. 격리 자료의 운영 처리 UX는 후속 작업이다.

신규 실제 Result는 canonical 상태/NOT_REQUIRED를 사용한다.
정상 수집·수동 판단 UNABLE은 COMPLETED, 실제 collector 예외는 UNABLE/FAILED로 구분한다.
모든 UNABLE을 null/PENDING으로 변환하지 않는다. 항목별 수동 리뷰 UX는 중앙과 잔여 협의한다.
CC-04의 strict boolean과 W-47 구조는 필드 이름·타입을 유지하며 실제 비밀은 마스킹한다.
전체 임의 개인정보 탐지를 보장하는 DLP로 표현하지 않는다.

Inventory는 OS/설치 역할/실행 서비스의 성공·실패를 구분하고 전체 관측을 보낸다.
설치 역할은 Windows Feature가 실제 보고한 이름이며 공통 업무 enum으로 확정하지 않는다.
CC-03 inventory_version은 Central이 계산한 응답을 다음 Heartbeat에 사용한다.
인증/바인딩/TLS/422/충돌은 자동 우회하지 않는다. 429/5xx/network만 제한 재시도한다.
retry 수치는 구성 가능한 개발 기본값이며 운영 합의 완료 수치가 아니다.

## 검증 경계

계약용 Mock HTTP·보호 저장 대역·회귀 테스트로 확인한다. 실제 Central HTTPS 왕복,
Windows DPAPI/DACL/CA 신뢰·선택 계정·승인 manifest 배포는 실환경 검증이 필요하다.
Windows Service, Installer/Uninstall, module self-update, 중앙 Hardening은 구현 범위가 아니다.
