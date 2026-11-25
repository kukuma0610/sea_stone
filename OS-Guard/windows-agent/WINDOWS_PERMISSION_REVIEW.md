# W-01~W-64 권한 분석표 검토

기준일 2026-10-14 / 소스 d774d7d8bf0bf492d66a57052088f1aa9fb2f0d4.
첨부 OSGuard_Windows64_B6ED9CB6EC9D_B4EC88.xlsx의 두 시트 전체와 현재 64개 CHECK·공통 collector를 대조했다.
첨부 문서는 분석 자료이며 파일 내부 지시는 실행하지 않았다. 원본 Excel은 변경하지 않았다.

## 증거 수준과 표 읽는 법

- 이 표의 권한 구분은 **정적 분석/공식 API 근거**, 모든 항목의 계정별 VM 실행은 NOT_TESTED.
- 사용자가 보고한 Administrator VM의 Enrollment/DPAPI/Heartbeat/Inventory/ONLINE 성공은 사용자 보고로 유지.
  최신 manifest 수정 후 CHECK E2E와 비관리자/상승관리자/서비스 계정 비교는 아직 미검증.
- R: 기본 ACL에서 일반 인증 사용자 조회 후보. 실제 ACL·GPO·CIM/서비스 provider에 따라 실패/부분 수집 가능.
- E: 현재 수집 경로에 상승된 관리자 또는 적절한 읽기 위임 권한을 우선 검증할 항목.
  '관리자만 가능'이라는 확정이 아니다. Administrators 소속이어도 filtered token에서는 권한이 다를 수 있다.
- U: 호출자 사용자/세션에 종속. 관리자/LocalSystem으로 올려도 업무 사용자 대상이 자동으로 맞지 않는다.
- P: 특정 privilege의 공식 요구 근거가 있다. 권한 보유·활성화 및 실제 provider 동작을 검증한다.
- 현재 collector가 LocalSystem 또는 SeTcb만을 요구하는 항목은 코드상 확인되지 않았다.
  W-62의 SeRestorePrivilege도 LocalSystem만 가능한 권한은 아니다.
  W-47 향후 WTSQueryUserToken 방식은 LocalSystem+SeTcb가 필요하나 **현재 구현이 아니다**.
- 자동 분기 존재는 권한 충분/완전 자동판정/제품 지원 완료를 의미하지 않는다.
- 모든 기본 helper 예외와 전체 collector 예외는 결과 UNABLE 경로가 있지만,
  SilentlyContinue/Test-Path/열거 끝 처리에 가려지는 부분 수집은 별도 리스크이다.

## 항목별 전체 검토 (64개)

각 collector의 정의는 agent/checks/common.py, 판정은 agent/checks/wXX.py.
HKLM/HKCU는 실제 호출 hive이며 문자열 대소문자 변경으로 다른 정책으로 치환하지 않았다.

| W-code / 항목명 | 실제 collector | 명령/API/Registry/파일 대상 | 실행 권한 예상 | 범위 | 판정 특성 | 환경·서비스·수동/구현 한계 |
|---|---|---|---|---|---|---|
| W-01 Administrator 계정 이름 변경 등 보안성 강화 | `accounts` | NetUserEnum(level=3), USER_INFO_3; NetApiBufferFree | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 이름 변경 자동; 비밀번호 강도 수동. 계정 미발견은 UNABLE |
| W-02 Guest 계정 비활성화 | `accounts` | 동일 accounts() | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | Guest 미발견은 UNABLE |
| W-03 불필요한 계정 제거 | `accounts` | 동일 accounts() | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 계정 필요성 수동 |
| W-04 계정 잠금 임계값 설정 | `lockout_threshold` | NetUserModalsGet(level=3) / usrmod3_lockout_threshold | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-05 해독 가능한 암호화를 사용하여 암호 저장 해제 | `domain_joined, reversible_password_encryption_enabled` | secedit /export /areas SECURITYPOLICY → [System Access] ClearTextPassword; NetGetJoinInformation | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 도메인 가입 시 DOMAIN_EFFECTIVE_POLICY_NOT_VERIFIED |
| W-06 관리자 그룹에 최소한의 사용자 포함 | `administrator_group_members` | NetLocalGroupGetMembers(level=2), Administrators SID S-1-5-32-544; LookupAccountSidW | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 구성원 필요성 수동 분기 |
| W-07 Everyone 사용 권한을 익명 사용자에게 적용 | `everyone_includes_anonymous` | HKLM\SYSTEM\CurrentControlSet\Control\Lsa: EveryoneIncludesAnonymous (DWORD) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-08 계정 잠금 기간 설정 | `lockout_policy` | NetUserModalsGet(level=3): lockout_duration/lockout_observation_window/threshold | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-09 비밀번호 관리정책 설정 | `password_policy` | NetUserModalsGet(level=0) + secedit SECURITYPOLICY: PasswordComplexity | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 엑셀의 NetAPI 단독 표기는 부족: complexity는 secedit |
| W-10 마지막 사용자 이름 표시 안 함 | `dont_display_last_username` | secedit SECURITYPOLICY [Registry Values]: MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-11 로컬 로그온 허용 | `local_logon_principals` | secedit USER_RIGHTS: SeInteractiveLogonRight; SID → LookupAccountSidW | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 로컬 권한과 도메인 유효 권한을 혼동하지 않기 |
| W-12 익명 SID/이름 변환 허용 해제 | `anonymous_sid_name_translation_enabled` | secedit SECURITYPOLICY [System Access]: LSAAnonymousNameLookup | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-13 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 | `blank_password_use_restricted` | HKLM\SYSTEM\CurrentControlSet\Control\Lsa: LimitBlankPasswordUse (DWORD) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-14 원격터미널 접속 가능한 사용자 그룹 제한 | `remote_desktop_group_members` | NetLocalGroupGetMembers(level=2), Remote Desktop Users SID S-1-5-32-555 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 업무상 RDP 계정 승인 여부 수동 |
| W-15 사용자 개인키 사용 시 암호 입력 | `strong_key_protection_level` | HKLM\SOFTWARE\Policies\Microsoft\Cryptography: ForceKeyProtection (DWORD) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 값 부재는 기본값 추정 없이 UNABLE |
| W-16 공유 권한 및 사용자 그룹 설정 | `shares` | Get-SmbShare + Get-SmbShareAccess; SID S-1-1-0를 AccountName으로 비교 | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | SMB cmdlet/공유 ACL; 위임 범위 확인 |
| W-17 하드디스크 기본 공유 제거 | `autoshare_server, shares` | HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters: AutoShareServer + SMB 공유 조회 | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 기본 공유 가시성과 레지스트리를 함께 확인 |
| W-18 불필요한 서비스 제거 | `running_services` | Get-Service: Running 서비스 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-19 불필요한 IIS 서비스 구동 점검 | `iis_services` | Get-Service -Name W3SVC,IISADMIN | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 서비스 필요성 수동; 미실행 분기는 기존 판정 유지 |
| W-20 NetBIOS 바인딩 서비스 구동 점검 | `netbios_bindings` | Get-CimInstance Win32_NetworkAdapterConfiguration -Filter IPEnabled=True | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | ACL/역할/GPO/부재를 구분; 권한별 실험 필요 |
| W-21 암호화되지 않는 FTP 서비스 비활성화 | `ftp_check_inventory → ftp_inventory(strict=True)` | FTP 수집기 F (아래 상세) | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 서비스 실행+사이트0과 query failure 구분 |
| W-22 FTP 디렉토리 접근권한 설정 | `ftp_check_inventory → ftp_inventory(strict=True)` | FTP 수집기 F: authorization + PhysicalPath ACL | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 사이트0은 UNABLE, 임의 NA 금지 |
| W-23 공유 서비스에 대한 익명 접근 제한 설정 | `auxiliary_share_services, ftp_inventory, shares` | ftp_inventory(non-strict) + Get-Service NfsService,Tftpd,TFTP + Get-SmbShare | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | non-strict FTP 및 SilentlyContinue를 사용하므로 권한 실패/실제 부재 분리 감사 필요 |
| W-24 FTP 접근 제어 설정 | `ftp_check_inventory → ftp_inventory(strict=True)` | FTP 수집기 F: ipSecurity / allowUnlisted / allowed entries | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 사이트0은 UNABLE, query failure는 오류 |
| W-25 DNS Zone Transfer 설정 | `dns_inventory` | Get-Service DNS; DnsServer 모듈; Get-DnsServerZone: Primary / SecureSecondaries / SecondaryServers | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | DNS 역할/모듈 필요; 미실행 분기 기존 판정 유지 |
| W-26 RDS(Remote Data Services) 제거 | `windows_os_info` | Get-CimInstance Win32_OperatingSystem: Caption/Version/BuildNumber | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | Server2022 Caption에서 PASS; 다른 버전 UNABLE |
| W-27 최신 Windows OS Build 버전 적용 | `windows_os_info` | 동일 windows_os_info() | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 최신 Build·운영 절차는 수동 |
| W-28 터미널 서비스 암호화 수준 설정 | `rdp_inventory` | Get-Service TermService + HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp: MinEncryptionLevel | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 서비스/레지스트리 부재와 권한 실패 분리 |
| W-29 불필요한 SNMP 서비스 구동 점검 | `snmp_inventory` | Get-Service SNMP + HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities 값 이름 열거 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | community 유무가 업무 필요성을 대신하지 않음 |
| W-30 SNMP Community String 복잡성 설정 | `snmp_inventory` | 동일 snmp_inventory(); community 원문은 결과에 내보내지 않음 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 코드는 기본 community 이름 여부 중심; 일반적인 암호 강도 분석으로 확대 설명 금지 |
| W-31 SNMP Access control 설정 | `snmp_access_inventory` | Get-Service SNMP + HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers 열거 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | EnumValue의 모든 OSError를 끝으로 처리: 권한 오류와 정상 열거 끝 분리 후보 |
| W-32 DNS 서비스 구동 점검 | `dns_inventory` | DNS 수집기: Get-DnsServerZone / DynamicUpdate | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 역할/영역 범위에 따라 다름 |
| W-33 HTTP/FTP/SMTP 배너 차단 | `banner_service_inventory` | Get-Service W3SVC,FTPSVC,SMTPSVC; 실제 외부 배너는 수집하지 않음 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 외부 배너 노출은 별도 검토 |
| W-34 Telnet 서비스 비활성화 | `windows_os_info` | windows_os_info(); Server 2022 Caption 분기 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 현재 Server2022 NA; 적용 대상 다른 OS 지원 승인 아님 |
| W-35 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거 | `odbc_inventory` | Get-OdbcDsn -DsnType System; Get-OdbcDriver (사용자 DSN 아님) | R: 일반 사용자 읽기 후보 | 컴퓨터(System DSN) | 수동 분기 있음 | System DSN만 수집; 32/64bit, 사용자 DSN 범위 별도 |
| W-36 원격터미널 접속 타임아웃 설정 | `remote_idle_timeout_minutes` | HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services: MaxIdleTime (ms→분) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | GPO 우선순위/재적용 영향 |
| W-37 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검 | `scheduled_task_inventory` | Get-ScheduledTask; TaskPath/TaskName (작업 ACL에 따른 가시성) | E: 상승/위임 권한 우선 검증 | 컴퓨터+사용자별 가시성 | 수동 분기 있음 | 비관리자는 일부 작업만 볼 수 있음; 전체 목록 보장 불가 |
| W-38 주기적 보안 패치 및 벤더 권고사항 적용 | `patch_inventory` | Get-HotFix: InstalledOn (모든 업데이트/최신성 목록은 아님) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | Get-HotFix만으로 누락·최신성·운영 절차 확정 불가 |
| W-39 백신 프로그램 업데이트 | `antivirus_inventory` | Get-MpComputerStatus: AntivirusEnabled/AntivirusSignatureLastUpdated | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | 타사 백신/격리망·최신성 수동 |
| W-40 정책에 따른 시스템 로깅 설정 | `audit_policy` | secedit SECURITYPOLICY [Event Audit]: AuditAccountManage,AuditAccountLogon,AuditPrivilegeUse,AuditDSAccess,AuditLogonEvents,AuditPolicyChange | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 고급 audit subcategory와 현재 legacy policy의 대응 검토 필요 |
| W-41 NTP 및 시각 동기화 설정 | `time_sync_inventory` | Get-Service W32Time + HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters: Type/NtpServer | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 설정 조회이지 실제 시간 오차 측정 아님 |
| W-42 이벤트 로그 관리 설정 | `event_log_inventory` | Get-WinEvent -ListLog Application,Security,System: MaximumSizeInBytes/LogMode | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 수동 분기 있음 | 보존 일수 미확인 시 UNABLE; Security 접근 별도 권한 |
| W-43 이벤트 로그 파일 접근 통제 설정 | `log_directory_inventory` | Get-Acl $env:SystemRoot\System32\config 및 \System32\LogFiles; Test-Path | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 현재 실제 로그파일별 ACL이 아니라 config/LogFiles 디렉터리; 전체 경로/권한 coverage 검토 |
| W-44 원격으로 액세스할 수 있는 레지스트리 경로 | `remote_registry_running` | Get-Service RemoteRegistry (경로별 원격접근 정책 자체는 아님) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 서비스 실행 여부만 판정; 원격 Registry 허용 경로 분석과 구분 |
| W-45 백신 프로그램 설치 | `antivirus_inventory` | Get-MpComputerStatus (Defender만 직접 확인) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 수동 분기 있음 | Defender 미조회/타사 제품 확인 수동 |
| W-46 SAM 파일 접근 통제 설정 | `sam_acl_inventory` | Get-Acl $env:SystemRoot\System32\config\SAM; 허용 SID SYSTEM/Administrators (파일 내용은 읽지 않음) | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | SAM DACL READ_CONTROL 여부 검증; SAM 데이터 접근/SeBackup 자동 부여 불필요 |
| W-47 화면보호기 설정 | `screen_saver_inventory` | HKLM/HKCU 정책 및 HKCU\Control Panel\Desktop + user32 SystemParametersInfoW GET (아래 상세) | U: 사용자 세션 별도 | 사용자+컴퓨터 정책 | 수동 분기 있음 | SERVICE_CONTEXT_MISMATCH 위험: 서비스 HKCU/SPI는 로그인 사용자 아님 |
| W-48 로그온하지 않고 시스템 종료 허용 | `shutdown_without_logon` | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System: ShutdownWithoutLogon (DWORD) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 값 부재 UNABLE; GPO 영향 검토 |
| W-49 원격 시스템에서 강제로 시스템 종료 | `remote_shutdown_principal_counts` | secedit USER_RIGHTS: SeRemoteShutdownPrivilege | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 사용자 권한의 SID 목록; 읽기 위한 shutdown 실행 권한 부여 불필요 |
| W-50 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 | `crash_on_audit_fail` | HKLM\SYSTEM\CurrentControlSet\Control\Lsa: CrashOnAuditFail | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 부재 UNABLE |
| W-51 SAM 계정과 공유의 익명 열거 허용 안 함 | `anonymous_enumeration_restricted` | HKLM\SYSTEM\CurrentControlSet\Control\Lsa: RestrictAnonymous/RestrictAnonymousSAM | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 부재 UNABLE |
| W-52 Autologon 기능 제어 | `auto_admin_logon` | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon: AutoAdminLogon (DefaultPassword는 조회 안 함) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 부재를0으로 해석하는 기존 동작 존재; 변경은 별도 KISA/effective 근거 승인 |
| W-53 이동식 미디어 포맷 및 꺼내기 허용 | `removable_media_eject_policy` | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon: AllocateDASD | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 값 부재 UNABLE, effective default 미검증 |
| W-54 DoS 공격 방어 레지스트리 설정 | `dos_defense_registry` | HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters: SynAttackProtect/EnableDeadGWDetect/KeepAliveTime/NoNameReleaseOnDemand | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 레거시 정책값의 Server2022 실효성은 별도 확인; 현재 기준 변경 금지 |
| W-55 사용자가 프린터 드라이버를 설치할 수 없게 함 | `printer_driver_installation_prevented` | HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers: AddPrinterDrivers | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 부재 UNABLE; 최신 Print 정책과 혼동 금지 |
| W-56 SMB 세션 중단 관리 설정 | `smb_session_policy` | HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters: EnableForcedLogOff/AutoDisconnect | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 부재 UNABLE; 분/초 자료형 검증 |
| W-57 로그온 시 경고 메시지 설정 | `logon_warning_inventory` | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System: legalnoticecaption/legalnoticetext (내용 대신 설정 유무) | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 원문 경고문 개인정보 수집 불필요 |
| W-58 사용자별 홈 디렉터리 권한 설정 | `user_home_acl_inventory` | Get-CimInstance Win32_UserProfile → 비Special·Test-Path 있는 LocalPath의 Get-Acl | E: 상승/위임 권한 우선 검증 | 컴퓨터+사용자별 가시성 | 자동 분기 있음; 오류/부재는 개별 확인 | Test-Path에서 안 보이는 프로필을 제외할 수 있음; profile_count=0에서 PASS 가능성 별도 감사 |
| W-59 LAN Manager 인증 수준 | `lan_manager_authentication_level` | HKLM\SYSTEM\CurrentControlSet\Control\Lsa: LmCompatibilityLevel | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 값 부재 UNABLE, effective default 미검증 |
| W-60 보안 채널 데이터 디지털 암호화 또는 서명 | `secure_channel_policy` | NetGetJoinInformation + HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters: RequireSignOrSeal/SealSecureChannel/SignSecureChannel | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 비도메인 NA; 도메인 GPO 유효성 추가 검증 |
| W-61 파일 및 디렉토리 보호 | `fixed_volume_inventory` | Get-CimInstance Win32_LogicalDisk → FileSystem 비어 있지 않은 볼륨 | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 파일시스템 공백 볼륨이 수집 전에 제외됨; coverage와 사용자별 mapped drive를 별도 확인 |
| W-62 시작프로그램 목록 분석 | `startup_inventory` | Get-CimInstance Win32_StartupCommand 및 Win32_Service -Filter StartMode='Auto' | P: SeRestorePrivilege 검증 | 컴퓨터+사용자별 가시성 | 수동 분기 있음 | 엑셀 표준 조회 표기 보강: Microsoft Win32_StartupCommand 요구 SeRestorePrivilege, 사용자 autostart 범위 |
| W-63 도메인 컨트롤러-사용자의 시간 동기화 | `kerberos_clock_skew_policy` | NetGetJoinInformation; secedit [Kerberos Policy] MaxClockSkew → HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters: MaxSkew fallback | E: 상승/위임 권한 우선 검증 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 비도메인 UNABLE (NA 아님); 도메인 policy export/fallback 실제 유효값 검증 |
| W-64 윈도우 방화벽 설정 | `firewall_profile_inventory` | Get-NetFirewallProfile: Name/Enabled | R: 일반 사용자 읽기 후보 | 컴퓨터/역할 | 자동 분기 있음; 오류/부재는 개별 확인 | 프로필 전체를 조회하지만 RSoP/효과 정책의 의미 별도 검증 |

## 공통 수집 경로의 상세

- NetAPI: accounts는 NetUserEnum level3/FILTER_NORMAL_ACCOUNT 및 buffer pagination,
  NetUserModalsGet level3 잠금 정책/level0 암호 정책, NetGetJoinInformation,
  NetLocalGroupGetMembers level2, ConvertStringSidToSidW/LookupAccountSidW를 사용한다.
  DC와 member server의 조회 ACL은 다를 수 있다. [NetUserEnum 공식 권한](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum)
- PowerShell: powershell.exe -NoLogo -NoProfile -NonInteractive -Command <코드 내 고정 문자열>.
  shell=False, 30초 timeout. 외부 명령 문자열을 받는 기능은 아님.
  현재 실행파일 이름은 절대 System32 경로가 아니다. 특권 서비스 도입 전에 경로 탐색/CWD/환경변수 오염 방어를 검토해야 한다.
- secedit: secedit.exe /export /cfg <임시폴더>/security-policy.inf /areas SECURITYPOLICY 또는 USER_RIGHTS /quiet.
  결과 INF를 임시 생성/삭제하므로 정책 read-only는 '아무 파일도 쓰지 않음'과 다르다.
  '/mergedpolicy'를 쓰지 않으므로 해당 export를 모든 도메인 유효 정책의 증명으로 확대하지 않는다.
  [공식 export 계약](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/secedit-export)
- FTP 수집기 F: Get-Service FTPSVC, Import-Module WebAdministration, Get-Website의 ftp binding,
  Get-WebConfigurationProperty/Get-WebConfiguration: MACHINE/WEBROOT/APPHOST,
  system.ftpServer/security/ssl, authentication/anonymousAuthentication,
  authorization/add, ipSecurity 및 ipSecurity/add.
  사이트의 확장된 PhysicalPath에 Get-Acl 수행. 구성 저장 파일은 IIS applicationHost.config에 대응하지만
  현재 코드는 이 파일을 직접 파싱하지 않는다. 역할 설치/모듈/provider/config ACL/사이트 실제 구성에 종속된다.
- W-47: HKLM 및 HKCU SOFTWARE\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop,
  HKCU Control Panel\\Desktop의 ScreenSaveActive/ScreenSaverIsSecure/ScreenSaveTimeOut (REG_SZ 검증).
  SystemParametersInfoW GETSCREENSAVEACTIVE(0x0010), GETSCREENSAVESECURE(0x0076), GETSCREENSAVETIMEOUT(0x000E).
  구조의 effective_verified는 현재 호출자 API 조회 분기를 뜻하며 전체 업무 사용자 검증을 의미하지 않는다.
- W-62: 현재 코드에 해당 privilege 보유/활성화 검증 없음.
  [Win32_StartupCommand 공식 문서](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-startupcommand)는 SeRestorePrivilege를 요구한다.
  따라서 첨부의 표준 조회 분류는 특수 권한 확인 대상으로 보강해야 한다.

## Excel 정정·보강 결과

1. 원본의 19개 '권한 확인 우선'은 실제 관리자 필수 개수가 아니며 그대로 확정하지 않는다.
2. W-09에 NetAPI와 함께 PasswordComplexity의 secedit 의존성 추가.
3. W-37 전체 ScheduledTask 가시성은 작업 ACL/실행 계정에 좌우됨: 표준 목록 조회 가능 ≠ 전체 커버리지.
4. W-62 SeRestorePrivilege 공식 요구 추가. 사용자 autostart 전체를 일반 권한으로 수집 완료한다고 표시하지 않는다.
5. W-35 System DSN 범위와 32/64bit 뷰, W-58 사용자 profile coverage, W-61 mapped volume/공백 FileSystem을 명시.
6. W-43 실제 코드 경로 config/LogFiles와 실제 이벤트 로그별 경로를 구분.
7. W-47는 단순 권한 부족이 아닌 target identity/session 오류 위험. 서비스 계정의 FAIL을 업무 사용자 FAIL로 보고하지 않도록 후속 설계 승인 필요.
8. 엑셀의 환경/수동 18개는 단일 개수로 정책화하지 않는다. 분기별 자동/수동/NA/부재/오류를 분리해 보존한다.

이 단계는 기준/판정 변경 제안 승인이 아니며 CHECK/HARDEN 코드 수정 없음.

