# Agent API v2 확인 대기 항목

문서 기준과 현재 Mock 전용 가정을 섞지 않기 위한 작업 메모다. 중앙 API 규격이 확정되기 전에는 아래 항목을 변경하지 않는다.

## 설계서에 명시된 규격

- 결과 전송 경로: `POST /agent-api/v2/tasks/{id}/results`
- 결과 주요 필드: `schema_version`, `message_id`, `sent_at`, `agent_id`, `server_id`, `job_id`, `scan_run_id`, `attempt_id`, `result_id`, `item_id`, `criteria_snapshot_id`, `status`, `review_state`, `auto_stage_state`, `reason_code`, `observed_at`, `evidence_ids`, `current_value`, `error`
- 증적 메타데이터 주요 필드: `evidence_id`, `server_id`, `scan_run_id`, `item_id`, `collector_id`, `captured_at`, `redacted`, `media_type`
- 증적 저장 추가값: `sha256`, `byte_length`, `storage_ref`, 접근 등급, `received_at`
- Agent는 `CONFIRMED` 판정을 전송하지 않음
- 설계 API 목록에 증적 업로드 경로 `POST /agent-api/v2/evidence-uploads`가 있음

## 현재 Mock 전용 가정

- 결과 수신 응답: `accepted_ids`, `duplicate_ids`
- 중복 판정 키: `result_id`
- 결과의 `auto_stage_state`: `MOCK_ONLY`
- 결과의 `reason_code`: `MOCK_NOT_IMPLEMENTED`
- Mock 결과의 `current_value`: `{ "mock": true, "checked": false }`
- Mock `module_version`: `windows-agent-mock-0.1.0`
- 증적 업로드는 호출하지 않고 결과의 `evidence_ids`와 메타데이터 모델만 검증함

## 김민지 확인 후 수정할 항목

1. 중복 결과 응답의 실제 HTTP 상태·필드명·재전송 처리 규칙
2. 증적 업로드 요청/응답 JSON, 업로드 시점, 해시·저장 참조 필수 여부
3. Agent 결과의 `status`, `review_state`, `auto_stage_state`, `reason_code` 허용값
4. Windows 운영용 `module_version` 값과 변경 정책

