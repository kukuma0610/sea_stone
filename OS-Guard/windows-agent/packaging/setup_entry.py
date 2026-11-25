"""서명되지 않은 개발용 설치 EXE. 서비스 계정은 사용자가 명시적으로 선택한다."""

import argparse
import ctypes
import sys
from pathlib import Path

from agent.windows_service.installer import LocalInstaller
from agent.windows_service.scm import NativeSCM
from agent.windows_service.security import LocalError


def safe_failure(exc):
    if isinstance(exc, LocalError):
        messages = {
            "SERVER_2022_AMD64_REQUIRED": "비도메인 Windows Server 2022 Build 20348 AMD64 테스트 VM에서만 설치할 수 있습니다.",
            "EXPLICIT_LOW_PRIVILEGE_CANDIDATE_REQUIRED": "virtual 또는 local-service 계정 후보를 선택하세요.",
            "UNSIGNED_DEVELOPMENT_CONSENT_REQUIRED": "개발용 무서명 설치 동의가 필요합니다.",
            "UPDATE_REQUIRES_APPROVED_MIGRATION": "기존 상태를 보존했습니다. 버전 변경은 승인된 마이그레이션이 필요합니다.",
            "EXISTING_RESOURCE_NOT_OWNED": "기존 제품 경로나 보존된 state가 있습니다. 임의 삭제하지 말고 이전 설치 이력을 확인하세요.",
        }
        return messages.get(str(exc), "제품 자원·계정·무결성 검증 실패: " + str(exc))
    return "로컬 설치/제거 실패. 보호된 제품 상태를 임의 삭제하지 마세요."


def perform(operation, candidate=None, accept=False):
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("INSTALLER_ADMIN_APPROVAL_REQUIRED")
    installer = LocalInstaller(NativeSCM())
    if operation == "uninstall": return installer.uninstall()
    payload = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "service-payload.zip"
    return installer.install(payload, candidate=candidate, accept_development=accept)


def main():
    parser = argparse.ArgumentParser(description="Unsigned OS Guard development installer; isolated Server 2022 only")
    parser.add_argument("--operation", choices=("install", "uninstall"))
    parser.add_argument("--candidate", choices=("virtual", "local-service"))
    parser.add_argument("--accept-unsigned-development", action="store_true")
    args = parser.parse_args()
    if args.operation:
        try:
            result = perform(args.operation, args.candidate, args.accept_unsigned_development)
            print(result["state"])
            return 0
        except Exception as exc:
            print(safe_failure(exc))
            return 1
    import tkinter as tk
    from tkinter import ttk, messagebox
    window = tk.Tk()
    window.title("OS Guard — 서명되지 않은 개발용 설치")
    window.geometry("640x320")
    ttk.Label(window, text="격리 Windows Server 2022 VM 전용 / 상용 승인 패키지 아님", wraplength=590).pack(pady=15)
    ttk.Label(window, text="계정 후보를 명시 선택하세요. 운영 기본값은 미승인입니다.").pack()
    candidate = tk.StringVar(value="")
    ttk.Combobox(window, textvariable=candidate, values=("virtual", "local-service"), state="readonly").pack(pady=8)
    consent = tk.BooleanVar(value=False)
    ttk.Checkbutton(window, text="서명되지 않은 개발용 설치·서비스 등록을 승인합니다", variable=consent).pack()
    ttk.Label(window, text="자동 Enrollment·CA 변경·CHECK·HARDEN은 비활성화됩니다.").pack(pady=10)
    def action(operation):
        if operation == "uninstall" and not messagebox.askyesno("제거", "로컬 서비스/제품 파일만 제거합니다. Credential/state와 Central 등록은 보존합니다. 계속할까요?"):
            return
        try:
            result = perform(operation, candidate.get(), consent.get())
            messagebox.showinfo("결과", result["state"])
        except Exception as exc:
            messagebox.showerror("실패", safe_failure(exc))
    ttk.Button(window, text="로컬 서비스 설치", command=lambda: action("install")).pack(pady=4)
    ttk.Button(window, text="로컬 서비스 제거 (state 보존)", command=lambda: action("uninstall")).pack(pady=4)
    window.mainloop()
    return 0


if __name__ == "__main__": raise SystemExit(main())
