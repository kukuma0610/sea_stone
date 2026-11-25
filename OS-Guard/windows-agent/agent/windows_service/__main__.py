"""SCM 진입점. foreground Central CLI와 분리하여 CHECK/Enrollment 옵션을 제공하지 않는다."""

import argparse
import json
from pathlib import Path

from .preflight import observe
from .runtime import load_config, run
from .scm import dispatch


def main(argv=None):
    parser = argparse.ArgumentParser(description="OS Guard development service; policy pending")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scm", action="store_true")
    group.add_argument("--preflight", action="store_true")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--probe-tls", action="store_true", help="preflight의 인증 없는 TLS handshake만 허용")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.scm:
            if args.probe_tls: parser.error("--probe-tls is only for local preflight")
            dispatch(lambda stop: run(config, stop))
        else:
            print(json.dumps(observe(config, connect=args.probe_tls), ensure_ascii=False))
        return 0
    except Exception:
        print("LOCAL_SERVICE_START_OR_PREFLIGHT_FAILED; no credential output")
        return 1


if __name__ == "__main__": raise SystemExit(main())
