"""Packaging entry point; all CHECK behavior remains in agent.local_runner."""

from agent.local_runner import main


if __name__ == "__main__":
    raise SystemExit(main())
