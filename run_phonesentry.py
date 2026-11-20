"""Entry point for PhoneSentry.exe. No arguments: GUI. With arguments: CLI."""
import multiprocessing
import os
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    # A windowed exe has no console: give libraries that print somewhere to write.
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    try:
        import pyi_splash  # type: ignore
        pyi_splash.close()
    except ImportError:
        pass
    if len(sys.argv) > 1:
        from phonesentry.cli import main
        sys.exit(main())
    from phonesentry.gui import run
    run()
