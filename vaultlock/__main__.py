from .cli import main
import sys

if __name__ == "__main__":
    # No arguments -> open the desktop app; otherwise behave as the CLI.
    sys.exit(main(sys.argv[1:] or ["gui"]))
