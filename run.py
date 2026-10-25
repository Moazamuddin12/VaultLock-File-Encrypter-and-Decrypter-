"""Double-click / `python run.py` launcher (same as `python -m vaultlock`)."""
import sys

from vaultlock.cli import main

sys.exit(main())
