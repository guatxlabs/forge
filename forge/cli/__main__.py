# SPDX-License-Identifier: AGPL-3.0-only
"""Point d'entrée module : `python -m forge.cli <commande>` (préserve le comportement de l'ancien
`forge/cli.py` exécuté directement)."""
import sys

from . import main

if __name__ == "__main__":
    sys.exit(main())
