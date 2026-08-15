# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les erreurs SGBD telles qu'une couche ORM les rend — la famille que forge ne lisait pas.

MESURÉ le 2026-08-15 sur DVGA, application vivante. La charge `1'` de `sqli.probe` provoquait bel
et bien l'erreur, et AUCUNE signature ne la reconnaissait :

    {"errors":[{"message":"(sqlite3.OperationalError) near \\"1\\": syntax error\\n[SQL: SELECT pastes.id …

`sqlite3::` (deux-points) ne matche pas `sqlite3.` (point), et `syntax error at or near` est la
forme PostgreSQL, pas la forme SQLite (`near "…": syntax error`). L'oracle voyait donc l'erreur
passer sans la lire, et rendait « SQLi non confirmé » sur une injection PROUVÉE à la main.

PORTÉE — ce n'est pas un cas DVGA. SQLAlchemy préfixe TOUTE erreur du pilote sous-jacent par
`(<module>.<Classe>)`, et c'est la couche d'accès dominante de l'écosystème Python. Forge était
aveugle à cette famille entière : une liste tenue à la main avait dérivé du terrain, exactement
comme `_RATE_FLAG_KINDS` avant elle.

APRÈS CORRECTIF, sur la même application vivante : `HIGH / vulnerable — SQLi CONFIRMÉ (error-based)`.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from forge.modules.injection import _SQL_ERROR_SIGNS                           # noqa: E402


def _seen(body):
    """Une signature apparaît-elle dans ce corps ? (même geste que l'oracle : minuscules)"""
    low = body.lower()
    return [s for s in _SQL_ERROR_SIGNS if s in low]


#: corps RÉELS, tels que les rendent les couches concernées
REELS = {
    "DVGA / SQLAlchemy+sqlite (MESURÉ)":
        '{"errors":[{"message":"(sqlite3.OperationalError) near \\"1\\": syntax error\\n[SQL: SELECT p.id]"}]}',
    "SQLAlchemy + psycopg2":
        '(psycopg2.errors.SyntaxError) syntax error at end of input\n[SQL: SELECT * FROM users WHERE x=\'1\'\']',
    "SQLAlchemy + pymysql":
        "(pymysql.err.ProgrammingError) (1064, \"You have an error in your SQL syntax\")",
    "SQLAlchemy + MySQLdb":
        "(MySQLdb._exceptions.ProgrammingError) (1064, 'syntax')",
    "SQLAlchemy générique":
        "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token",
    "cx_Oracle":
        "(cx_Oracle.DatabaseError) ORA-00933: SQL command not properly ended",
    "pyodbc / SQL Server":
        "(pyodbc.ProgrammingError) ('42000', \"[42000] [Microsoft][ODBC Driver]\")",
    "asyncpg":
        "(asyncpg.exceptions.PostgresSyntaxError) syntax error at or near \"'\"",
    "SQLite nu (sans ORM)":
        'sqlite3.OperationalError: near "x": syntax error',
}


class TheORMFamilyIsRecognised(unittest.TestCase):

    def test_chaque_forme_reelle_est_reconnue(self):
        for label, body in REELS.items():
            with self.subTest(pile=label):
                self.assertTrue(_seen(body), f"aucune signature ne lit : {body[:80]}")

    def test_le_corps_EXACT_mesure_sur_DVGA(self):
        """Le cas qui a révélé le trou, à l'octet près."""
        body = ('{"errors":[{"message":"(sqlite3.OperationalError) near \\"1\\": syntax error'
                '\\n[SQL: SELECT pastes.id AS pastes_id FROM pastes WHERE title LIKE \'%1\'%\']"}]}')
        self.assertIn("(sqlite3.", _seen(body))


class NoWideningBeyondWhatWasMeasured(unittest.TestCase):
    """Élargir une signature au-delà du mesuré, c'est fabriquer le faux positif de demain."""

    def test_un_corps_applicatif_ordinaire_ne_matche_pas(self):
        for body in (
                "Aucun résultat pour votre recherche.",
                '{"data":{"pastes":[]}}',
                "<html><body>Bienvenue sur le site</body></html>",
                "Erreur : le formulaire est incomplet.",
                '{"hotels":[{"nom":"Hotel near \\"Gare du Nord\\"","note":4}]}',
                "Votre commande near Paris a été enregistrée",
                "La colonne demandée est introuvable dans le rapport."):
            with self.subTest(corps=body[:40]):
                self.assertEqual(_seen(body), [], f"faux positif potentiel sur : {body[:60]}")

    def test_near_seul_ne_suffit_PAS(self):
        """`near \"` seul aurait matché une phrase légitime : on exige le phrasé COMPLET."""
        self.assertEqual(_seen('un restaurant near "la gare" est disponible'), [])
        self.assertTrue(_seen('near "x": syntax error'))

    def test_les_signatures_historiques_sont_conservees(self):
        for body in ("You have an error in your SQL syntax",
                     "Warning: mysqli_query()",
                     "ORA-00933: SQL command not properly ended",
                     "unclosed quotation mark after the character string"):
            with self.subTest(corps=body[:30]):
                self.assertTrue(_seen(body), "une signature historique a été perdue")


if __name__ == "__main__":
    unittest.main()
