# SPDX-License-Identifier: AGPL-3.0-or-later
"""Les deux règles publiques sont-elles INFRANCHISSABLES, ou seulement écrites ?

Une recréation de dépôt nettoie le passé ; elle ne garantit rien sur l'avenir. Sans vérification
machine, la dérive recommence au premier commit — et ce dépôt a deux démonstrations de ce que
devient une règle non gardée : `_RATE_FLAG_KINDS` et `_SQL_ERROR_SIGNS`, justes le jour de leur
écriture et fausses quelques mois plus tard.

DEUX BARRIÈRES, UNE SEULE IMPLÉMENTATION (`scripts/check_commit_register.py`) :
  · le hook `commit-msg` — poste local, avant que le commit existe ;
  · le job CI sur la plage poussée — dépôt publié.
Le hook ne ferme pas : il n'est pas transporté par `git clone` et n'est jamais exécuté par l'édition
via l'interface web de GitHub, la voie même par laquelle des commits à compte personnel sont entrés.

Ce fichier vérifie les deux sens : ce qui doit être REFUSÉ l'est, et ce qui doit RESTER passe.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import unittest

RACINE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RACINE / "scripts"))

from check_commit_register import (  # noqa: E402
    BANNIES, faute_d_identite, fautes_de_message, verifier_revisions)


class WhatMustBeRefused(unittest.TestCase):

    def test_le_recit_d_enquete_a_la_premiere_personne(self):
        for phrase in ("j'avais écarté ce champ deux jours plus tôt",
                       "ma contre-vérification a montré l'inverse",
                       "j'ai mesuré 27 cibles atteintes",
                       "je consigne le résultat ici"):
            with self.subTest(phrase=phrase[:36]):
                self.assertTrue(fautes_de_message(phrase), f"non détecté : {phrase}")

    def test_l_adresse_directe_a_un_interlocuteur(self):
        for phrase in ("comme vous l'avez demandé, le champ est corrigé",
                       "comme demandé, le débit est borné",
                       "vous trouverez le détail dans la roadmap",
                       "merci de vérifier le résultat"):
            with self.subTest(phrase=phrase[:36]):
                self.assertTrue(fautes_de_message(phrase), f"non détecté : {phrase}")

    def test_la_chronologie_de_session_comme_fil_narratif(self):
        for phrase in ("cette session a produit trois correctifs",
                       "dans ma dernière réponse, le chiffre était faux"):
            with self.subTest(phrase=phrase[:36]):
                self.assertTrue(fautes_de_message(phrase), f"non détecté : {phrase}")

    def test_une_identite_personnelle_ou_nominative(self):
        # Identités SYNTHÉTIQUES à dessein. Une fixture n'a pas besoin d'une vraie adresse pour
        # prouver la propriété — et ce test-ci, s'il en portait une, publierait exactement ce que
        # la règle interdit de publier. Les quatre cas couvrent les quatre formes de refus :
        # pseudonyme hors registre, identité nominative, casse divergente, domaine tiers.
        for nom, email in (("pseudo-perso", "1234567+pseudo-perso@users.noreply.github.com"),
                           ("Prénom Nom", "prenom.nom@example.com"),
                           ("GuatX", "noreply@guatx.com"),
                           ("guatxlabs", "compte-perso@example.com")):
            with self.subTest(identite=f"{nom} <{email}>"):
                self.assertIsNotNone(faute_d_identite(nom, email), f"accepté à tort : {nom}")

    def test_l_identite_publique_unique_PASSE(self):
        self.assertIsNone(faute_d_identite("guatxlabs", "noreply@guatx.com"))


class WhatMustKeepPassing(unittest.TestCase):
    """L'EXCÈS INVERSE — un garde trop zélé appauvrirait la documentation qu'il prétend protéger."""

    def test_la_voix_de_l_outil(self):
        """La voix de l'outil doit porter une MARQUE de citation — guillemets, backticks ou « > ».

        C'est la contrepartie du garde généralisé : il lit des formes sans savoir qui parle, donc
        une première personne nue lui est indiscernable d'un récit d'enquête. Le second cas
        ci-dessous était écrit sans guillemets tant que la liste énumérait les verbes ; il en
        porte depuis que la forme fait foi."""
        for phrase in ("un `skipped` dit « je n'ai PAS pu vérifier »",
                       "le statut énonce « je n'ai pas vu l'application »"):
            with self.subTest(phrase=phrase[:36]):
                self.assertEqual(fautes_de_message(phrase), [], f"banni à tort : {phrase}")

    def test_les_DEUX_moities_de_la_voix_de_l_outil_passent(self):
        """`skipped` et `tested` disent la même chose sur deux statuts : les deux doivent passer.

        Une version antérieure du garde énumérait les verbes bannis après « j'ai » et n'admettait
        que la ligne « > » comme citation. Le pendant `tested` se faisait donc refuser quand sa
        moitié `skipped` passait — asymétrie sans règle derrière, pur artefact d'énumération. Le
        garde reconnaît désormais la citation à sa FORME, ce qui rend les deux symétriques.

        La contrepartie est figée juste en dessous : hors citation, la même tournure est refusée."""
        for voix in ("un `skipped` dit « je n'ai PAS pu vérifier »",
                     "un `tested` dit « j'ai vérifié, rien trouvé »",
                     "> un `tested` dit « j'ai vérifié, rien trouvé »"):
            with self.subTest(voix=voix[:34]):
                self.assertEqual(fautes_de_message(voix), [], f"banni à tort : {voix}")

    def test_hors_citation_la_MEME_tournure_est_refusee(self):
        """Sans cette contrepartie, « reconnaître les citations » deviendrait « ne plus rien voir ».

        Ces quatre formes sont celles qui ont réellement traversé l'énumération précédente."""
        for nu in ("j'ai vérifié, rien trouvé",
                   "j'ai d'abord inséré le correctif dans recon.subfinder",
                   "mon propre garde criait au loup",
                   "le travail d'hier porte celui du jour"):
            with self.subTest(nu=nu[:34]):
                self.assertTrue(fautes_de_message(nu), f"non détecté : {nu}")

    def test_aujourd_hui_n_est_PAS_de_la_chronologie(self):
        """`hier` est banni, `aujourd'hui` non — et l'asymétrie est mesurée, pas supposée.

        `hier` en message de commit n'a aucun référent pour un lecteur public. `aujourd'hui` sert
        à dire « à l'état actuel du code », dans 8 emplois sur 9 relevés dans cet historique."""
        self.assertEqual(fautes_de_message("aucun réglage n'expose ce levier aujourd'hui"), [])
        self.assertTrue(fautes_de_message("la garde d'hier les a rendus visibles"))

    def test_une_date_de_mesure_reste_de_la_TRACABILITE(self):
        phrase = "MESURÉ le 2026-08-16 sur l'application vivante : 27 cibles, 0 page vulnérable."
        self.assertEqual(fautes_de_message(phrase), [])

    def test_un_POURQUOI_long_reste_admis(self):
        """La longueur n'a jamais été le défaut ; l'adressage l'était."""
        phrase = ("La forme urlencodée était un angle mort pour toute API JSON : le corps partait "
                  "sous un `Content-Type: application/json` sans en avoir la structure, et le "
                  "serveur répondait 500, ce que l'oracle lisait comme « pas vulnérable ». " * 3)
        self.assertEqual(fautes_de_message(phrase), [])

    def test_les_trailers_d_attribution_sont_ignores(self):
        msg = ("fix: un correctif\n\nUn corps normal.\n\n"
               "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>\n"
               "Signed-off-by: guatxlabs <noreply@guatx.com>\n")
        self.assertEqual(fautes_de_message(msg), [])

    def test_une_CITATION_de_la_mauvaise_forme_est_ignoree(self):
        """Une règle doit pouvoir citer ce qu'elle interdit sans se refuser elle-même."""
        msg = "docs: poser la règle\n\n> « j'avais écarté ce champ » -> adressé à une conversation\n"
        self.assertEqual(fautes_de_message(msg), [])


class TheTwoBarriersExist(unittest.TestCase):

    def test_le_hook_est_VERSIONNE_et_executable(self):
        hook = RACINE / ".githooks" / "commit-msg"
        self.assertTrue(hook.exists(), "hook absent — rien n'arrête la faute avant le commit")
        self.assertTrue(hook.stat().st_mode & 0o111, "hook non exécutable")

    def test_la_CI_verifie_la_PLAGE_poussee(self):
        ci = (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("check_commit_register.py", ci,
                      "aucune barrière CI — le hook seul ne couvre ni un autre poste ni "
                      "l'édition via l'interface web de GitHub")
        self.assertIn("fetch-depth: 0", ci, "sans historique complet, la plage est illisible")

    def test_TOUS_les_jobs_sont_EXIGES_par_l_agregateur(self):
        """Un job absent de `needs` s'exécute, échoue… et ne bloque RIEN.

        `ci-ok` est le seul contrôle exigé par le ruleset : il ne regarde que ce que `needs`
        énumère. Le job `register` a tourné VERT à côté de la plaque pendant toute une série de
        poussées — présent dans l'interface, sans effet sur la fusion. Le commentaire de `ci-ok`
        avertissait déjà de ce piège ; il fallait une machine pour le tenir."""
        ci = (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        # Borné à la section `jobs:` — sinon `push:` du bloc `on:` est pris pour un job.
        # Lecture par regex plutôt que par `yaml.safe_load` : ce test doit tourner là où la CI
        # n'installe que `.[test]`, qui ne fournit pas pyyaml.
        corps = ci.split("\njobs:", 1)
        self.assertEqual(len(corps), 2, "section `jobs:` introuvable")
        declares = set(re.findall(r"^  ([a-z][a-z0-9-]*):$", corps[1], re.M)) - {"ci-ok"}
        apres = ci.split("\n  ci-ok:", 1)
        self.assertEqual(len(apres), 2, "agrégateur `ci-ok` absent — plus rien n'est exigé")
        besoins = re.search(r"^    needs: \[([^\]]+)\]", apres[1], re.M)
        self.assertIsNotNone(besoins, "`ci-ok` sans `needs` — plus rien n'est exigé")
        exiges = {x.strip() for x in besoins.group(1).split(",")}
        self.assertEqual(declares - exiges, set(),
                         "des jobs tournent sans rien bloquer, car absents du `needs` de `ci-ok`")

    def test_le_PLANCHER_python_declare_est_verifie(self):
        """`requires-python` est une PROMESSE faite à qui installe le paquet.

        Elle n'était vérifiée par rien : la suite tourne sur 3.11, donc une syntaxe 3.10-only
        serait passée — et une f-string 3.12-only (PEP 701) a réellement coûté 53 erreurs d'import.
        `ast.parse(feature_version=…)` ne détecte PAS ce cas ; seul l'interpréteur du plancher le
        fait, d'où un job qui lit la version déclarée et lance `compileall` dessus."""
        ci = (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("compileall", ci, "aucun contrôle du plancher python déclaré")
        self.assertIn("requires-python", ci,
                      "le job doit LIRE le plancher dans pyproject, pas le coder en dur — "
                      "une valeur recopiée dérive de la déclaration qu'elle prétend vérifier")

    def test_le_verificateur_s_execute_vraiment(self):
        r = subprocess.run([sys.executable, str(RACINE / "scripts" / "check_commit_register.py"),
                            "--rev", "HEAD"], capture_output=True, text=True, cwd=RACINE)
        self.assertIn(r.returncode, (0, 1), f"le vérificateur a planté : {r.stderr[:200]}")

    def test_le_COMMITTER_est_verifie_autant_que_l_auteur(self):
        """Un `cherry-pick`, un `rebase` ou l'édition web gardent l'auteur et changent le committer.

        Vérifier `%an/%ae` seul laisse cette porte ouverte — et c'est précisément par l'édition via
        l'interface web que des commits à compte personnel sont entrés ici. Le contrôle se fait sur
        un dépôt jetable : rien n'est lu ni écrit dans le dépôt courant."""
        import os
        import shutil
        import tempfile
        if shutil.which("git") is None:
            self.skipTest("git absent : ce test FABRIQUE un dépôt pour observer le committer, "
                          "il ne peut pas s'en passer (le garde, lui, refuse proprement — cf. "
                          "`test_une_plage_ILLISIBLE_est_un_REFUS_et_non_un_succes`)")
        with tempfile.TemporaryDirectory() as d:
            def git(*a, **env):
                subprocess.run(["git", *a], cwd=d, capture_output=True, check=True,
                               env={**os.environ, **env.get("env", {})})
            git("init", "-q", "-b", "main")
            git("config", "user.name", "guatxlabs")
            git("config", "user.email", "noreply@guatx.com")
            pathlib.Path(d, "a.txt").write_text("x", encoding="utf-8")
            git("add", "a.txt")
            # auteur conforme, committer d'un compte personnel — exactement le cas de l'édition web
            git("commit", "-q", "-m", "feat: un changement décrit pour un lecteur",
                env={"GIT_COMMITTER_NAME": "pseudo-perso",
                     "GIT_COMMITTER_EMAIL": "1234567+pseudo-perso@users.noreply.github.com"})
            cwd = os.getcwd()
            try:
                os.chdir(d)
                refus = verifier_revisions("main")
            finally:
                os.chdir(cwd)
        self.assertTrue(any("(committer)" in r for r in refus),
                        f"committer non conforme accepté — refus obtenus : {refus}")
        self.assertFalse(any("(auteur)" in r for r in refus),
                         f"l'auteur était conforme et a pourtant été refusé : {refus}")
        # le libellé doit nommer le SLOT fautif, et lui seul
        self.assertFalse(any("(committer) : auteur" in r for r in refus),
                         f"le refus désigne le mauvais slot : {refus}")

    def test_une_plage_ILLISIBLE_est_un_REFUS_et_non_un_succes(self):
        """Une barrière échoue FERMÉE — sinon elle valide ce qu'elle n'a pas lu.

        Le job CI retombait sur la plage littérale « -1 HEAD » quand `github.event.before` vaut
        000…0 (branche neuve, dispatch manuel). `git log` refuse cet argument unique, l'ancien
        `_git` ne rendait que `stdout` — vide — et le garde concluait « aucune faute » : la CI
        annonçait un contrôle vert sur une plage jamais lue."""
        for plage in ("-1 HEAD", "cette-reference-n-existe-pas..HEAD"):
            with self.subTest(plage=plage):
                refus = verifier_revisions(plage)
                self.assertTrue(refus, f"plage illisible « {plage} » acceptée en silence")
                self.assertIn("ILLISIBLE", refus[0])

    def test_le_repli_du_job_CI_est_une_plage_que_git_SAIT_lire(self):
        """La correction du garde ne sert à rien si le YAML lui donne toujours l'argument cassé."""
        ci = (RACINE / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn('PLAGE="-1 HEAD"', ci,
                         "le repli passe encore « -1 HEAD » comme UNE seule révision à git")

    def test_les_TROIS_plages_du_job_CI_refusent_vraiment(self):
        """LA GARDE DOIT PROUVER QU'ELLE MORD, sur les trois formes de plage que le job calcule.

        Ce contrôle avait été vu PASSER, jamais REFUSER — et l'une des trois formes rendait un
        vert sans rien lire. Les trois sont donc exercées ici contre un commit délibérément
        fautif, dans un dépôt jetable :

          · `base..HEAD`      — le cas d'une pull request ;
          · `--rev HEAD`      — le repli d'une branche neuve (`github.event.before` = 000…0) ;
          · `--rev HEAD`      — le repli d'un `workflow_dispatch` (base vide).

        Un contrôle incapable d'échouer est un décor : si cette assertion devient verte alors
        qu'elle ne devrait pas, c'est le garde qui a cessé de garder, pas le dépôt qui s'est
        assaini."""
        import shutil
        import subprocess as sp
        import tempfile
        if shutil.which("git") is None:
            self.skipTest("git absent : ce test fabrique un dépôt pour exercer le job CI")
        garde = RACINE / "scripts" / "check_commit_register.py"
        with tempfile.TemporaryDirectory() as d:
            def git(*a):
                sp.run(["git", *a], cwd=d, capture_output=True, check=True)
            (pathlib.Path(d) / "scripts").mkdir()
            shutil.copy(garde, pathlib.Path(d) / "scripts" / "check_commit_register.py")
            git("init", "-q", "-b", "main")
            git("config", "user.name", "guatxlabs")
            git("config", "user.email", "noreply@guatx.com")
            pathlib.Path(d, "f.txt").write_text("a", encoding="utf-8")
            git("add", "-A")
            git("commit", "-q", "-m", "feat: un changement décrit pour un lecteur public")
            base = sp.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True,
                          text=True).stdout.strip()
            pathlib.Path(d, "f.txt").write_text("b", encoding="utf-8")
            git("add", "-A")
            git("commit", "-q", "-m",
                "fix: j'ai corrigé le champ hier, comme vous l'avez demandé")

            def lancer(*args):
                return sp.run([sys.executable, "scripts/check_commit_register.py", *args],
                              cwd=d, capture_output=True, text=True)

            for label, args in (("plage de PR", ("--range", f"{base}..HEAD")),
                                ("repli branche neuve", ("--rev", "HEAD")),
                                ("repli dispatch", ("--rev", "HEAD"))):
                with self.subTest(cas=label):
                    r = lancer(*args)
                    self.assertEqual(r.returncode, 1,
                                     f"{label} : le commit fautif a été ACCEPTÉ "
                                     f"(sortie {r.returncode})")
                    self.assertIn("REGISTRE", r.stderr, f"{label} : refus sans motif nommé")

            # ET L'EXCÈS INVERSE : un commit conforme doit passer par les mêmes chemins, sans quoi
            # « ça refuse » ne prouverait qu'un garde bloqué en position fermée.
            for label, args in (("plage de PR", ("--range", f"{base}..{base}")),
                                ("un seul commit", ("--rev", base))):
                with self.subTest(cas=f"conforme / {label}"):
                    self.assertEqual(lancer(*args).returncode, 0,
                                     f"{label} : un commit conforme a été refusé")

    def test_le_motif_de_chaque_regle_porte_sa_RAISON(self):
        for motif, raison in BANNIES.items():
            with self.subTest(motif=motif[:30]):
                self.assertTrue(raison.strip(), f"{motif} refusé sans justification écrite")


if __name__ == "__main__":
    unittest.main()
