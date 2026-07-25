# SPDX-License-Identifier: AGPL-3.0-or-later
"""Invariants de GOUVERNANCE du SPA de la console (console/web/js) vérifiés sur la SOURCE.

Portée mesurée : ces tests lisent le JavaScript servi par la console et vérifient PAR QUEL CHEMIN les
routes gouvernées sont appelées. Ils ne font PAS tourner le SPA — ils couvrent l'angle mort des tests
Rust, qui appellent les handlers directement et ne peuvent donc pas voir que le CLIENT n'envoie pas les
en-têtes opérateur.

INVARIANT COUVERT — `POST /api/plan` (dry-plan INERTE) ne doit JAMAIS être plus restreint que
`POST /api/run` (campagne ARMÉE) : qui peut TIRER doit pouvoir PRÉVISUALISER. Le serveur applique la
même gate aux deux ; il faut donc que le client fournisse la même preuve d'opérateur aux deux. Un
`fetch()` brut ne le fait pas : seul le helper partagé `write()` (core/api.js -> operatorHeaders)
injecte `X-Forge-Operator`.

POURQUOI CE FICHIER A ÉTÉ RÉÉCRIT (et ce que la réécriture change VRAIMENT). La version précédente
lisait le source LIGNE PAR LIGNE : elle ne voyait un appel que si le littéral de route ET le mot-clé
d'appel tombaient sur la MÊME ligne. Mesuré : un `fetch(` multi-ligne vers /api/plan passait les trois
tests (RC=0) alors que la MÊME régression écrite sur une ligne était bien attrapée. La garde fermait
donc une FORME D'ÉCRITURE, pas la CLASSE.

Ici, la détection ne raisonne plus sur des lignes mais sur la STRUCTURE du source :
  1. les commentaires sont neutralisés par un scanner qui connaît les chaînes (`'`, `"`, `` ` ``), pas
     par un test de préfixe de ligne ;
  2. on ne cherche pas une sous-chaîne mais un LITTÉRAL DE CHAÎNE dont la valeur DÉSIGNE la route
     (égale, ou suivie de `?`/`/`) — `'/api/runs'` n'est donc plus confondu avec `'/api/run'` sans
     bricolage d'apostrophe ;
  3. l'appel englobant est retrouvé en remontant les parenthèses ÉQUILIBRÉES, ce qui traverse les sauts
     de ligne, les arguments imbriqués (`fetch(withEngagement('/api/plan'), …)`) et les espaces entre
     le nom et sa parenthèse ;
  4. la preuve d'opérateur est cherchée dans le TEXTE COMPLET de l'appel (donc `auth: 'operator'` peut
     vivre trois lignes plus bas).
Ce que ça ne fait PAS : ce n'est pas un parseur JavaScript. Les formes qu'il ne sait pas rattacher à un
appel réseau connu ne sont pas ignorées en silence — elles font ÉCHOUER le test (cf.
`test_every_reference_is_attached_to_a_known_network_call`), pour qu'un angle mort se signale au lieu
de se taire. `test_detector_sees_forms_it_was_not_written_for` exerce des écritures ABSENTES du dépôt.
"""
import re
import unittest
from pathlib import Path

JS_DIR = Path(__file__).resolve().parents[1] / "console" / "web" / "js"

#: callees qui ÉMETTENT une requête réseau dans ce SPA (`write`/`api`/`adminApi` = helpers partagés qui
#: injectent les en-têtes ; `fetch` = appel brut, celui qui avait dérivé).
_NETWORK_CALLEES = {"fetch", "write", "api", "adminApi"}
_IDENT = re.compile(r"[A-Za-z0-9_$]")


def _blank_comments(src):
    """Remplace les commentaires par des espaces (longueur et n° de ligne PRÉSERVÉS). Scanner qui suit
    l'état de chaîne (`'`, `"`, `` ` ``) et les échappements : un `//` dans une URL littérale n'ouvre
    pas un commentaire, et un `'` dans un commentaire n'ouvre pas une chaîne."""
    out = list(src)
    i, n = 0, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"`":
            quote = c
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            for k in range(i, min(i + 2, n)):
                out[k] = " "
            i += 2
            continue
        i += 1
    return "".join(out)


def _string_literals(src):
    """(début, fin, valeur) de chaque littéral de chaîne. `fin` = index du quote fermant."""
    lits = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"`":
            j = i + 1
            buf = []
            while j < n:
                if src[j] == "\\":
                    buf.append(src[j : j + 2])
                    j += 2
                    continue
                if src[j] == c:
                    break
                buf.append(src[j])
                j += 1
            lits.append((i, j, "".join(buf)))
            i = j + 1
            continue
        i += 1
    return lits


def _match_paren(src, open_idx):
    """Index de la parenthèse fermante correspondant à `src[open_idx] == '('` (chaînes ignorées)."""
    depth, i, n = 0, open_idx, len(src)
    quote = None
    while i < n:
        c = src[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in "'\"`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _enclosing_calls(src, idx):
    """Chaîne des appels ENGLOBANT `src[idx]`, du plus PROCHE au plus LOINTAIN.

    On remonte le source en comptant les parenthèses : une `(` rencontrée à profondeur 0 est la
    parenthèse ouvrante d'un appel englobant ; le callee est l'identifiant qui la précède (espaces et
    SAUTS DE LIGNE ignorés, `a.b.fetch(` -> `fetch`). Une `(` de simple groupement (aucun identifiant
    devant) arrête la remontée. Renvoie [(callee, texte complet de l'appel)]."""
    calls = []
    i, depth = idx, 0
    while i > 0:
        c = src[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                j = i - 1
                while j >= 0 and src[j].isspace():
                    j -= 1
                k = j
                while k >= 0 and _IDENT.match(src[k]):
                    k -= 1
                name = src[k + 1 : j + 1]
                if not name:
                    break
                calls.append((name, src[k + 1 : _match_paren(src, i) + 1]))
                i = k
                depth = 0
                continue
            depth -= 1
        i -= 1
    return calls


def _route_refs(code, route):
    """(ligne, index, source neutralisé) de chaque LITTÉRAL désignant `route` — égal, ou suivi de
    `?`/`/`. `code` doit déjà avoir ses commentaires neutralisés."""
    out = []
    for start, _end, value in _string_literals(code):
        v = value.strip()
        if v == route or v.startswith(route + "?") or v.startswith(route + "/"):
            out.append((code.count("\n", 0, start) + 1, start))
    return out


def _network_call_sites(route, sources=None):
    """(fichier, ligne, texte de l'appel réseau) pour chaque référence à `route`.

    `texte` est le texte COMPLET de l'appel réseau le plus EXTERNE qui englobe la référence (donc
    multi-ligne inclus). `None` si aucune callee réseau connue n'englobe la référence : le cas n'est pas
    jeté, il est REMONTÉ pour que le test échoue au lieu de devenir aveugle."""
    sites = []
    for name, src in (sources if sources is not None else _repo_sources()):
        code = _blank_comments(src)
        for line, idx in _route_refs(code, route):
            outer = None
            for callee, text in _enclosing_calls(code, idx):  # du plus proche au plus lointain
                if callee in _NETWORK_CALLEES:
                    outer = text  # on garde le plus EXTERNE
            sites.append((name, line, outer))
    return sites


def _repo_sources():
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted(JS_DIR.rglob("*.js"))]


def _has_operator_proof(text):
    """Preuve d'opérateur acceptable : le helper partagé (qui injecte l'en-tête) OU l'en-tête posé
    explicitement (cas de la SONDE de posture C2, qui l'envoie VIDE à dessein)."""
    return text is not None and ("write(" in text or "X-Forge-Operator" in text)


class TestDryPlanIsNotMoreRestrictedThanRun(unittest.TestCase):
    def test_plan_carries_the_same_operator_proof_as_run(self):
        sites = _network_call_sites("/api/plan")
        self.assertTrue(sites, "aucun appel à /api/plan trouvé dans le SPA (test devenu aveugle)")
        for name, line, text in sites:
            self.assertTrue(
                _has_operator_proof(text),
                f"{name}:{line} appelle /api/plan sans preuve opérateur (ni `write()` ni X-Forge-Operator) : "
                f"le dry-plan INERTE devient plus restreint que le lancement ARMÉ -> {text}",
            )

    def test_run_call_sites_all_carry_it_too(self):
        sites = _network_call_sites("/api/run")
        self.assertTrue(sites, "aucun appel à /api/run trouvé dans le SPA (test devenu aveugle)")
        for name, line, text in sites:
            self.assertTrue(_has_operator_proof(text),
                            f"{name}:{line} : /api/run sans preuve opérateur -> {text}")

    def test_plan_uses_exactly_the_helper_used_by_the_launch_form(self):
        """Le formulaire de lancement poste /api/run via `write(..., auth: 'operator')`. Le dry-plan doit
        emprunter LE MÊME helper : c'est ce qui rend les deux en-têtes identiques PAR CONSTRUCTION plutôt
        que par recopie (la recopie est exactement ce qui avait dérivé)."""
        plan = [t for _n, _l, t in _network_call_sites("/api/plan")]
        run = [t for _n, _l, t in _network_call_sites("/api/run") if t and "write(" in t]
        self.assertTrue(run, "le lancement n'utilise plus `write()` : invariant à réécrire")
        self.assertTrue(any(t and "write(" in t and "operator" in t for t in plan),
                        "aucun appel /api/plan via `write(..., auth: 'operator')` : " + " | ".join(map(str, plan)))

    def test_every_reference_is_attached_to_a_known_network_call(self):
        """Un littéral de route que la garde ne sait PAS rattacher à un appel réseau connu est un ANGLE
        MORT : on échoue bruyamment (au lieu de l'ignorer, ce qui est exactement la faute d'origine)."""
        for route in ("/api/plan", "/api/run"):
            for name, line, text in _network_call_sites(route):
                self.assertIsNotNone(
                    text,
                    f"{name}:{line} référence {route} hors d'un appel réseau reconnu "
                    f"({sorted(_NETWORK_CALLEES)}) : la garde doit être étendue, pas contournée",
                )


class TestDetectorSeesTheClassNotTheCase(unittest.TestCase):
    """La garde elle-même est mise à l'épreuve sur des ÉCRITURES QUI N'EXISTENT PAS DANS LE DÉPÔT.
    Si la détection redevenait ligne-à-ligne (ou naïvement textuelle), ces cas la feraient échouer."""

    #: (nom, source, doit_être_détecté_comme_appel, porte_une_preuve_opérateur)
    FIXTURES = [
        ("fetch multi-ligne via un helper d'URL", """
export async function lcDryPlanV2(body) {
  const r = await fetch(
    withEngagement('/api/plan'),
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
  );
  return r;
}
""", True, False),
        ("nom et parenthèse séparés par un saut de ligne", """
const r = await fetch
  (
    '/api/plan',
    { method: 'POST' }
  );
""", True, False),
        ("appel qualifié globalThis.fetch", """
globalThis.fetch('/api/plan', { method: 'POST' });
""", True, False),
        ("littéral gabarit avec query", """
await fetch(`/api/plan?dry=1`, { method: 'POST' });
""", True, False),
        ("imbrication à deux étages", """
handle(await fetch(withEngagement(String('/api/plan')), { method: 'POST' }));
""", True, False),
        ("helper partagé multi-ligne, preuve 3 lignes plus bas", """
const r = await write(
  '/api/plan',
  {
    body,
    auth: 'operator',
    engagement: true,
  }
);
""", True, True),
        ("commentaire ligne : faux site, doit être IGNORÉ", """
// const r = await fetch('/api/plan', { method: 'POST' });
const x = 1;
""", False, False),
        ("commentaire bloc multi-ligne : faux site, doit être IGNORÉ", """
/*
  await fetch('/api/plan');
*/
const y = 2;
""", False, False),
        ("URL contenant // : ne casse pas le scanner de commentaires", """
const u = 'https://example.test/x';
await write('/api/plan', { body, auth: 'operator' });
""", True, True),
    ]

    def test_detector_sees_forms_it_was_not_written_for(self):
        for label, src, detected, proof in self.FIXTURES:
            with self.subTest(label):
                sites = _network_call_sites("/api/plan", sources=[("fixture.js", src)])
                if not detected:
                    self.assertEqual(sites, [], f"[{label}] faux site détecté dans un commentaire")
                    continue
                self.assertTrue(sites, f"[{label}] appel NON DÉTECTÉ : la garde est aveugle à cette écriture")
                for _n, _l, text in sites:
                    self.assertIsNotNone(text, f"[{label}] appel détecté mais non rattaché à une callee réseau")
                    self.assertEqual(
                        _has_operator_proof(text), proof,
                        f"[{label}] preuve opérateur mal jugée sur : {text}",
                    )

    def test_run_is_not_confused_with_runs(self):
        """`'/api/runs'` (liste, lecture) n'est PAS `'/api/run'` (lancement armé) : la détection porte sur
        la VALEUR du littéral, plus sur une sous-chaîne bricolée avec une apostrophe."""
        src = "await api('/api/runs');\nawait write('/api/run', { body, auth: 'operator' });\n"
        sites = _network_call_sites("/api/run", sources=[("fixture.js", src)])
        self.assertEqual(len(sites), 1, f"une seule référence à /api/run attendue, obtenu {sites}")
        self.assertTrue(_has_operator_proof(sites[0][2]))


if __name__ == "__main__":
    unittest.main()
