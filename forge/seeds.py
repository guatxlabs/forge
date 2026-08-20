# SPDX-License-Identifier: AGPL-3.0-or-later
"""Normalisation des GRAINES d'engagement — une entité est un PIVOT, jamais une cible.

CE QUE CE MODULE PROTÈGE. Toute la sûreté de forge est ancrée sur une IP ÉPINGLABLE :
`Scope.is_in_scope` apparie un hôte, puis `resolve_target_ips` rend les IP contre lesquelles
le ROE prononce son verdict (privé / LAN / hors-scope-par-IP), fail-closed sur dépassement.
Une entité humaine — nom, pseudonyme, numéro de téléphone — n'a AUCUNE IP. Elle ne peut donc
pas être gouvernée par cette ancre, et la faire passer pour une cible reviendrait à tirer
sans verdict réseau.

D'où la règle tenue ici : **une graine doit produire une cible RÉSEAU, ou être refusée
NOMMÉMENT à l'entrée.** Le refus arrive au chargement, pas trois couches plus bas où il
ressemblerait à « rien trouvé ».

L'E-MAIL EST LE CAS QUI DEMANDAIT D'ÊTRE RENDU EXPLICITE. `alice@example.com` passait DÉJÀ le
scope-guard et résolvait vers les IP d'`example.com` — non par décision, mais parce que
`Scope._host()` retire le `userinfo` d'une URL (`https://user@hôte/`), comportement délibéré
et figé par test pour les URL. Un e-mail a la même forme, il retombait donc sur son domaine
par effet de bord. Ici c'est écrit : un e-mail est un PIVOT vers son domaine, la partie locale
est jetée, et la graine d'origine est conservée dans les attributs pour la traçabilité.

CE QUI N'EST PAS FAIT, ET POURQUOI. Agir sur une PERSONNE — énumérer ses comptes, remonter un
numéro — n'est pas du test d'infrastructure : le ROE n'a aujourd'hui aucun moyen d'exprimer
« autorisé à investiguer cette identité ». Tant que cette autorisation n'est pas exprimable,
ces graines sont refusées. C'est une limite d'AUTORISATION, pas de capacité technique.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

#: `local@domaine` — assez strict pour ne pas avaler un `user@host` d'URL déjà porteur d'un
#: chemin ou d'un schéma (ceux-là sont traités comme URL, plus haut dans `classify`).
_EMAIL = re.compile(r"^[^\s@/:]+@([A-Za-z0-9._-]+\.[A-Za-z]{2,})$")
#: Pseudonyme : `@handle` UNIQUEMENT.
#:
#: La forme `plateforme:handle` a été essayée puis RETIRÉE : elle avale `localhost:8080`,
#: c'est-à-dire une cible réseau parfaitement valide. Un motif de refus qui se trompe REFUSE
#: du travail légitime — le coût d'un faux positif n'est pas symétrique de celui d'un faux
#: négatif ici, puisque le scope-guard reste derrière pour trancher les cas réseau.
_PSEUDO = re.compile(r"^@[\w.\-]{1,64}$")
#: Téléphone : E.164 ou forme nationale espacée. TESTÉ APRÈS les littéraux IP — sans quoi
#: `1.2.3.4` (chiffres et points, 7 caractères) matche et une IPv4 valide se fait refuser.
#: Trouvé par sonde avant la première exécution réelle.
_TEL = re.compile(r"^\+?[0-9][0-9 .\-]{6,19}$")
#: Hôte ou IP littérale, éventuellement avec port/chemin/schéma : la forme réseau habituelle.
_RESEAU = re.compile(r"^(?:[a-z][a-z0-9+.\-]*://)?[A-Za-z0-9\[\]:._-]+(?:[/?#].*)?$")

#: Graines qui NOMMENT une personne plutôt qu'une machine. Refusées tant que le ROE ne sait
#: pas exprimer l'autorisation correspondante.
_ENTITES_PERSONNE = ("pseudonyme", "telephone", "nom")


@dataclass(frozen=True)
class Seed:
    """Résultat de la normalisation. `cible` est None quand la graine est refusée."""

    brut: str
    genre: str                       # url | hote | email | pseudonyme | telephone | nom
    cible: Optional[str] = None      # la cible RÉSEAU à gouverner, ou None
    motif: str = ""                  # pourquoi refusée (vide si acceptée)

    @property
    def acceptee(self) -> bool:
        return self.cible is not None


def _refus_personne(genre: str, brut: str) -> str:
    quoi = {"pseudonyme": "un pseudonyme", "telephone": "un numéro de téléphone",
            "nom": "un nom de personne"}[genre]
    return (f"« {brut} » est {quoi} : aucune IP ne peut en être résolue, donc le ROE ne peut "
            f"rendre aucun verdict réseau et le scope-guard n'a rien à apparier. Fournir un "
            f"hôte, une URL ou un e-mail — ou, si la plateforme visée est dans le périmètre "
            f"autorisé, mettre son domaine dans le scope et viser ce domaine.")


def normalize(brut: str) -> Seed:
    """Classe une graine et rend la cible RÉSEAU à gouverner, ou un refus nommé.

    Ne fait AUCUNE I/O : pas de résolution DNS, pas de requête. La résolution reste au
    fire-time dans le ROE, seul endroit qui épingle — ce module ne fait que décider ce qui
    mérite d'y arriver."""
    s = (brut or "").strip()
    if not s:
        return Seed(brut, "nom", None, "graine vide")

    # URL explicite : le schéma tranche avant tout le reste (un `user@` y est un userinfo).
    if "://" in s or s.startswith("/"):
        return Seed(s, "url", s)

    # LITTÉRAL IP AVANT TOUT MOTIF DE PERSONNE : `1.2.3.4` a la forme d'un numéro.
    hote_nu = s.split("/", 1)[0].split("?", 1)[0]
    candidat = hote_nu[1:].split("]", 1)[0] if hote_nu.startswith("[") else hote_nu.rsplit(":", 1)[0] \
        if hote_nu.count(":") == 1 else hote_nu
    for essai in (hote_nu, candidat):
        try:
            ipaddress.ip_address(essai)
        except ValueError:
            continue
        return Seed(s, "hote", s.casefold())

    m = _EMAIL.match(s)
    if m:
        # PIVOT : on garde le domaine, on jette la partie locale. Écrit, plus incident.
        return Seed(s, "email", m.group(1).casefold())

    if _PSEUDO.match(s):
        return Seed(s, "pseudonyme", None, _refus_personne("pseudonyme", s))
    if _TEL.match(s):
        return Seed(s, "telephone", None, _refus_personne("telephone", s))

    # Un espace ou un caractère non réseau => un nom, pas une machine.
    if " " in s or not _RESEAU.match(s):
        return Seed(s, "nom", None, _refus_personne("nom", s))

    return Seed(s, "hote", s.casefold())
