"""LOT AUTH-FLOW / RACE — oracle de VÉRIFICATION des faiblesses de FLUX OAuth/OIDC à PREUVE MINIMALE,
verrouillé sur le PROPRE flux de l'opérateur (`oauth.flow`).

Cet oracle CONFIRME des faiblesses du FLUX OAuth/OIDC avec une preuve MINIMALE et BÉNIGNE — détection/
vérification pour test autorisé, sur le flux de l'OPÉRATEUR (son `client_id` enregistré), JAMAIS une
identité tierce et JAMAIS le jeton d'un autre utilisateur :

  - redirect_uri validation bypass (CWE-601) : injecte une destination `redirect_uri` contrôlée par
    l'opérateur (hôte BÉNIGN de type example.) et LIT la redirection SANS LA SUIVRE (garde-fou de sûreté
    + scope). Promu `vulnerable` UNIQUEMENT si la destination est attaquant-contrôlable ET chaînable à un
    sink sensible — ici, un flux OAuth émetteur de code/jeton (response_type=code/token) EST le sink :
    un redirect_uri accepté = vol de code/jeton. Miroir de la discipline `redirect.open` (chaînable-seul).
  - `state` manquant/faible (CWE-352, CSRF sur le flux) : envoie une requête d'autorisation SANS `state`
    (ni PKCE) et observe si un code/jeton est TOUT DE MÊME émis -> aucune liaison anti-CSRF n'est imposée.
  - downgrade/absence de PKCE (CWE-287) : la même requête SANS `code_challenge` émet un code pour un
    client public -> PKCE non imposé (downgrade). Distinct du `state` (mitigation CSRF différente).
  - manipulation de scope/`idp_hint` : le `scope` (escalade) et l'`idp_hint` fournis par l'opérateur
    sont transmis ; leur ACCEPTATION/reflet est notée dans l'evidence (observation, non promue seule).

Les problèmes de JETON (alg=none, confusion RS256/HS256, secret faible, kid) restent couverts par
`jwt.weakness` ; cet oracle couvre le FLUX. exploit=False, destructive=False : sondes de VÉRIFICATION
bénignes (lecture du flux de l'opérateur, aucune mutation, aucun tiers) — gardées par le ROE comme toute
interaction web (`web_allowed`).

GARDE-FOUS (prouvés par les tests) :
  (1) SCOPE-GUARD fail-closed : cible hors périmètre -> `skipped`, AUCUNE requête émise (défense en
      profondeur : l'engine gate déjà en Couche 2, on re-valide localement AVANT tout réseau).
  (2) PREUVE MINIMALE, BÉNIGNE & FLUX-OPÉRATEUR : promotion `vulnerable` uniquement sur preuve concrète
      (redirect_uri attaquant accepté ET chaînable / code émis sans `state` / code émis sans PKCE). Sinon
      `tested`. `client_id` = celui de l'opérateur ; redirect_uri = hôte BÉNIGN contrôlé par l'opérateur.
  (3) NON DESTRUCTIF : lecture/observation du flux (redirections NON suivies) ; aucune identité tierce,
      aucun jeton d'autrui, aucune mutation d'état — le plancher exploit/destructif du ROE reste OFF.
  (4) SESSION SECRÈTE : le matériel d'auth gouverné est fusionné par `Oracle._http` UNIQUEMENT sur des
      URL in-scope et n'est JAMAIS journalisé/rapporté (les PoC dérivent des en-têtes de l'appelant).
  (5) DÉGRADATION GRACIEUSE : transport indisponible -> `skipped` (offline-safe).

Bâti sur la base `ClientFlowOracle` (clientflow.py — `_fetch` header-aware -> (status, body, pairs),
lecture de `Location`, redirections NON suivies) + `Oracle` (Finding + curl partagés)."""
import urllib.parse

from .clientflow import ClientFlowOracle, _CLIENT_REDIRECT_HINTS
from .registry import register
from ..roe import Scope
from .. import techniques

# response_type qui émettent un code/jeton dans la redirection -> le redirect_uri EST le sink sensible.
_SENSITIVE_RESPONSE_TYPES = {
    "code", "token", "id_token", "code id_token", "code token", "id_token token",
    "code id_token token",
}
# Clés de query/fragment prouvant qu'un code/jeton a été émis (par opposition à une erreur `error=`).
_ISSUED_KEYS = {"code", "access_token", "id_token"}


@register("oauth.flow")
class OAuthFlow(ClientFlowOracle):
    kind = "oauth.flow"
    exploit = False              # lecture/observation du flux de l'opérateur -> non-exploit
    destructive = False          # aucune mutation, aucune identité tierce
    web_allowed = True           # interaction web (réseau) -> gardée par le ROE
    available = True             # urllib stdlib -> toujours disponible
    mitre = techniques.mitre_for("oauth.flow")           # source de vérité : forge/techniques.py (T1528)
    cwe = "CWE-601"                                       # canonique (redirect_uri) ; 352/287 par finding
    tool = "forge/modules/oauth.py:oauth.flow"
    fix = ("Verrouiller le flux OAuth/OIDC : valider `redirect_uri` par correspondance EXACTE contre une "
           "allowlist pré-enregistrée (jamais de préfixe/sous-chaîne/wildcard) ; imposer un `state` "
           "imprévisible (CSPRNG) lié à la session ET/OU PKCE (`code_challenge` S256) OBLIGATOIRE, y "
           "compris pour les clients publics ; ne jamais accepter une requête d'autorisation sans "
           "liaison anti-CSRF ; restreindre les `scope`/`idp_hint` à des valeurs autorisées côté serveur "
           "(CWE-601 / CWE-352 / CWE-287).")
    description = ("Oracle OAuth/OIDC FLOW à PREUVE MINIMALE (flux de l'opérateur) : redirect_uri bypass "
                   "chaînable (CWE-601), `state` non imposé (CSRF, CWE-352), PKCE downgrade (CWE-287), "
                   "scope/idp_hint notés. Redirections NON suivies. jwt.weakness couvre le JETON. Sinon "
                   "tested. CWE-601/352/287.")

    _DEFAULT_ATTACKER = "https://forge-oauth.example/callback"   # hôte BÉNIGN contrôlé par l'opérateur

    # --- construction de la requête d'autorisation (query urlencodée) ---
    def _authorize(self, action, *, redirect_uri, include_state, include_pkce):
        """Émet un GET vers l'endpoint d'autorisation avec les paramètres OAuth demandés, SANS suivre la
        redirection (lecture de la cible sans I/O vers un hôte attaquant potentiellement hors-scope).
        Renvoie (url, status, body, pairs). `client_id` = celui de l'OPÉRATEUR (jamais un tiers)."""
        p = action.params
        base = p.get("authorize_url") or action.target
        q = {
            p.get("client_id_param", "client_id"): str(p["client_id"]),
            "response_type": str(p.get("response_type", "code")),
            p.get("redirect_param", "redirect_uri"): redirect_uri,
        }
        if p.get("scope"):
            q["scope"] = str(p["scope"])
        if p.get("idp_hint"):
            q[str(p.get("idp_hint_param", "idp_hint"))] = str(p["idp_hint"])
        if include_state:
            q["state"] = str(p.get("state") or self._marker(base, "state", "oauthstate"))
        if include_pkce and p.get("code_challenge"):
            q["code_challenge"] = str(p["code_challenge"])
            q["code_challenge_method"] = str(p.get("code_challenge_method", "S256"))
        sep = "&" if "?" in base else "?"
        url = f"{base}{sep}{urllib.parse.urlencode(q)}"
        st, body, pairs = self._fetch(url, headers=dict(p.get("headers", {})), method="GET",
                                      follow_redirects=False)
        return url, st, body, pairs

    def _redirect_controllable(self, st, body, pairs, attacker):
        """(bool, via) — la réponse redirige-t-elle vers l'hôte `redirect_uri` ATTAQUANT (contrôlable) ?
        (A) 3xx + Location vers l'hôte attaquant ; (B) redirection client-side (meta-refresh/JS) vers lui."""
        location = self._get(pairs, "Location") or ""
        attacker_host = Scope._host(attacker)
        if 300 <= (st or 0) < 400 and location:
            if location.startswith(attacker) or Scope._host(location) == attacker_host:
                return True, f"header Location (HTTP {st} -> {location})"
        if attacker in (body or ""):
            low = (body or "").lower()
            if any(h in low for h in _CLIENT_REDIRECT_HINTS):
                return True, "redirection client-side (meta-refresh/JS) vers le redirect_uri attaquant"
        return False, ""

    def _chainable(self, action, attacker_location):
        """(bool, raison) — le redirect_uri bypass chaîne-t-il vers un sink sensible ? Un flux OAuth
        émetteur de code/jeton EST le sink (miroir redirect.open « open redirect only if chained »)."""
        p = action.params
        if p.get("chainable") is False:
            return False, "chaînabilité niée par l'opérateur (params.chainable=False)"
        if p.get("chainable") is True:
            return True, "chaîne vers le sink OAuth (code/jeton) affirmée par l'opérateur"
        rt = str(p.get("response_type", "code")).strip().lower()
        if rt in _SENSITIVE_RESPONSE_TYPES:
            return True, (f"flux OAuth émetteur de code/jeton (response_type={rt}) -> un redirect_uri "
                          f"contrôlé = vol du code/jeton d'autorisation")
        low = (attacker_location or "").lower()
        if any(m + "=" in low for m in _ISSUED_KEYS):
            return True, "la redirection porte déjà un code/jeton vers l'hôte attaquant"
        return False, "response_type non sensible et aucun code/jeton dans la redirection — reste tested"

    @staticmethod
    def _code_issued(st, body, location):
        """(bool, où) — un code/jeton a-t-il été ÉMIS ? Parse la query ET le fragment de `Location`
        (3xx) à la recherche de `code`/`access_token`/`id_token` SANS `error` ; sinon un corps 200
        form_post/JSON portant un jeton. Robuste (parse_qs), ne confond pas avec une réponse d'erreur."""
        if 300 <= (st or 0) < 400 and location:
            split = urllib.parse.urlsplit(location)
            keys = set(urllib.parse.parse_qs(split.query)) | set(urllib.parse.parse_qs(split.fragment))
            if "error" not in keys and (keys & _ISSUED_KEYS):
                return True, f"Location porte {sorted(keys & _ISSUED_KEYS)} (HTTP {st})"
        low = (body or "").lower()
        if st in (200, 201) and '"error"' not in low and (
                '"access_token"' in low or '"id_token"' in low or '"code"' in low):
            return True, "corps porte un code/jeton (form_post/JSON)"
        return False, ""

    def _scope_note(self, action, location, body):
        """Observation scope/idp_hint : le `scope`/`idp_hint` fourni est-il reflété/accepté dans la
        réponse ? (informatif — non promu seul, mais tracé dans l'evidence du finding redirect)."""
        bits = []
        p = action.params
        hay = f"{location or ''} {body or ''}"
        if p.get("scope") and str(p["scope"]) in hay:
            bits.append(f"scope='{p['scope']}' reflété (manipulation de scope à vérifier)")
        if p.get("idp_hint") and str(p["idp_hint"]) in hay:
            bits.append(f"idp_hint='{p['idp_hint']}' reflété (manipulation d'idp_hint à vérifier)")
        return "; ".join(bits) if bits else "scope/idp_hint : aucun reflet observé"

    def dry(self, action):
        p = action.params
        base = p.get("authorize_url") or action.target
        attacker = str(p.get("attacker_redirect") or self._DEFAULT_ATTACKER)
        return (f"# flux OAuth de l'OPÉRATEUR (client_id={p.get('client_id', '<client_id>')}) sur {base} :\n"
                f"# (1) redirect_uri={attacker} (hôte BÉNIGN contrôlé) SANS suivre la redirection -> "
                f"PREUVE = redirection vers l'hôte attaquant ET flux émetteur de code/jeton (chaînable)\n"
                f"# (2) requête d'autorisation SANS state ni code_challenge -> PREUVE = code émis (state/"
                f"PKCE non imposés, CSRF/downgrade) ; sinon tested ; jamais un tiers, redirections non suivies")

    def fire(self, action):
        base = action.params.get("authorize_url") or action.target
        # (1) SCOPE-GUARD fail-closed — endpoint d'autorisation hors périmètre -> skipped, AUCUN réseau.
        if not self._in_scope(action, base):
            return [self._scope_refused(action)]
        # config : le flux de l'OPÉRATEUR EXIGE son propre client_id (jamais un tiers).
        if not action.params.get("client_id"):
            return [self.skip(
                target=action.target, title="OAuth flow non testé — config manquante",
                evidence=("Requiert params.client_id (le client OAuth ENREGISTRÉ de l'opérateur — jamais "
                          "un tiers). Optionnel : params.authorize_url, params.redirect_param (défaut "
                          "redirect_uri), params.attacker_redirect (hôte bénin contrôlé), params.response_type "
                          "(défaut code), params.legit_redirect (redirect_uri valide pour la sonde state/PKCE), "
                          "params.state/code_challenge, params.scope/idp_hint, params.chainable, "
                          "params.client_validates_state, params.public_client, params.pkce_enforced, "
                          "params.headers."),
                poc=self.dry(action))]

        p = action.params
        attacker = str(p.get("attacker_redirect") or self._DEFAULT_ATTACKER)
        legit = str(p.get("legit_redirect") or p.get("redirect_uri") or attacker)
        seen_network = False

        # --- Sonde R : redirect_uri bypass (CWE-601) — redirect_uri attaquant, state+PKCE valides ---
        _, r_st, r_body, r_pairs = self._authorize(
            action, redirect_uri=attacker, include_state=True, include_pkce=True)
        if r_st is not None:
            seen_network = True
        controllable, via = self._redirect_controllable(r_st, r_body, r_pairs, attacker)
        r_location = self._get(r_pairs, "Location") or ""
        chainable, chain_why = self._chainable(action, r_location)
        scope_note = self._scope_note(action, r_location, r_body)

        # --- Sonde B : requête d'autorisation SANS state NI code_challenge (state CSRF + PKCE) ---
        _, b_st, b_body, b_pairs = self._authorize(
            action, redirect_uri=legit, include_state=False, include_pkce=False)
        if b_st is not None:
            seen_network = True
        b_location = self._get(b_pairs, "Location") or ""
        code_issued, code_where = self._code_issued(b_st, b_body, b_location)

        # (5) DÉGRADATION GRACIEUSE : aucune réponse du tout (transport indisponible) -> skipped (offline).
        if not seen_network:
            return [self.degraded(
                target=action.target,
                title="OAuth flow non testé — réseau indisponible (dégradation gracieuse)",
                evidence="Aucune réponse de l'endpoint d'autorisation (transport indisponible) ; offline-safe.",
                poc=self.dry(action))]

        findings = []

        # (a) redirect_uri bypass (CWE-601) — promu SEULEMENT si attaquant-contrôlable ET chaînable.
        redir_proven = controllable and chainable
        if redir_proven:
            r_title = "OAuth redirect_uri bypass CONFIRMÉ — destination attaquant acceptée ET chaînable (vol de code/jeton)"
        elif controllable:
            r_title = "OAuth redirect_uri NON promu — destination attaquant acceptée mais NON chaînée (reste tested)"
        else:
            r_title = "OAuth redirect_uri non confirmé — destination non attaquant-contrôlée (pas de verdict aveugle)"
        findings.append(self.finding(
            _proven=bool(redir_proven),                  # PREUVE concrète (contrôlable ET chaînable)
            target=action.target, title=r_title, severity=("HIGH" if redir_proven else "INFO"),
            category="CWE-601", cwe="CWE-601", mitre=self.mitre, fix=self.fix,
            status=("vulnerable" if redir_proven else "tested"), tool=self.tool,
            evidence=(f"redirect_uri attaquant (BÉNIGN, contrôlé par l'opérateur)={attacker} ; "
                      f"attaquant_contrôlable={controllable} ({via or '—'}) ; chaînable={chainable} "
                      f"({chain_why}) ; {scope_note} ; redirection NON suivie (sûreté + scope) ; "
                      f"client_id de l'OPÉRATEUR (jamais un tiers) ; session gouvernée non journalisée"),
            poc=(f"# {self._curl(base + ('&' if '?' in base else '?') + urllib.parse.urlencode({p.get('redirect_param', 'redirect_uri'): attacker}), dict(p.get('headers', {})))}\n"
                 f"# (redirections NON suivies) PREUVE = la réponse redirige vers {attacker} dans un flux "
                 f"émetteur de code/jeton (redirect_uri bypass = vol de code/jeton)")))

        # (b) state manquant (CWE-352, CSRF sur le flux) — code émis SANS state, sauf si l'opérateur
        #     atteste que SON client valide le state (params.client_validates_state=True).
        state_proven = code_issued and (p.get("client_validates_state") is not True)
        findings.append(self.finding(
            target=action.target,
            title=("OAuth `state` non imposé CONFIRMÉ — code/jeton émis sans state (CSRF sur le flux)"
                   if state_proven else "OAuth `state` — non promu (code non émis sans state, ou client valide le state)"),
            severity=("HIGH" if state_proven else "INFO"),
            category="CWE-352", cwe="CWE-352", mitre=self.mitre, fix=self.fix,
            status=("vulnerable" if state_proven else "tested"), tool=self.tool,
            _proven=bool(state_proven),                  # PREUVE concrète (code émis sans state)
            evidence=(f"requête d'autorisation SANS `state` -> code_émis={code_issued} ({code_where or '—'}) ; "
                      f"client_valide_state={p.get('client_validates_state')} ; sans liaison anti-CSRF "
                      f"(state ni PKCE), un code émis = CSRF sur le flux OAuth (CWE-352) ; flux de l'opérateur ; "
                      f"redirection NON suivie"),
            poc=(f"# GET {base} avec client_id de l'opérateur, redirect_uri légitime, SANS state\n"
                 f"# PREUVE = un code/jeton est émis malgré l'absence de `state` (aucune liaison anti-CSRF)")))

        # (c) PKCE downgrade/absence (CWE-287) — code émis SANS code_challenge pour un client public,
        #     sauf si l'opérateur atteste PKCE imposé (pkce_enforced) ou client confidentiel (public_client=False).
        pkce_proven = (code_issued and (p.get("public_client") is not False)
                       and (p.get("pkce_enforced") is not True))
        findings.append(self.finding(
            target=action.target,
            title=("OAuth PKCE non imposé CONFIRMÉ — code émis sans code_challenge (downgrade, client public)"
                   if pkce_proven else "OAuth PKCE — non promu (code non émis sans challenge, ou PKCE imposé/client confidentiel)"),
            severity=("MEDIUM" if pkce_proven else "INFO"),
            category="CWE-287", cwe="CWE-287", mitre=self.mitre, fix=self.fix,
            status=("vulnerable" if pkce_proven else "tested"), tool=self.tool,
            _proven=bool(pkce_proven),                   # PREUVE concrète (code émis sans PKCE, client public)
            evidence=(f"requête d'autorisation SANS `code_challenge` -> code_émis={code_issued} "
                      f"({code_where or '—'}) ; public_client={p.get('public_client')} ; "
                      f"pkce_enforced={p.get('pkce_enforced')} ; un code émis sans PKCE pour un client public = "
                      f"downgrade PKCE (CWE-287) ; flux de l'opérateur ; redirection NON suivie"),
            poc=(f"# GET {base} avec client_id public de l'opérateur, SANS code_challenge\n"
                 f"# PREUVE = un code est émis malgré l'absence de PKCE (downgrade pour client public)")))

        return findings
