<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Repository rules — read BEFORE committing

[English](AGENTS.md) | [Français](AGENTS.fr.md)

This file exists to be read **without any prior context**: by a new contributor, or
by an agent that opens this repository with no memory of what came before. The two rules below are not
negotiable, and they are **checked by the machine** — a commit that breaks them is refused.

## 1. A single public identity: `guatxlabs <noreply@guatx.com>`

```sh
git config user.name  guatxlabs
git config user.email noreply@guatx.com
```

**No personal or named address**, ever — neither as author nor as committer. A repository
published under a collective must not expose the personal account of whoever writes it.

This rule has a useful history: for months the history carried two identities for the
same person, one of them a personal GitHub account that came in through **editing via the web interface**. A
`.mailmap` did not fix it — GitHub's *Contributors* page matches commits to accounts
by the address stored in the commit bytes. The history had to be rewritten.

## 2. A commit message addresses a PUBLIC READER

Write for someone who was not in the room, who does not know you, and who must be able to
act on what they read. Say **what changes and why**.

The guard reads commit messages in **French**: the refused and admitted phrasings below are quoted
in French, as the guard reads them, each followed by an English gloss in parentheses.

**Forbidden** — the commit is not a conversation transcript:

* first-person investigation narrative (« j'avais écarté ce champ » (*I had ruled out this field*), « ma vérification » (*my check*));
* direct address to an interlocutor (« comme vous l'avez demandé » (*as you asked*), « merci de vérifier » (*please check*));
* the session chronology as narrative thread (« cette session a produit… » (*this session produced…*)).

**Admitted, and not to be confused with the above**:

* the **voice of the tool** — « un `skipped` dit *je n'ai PAS pu vérifier* » (*a `skipped` says "I could NOT verify"*) states the meaning of a status;
* a **measurement date** — « MESURÉ le 2026-08-16 » (*MEASURED on 2026-08-16*) is traceability, not a diary;
* a **long "why"**. Length was never the defect; addressing was.

The chronology of an investigation does not belong in the public repository: `ROADMAP.md` is a
**summary** there — what is delivered, what remains open, the accepted limits — and not a campaign
log. The narrative of an investigation is kept outside the repository; what must survive of it publicly
is the **decision** and its **why**, in the message of the commit that carries it.

### The first person: forbidden bare, admitted QUOTED

The guard reads **forms**, not intentions — it does not know who is speaking. Every elision of « je » (*I*)
and every possessive (`mon`, `ma`, `mes` — *my*) are therefore refused **as a block**, whatever the verb that
follows. This is not gratuitous strictness: the version that enumerated the verbs
(`j'ai trouvé|corrigé|mesuré|…` — *I found|fixed|measured|…*) let **56 occurrences** through — `j'ai inséré`, `j'ai composé`,
`mon propre garde`, `de mon côté`, `ma main` (*I inserted*, *I composed*, *my own guard*, *on my side*, *my hand*) — in commits it declared compliant.

The voice of the tool is nevertheless written in the first person, and must pass. It passes by carrying
a **quotation mark** — this is one:

| mark | example |
|---|---|
| quotation marks | un `skipped` dit « je n'ai PAS pu vérifier » (*a `skipped` says "I could NOT verify"*) |
| code | le motif `mon propre garde` n'était pas couvert (*the pattern `mon propre garde` was not covered*) |
| `>` line | `> un `tested` dit « j'ai vérifié, rien trouvé »` (*a tested status says "I checked, found nothing"*) |

This is also what lets the rule quote what it forbids without refusing itself. A
quotation does not cross a paragraph break, and **a code span must not be split by a
line break** — otherwise the backtick pairing shifts and the quoted content becomes
visible to the guard again.

### `hier` is forbidden, `aujourd'hui` is not

(`hier` = *yesterday*, `aujourd'hui` = *today*.) Asymmetry measured, not assumed. « hier » has no referent for a reader who arrives six months
later. « aujourd'hui » serves to say *in the current state of the code* — « aucun réglage n'expose ce
levier aujourd'hui » (*no setting exposes this lever today*) — in 8 uses out of 9 found in this history.

## How these rules are held

| barrier | reach | activation |
|---|---|---|
| `commit-msg` hook | local workstation, before the commit exists | `make hooks` (once per clone) |
| `registre public` CI job (*public register*) | everything that reaches the repository | automatic |

The hook **is not enough**: it is not carried by `git clone` and is never run by
GitHub's web editing — the very path through which the problem had come in. **The CI is what
closes.** The hook only saves having to fix things afterwards.

Both identity slots are checked, **author and committer**: a `cherry-pick`, a `rebase` or
web editing leave the author intact and write another identity as committer — and that is
how the personal account had come in. A range that git could not read is a **refusal**, not
silence: a barrier fails closed.

Check a message before committing, or a range already written:

```sh
python3 scripts/check_commit_register.py --message-file <fichier>
python3 scripts/check_commit_register.py --range origin/main..HEAD
```

### What a guard cannot do, and what to do instead

**A guard only catches what it knows how to describe.** The 56 occurrences cited above were not
found by it — it declared them compliant — but by an **independent audit**, written with
other patterns, deliberately broader, and compared line by line. This repository has four hand-kept lists
that outlived their purpose: `_RATE_FLAG_KINDS`, `_SQL_ERROR_SIGNS`, the exemptions of the
document guard, and this enumeration of verbs.

Before asserting that a repository is clean: write a check **independent of the guard**, compare, and
sort the false positives by hand. A green guard only proves the absence of what it looks for.

### If you rewrite history

Three traps encountered, each of which cost a redo:

* `git filter-repo` **resets the working tree to the committed state**. Any uncommitted change
  is lost — commit first, rewrite afterwards.
* without `--prune-empty=never`, a commit whose only change becomes a no-op after rewriting
  is **deleted along with its message**. Check the commit count before/after.
* filter-repo **rewrites the SHAs cited in messages**: a literal replacement that contains
  a SHA will no longer match on the next pass.

## The rest

The technical invariants (fail-closed scope-guard, 4-layer ROE gate, exploit floor, append-only
ledger, secret redaction, coverage-safe planner, evidence-backed findings) are in
[`CONTRIBUTING.md`](CONTRIBUTING.md). A PR that weakens one of them is refused, whatever its
usefulness otherwise.
