#!/usr/bin/env bash
#
# check-pile — aucune pile QUIC ou HTTP/3 tierce n'entre dans le graphe. (C15)
#
# # POURQUOI CETTE BARRIÈRE EXISTE
#
# La pile QUIC et HTTP/3 de ce produit est celle d'`air-mail-server` : écrite
# ici, sans une ligne de C, déjà éprouvée par un autre produit, et destinée à
# migrer dans `air`.
#
# **Réimplémenter QUIC est le genre de décision qui paraît raisonnable un
# après-midi et coûte deux ans.** Tirer une pile tierce paraît encore plus
# raisonnable — et ferait entrer, en une ligne de manifeste, des dépendances C et
# un calendrier de publication qui ne sont pas les nôtres.
#
# # CE QUE CE CONTRÔLE FAIT, ET CE QU'IL NE PEUT PAS FAIRE
#
# Il lit le graphe RÉSOLU (`cargo metadata`), donc il voit les dépendances
# transitives — celles que personne n'a déclarées et que personne ne regarde.
# C'est là que ce genre de crate entre.
#
# **Il ne peut PAS voir une réimplémentation locale.** Un module qui écrirait une
# poignée de main QUIC dans nos propres crates lui est invisible. Cela relève de
# la revue, et c'est écrit ici pour qu'on ne croie pas le contraire.

set -euo pipefail

cd "$(dirname "$0")/.."

# Les piles tierces connues. La liste n'a pas à être exhaustive : le motif
# générique ci-dessous attrape ce qu'elle oublie.
interdites=(
    quinn quinn-proto quinn-udp
    quiche
    s2n-quic s2n-quic-core s2n-quic-transport
    msquic msquic-sys
    xquic
    h3 h3-quinn
)

# Ce qui nous appartient, et qui a donc le droit de porter ces mots.
motif_a_nous='^(asl|ams)-'

echo 'check-pile — aucune pile QUIC ou HTTP/3 tierce (C15)'
echo

# LE JSON SE LIT AVEC UN LECTEUR DE JSON, PAS AVEC UN `grep`.
#
# La première version de ce script extrayait `"name":"…"` à la main. Ce champ
# n'appartient pas qu'aux PAQUETS : chaque CIBLE en porte un. Sur un workspace de
# huit crates sans aucune dépendance, le script annonçait « 15 paquets, dont 7
# tierces » — les sept noms de cibles, avec leurs tirets bas.
#
# Il rendait donc un OK en croyant avoir examiné sept crates tierces qui
# n'existaient pas, et sautait le message « RIEN n'a été examiné » qui était la
# vérité. Un contrôle qui se trompe sur ce qu'il a regardé est pire qu'un
# contrôle absent : il rassure.
if ! metadata=$(cargo metadata --format-version 1 --locked 2>/dev/null); then
    echo "ÉCHEC : \`cargo metadata\` n'a pas répondu."
    exit 1
fi

if ! paquets=$(printf '%s' "$metadata" | python3 -c '
import json, sys
donnees = json.load(sys.stdin)
for nom in sorted({paquet["name"] for paquet in donnees["packages"]}):
    print(nom)
'); then
    echo "ÉCHEC : le JSON de \`cargo metadata\` n'a pas pu être lu."
    exit 1
fi

nombre=$(printf '%s\n' "$paquets" | grep -c . || true)
echo "paquets dans le graphe : $nombre"

# UN GRAPHE QUI NE CONTIENT QUE NOS CRATES N'A RIEN À EXAMINER, ET ON LE DIT.
# Un rapport vert qui n'a rien examiné est un mensonge poli.
tierces=$(printf '%s\n' "$paquets" | grep -vE "$motif_a_nous" || true)
nombre_tierces=$(printf '%s\n' "$tierces" | grep -c . || true)
echo "dont tierces           : $nombre_tierces"
echo

violations=0

for paquet in $paquets; do
    # Nos propres crates portent légitimement `quic` ou `h3` dans leur nom.
    if printf '%s' "$paquet" | grep -qE "$motif_a_nous"; then
        continue
    fi

    for interdite in "${interdites[@]}"; do
        if [ "$paquet" = "$interdite" ]; then
            echo "VIOLATION  $paquet — pile QUIC/HTTP-3 tierce"
            violations=$((violations + 1))
        fi
    done

    # Le filet générique : ce que la liste ci-dessus oublie.
    if printf '%s' "$paquet" | grep -qiE '(^|[-_])(quic|qpack)([-_]|$)'; then
        echo "VIOLATION  $paquet — son nom désigne une pile QUIC, et elle n'est pas de nous"
        violations=$((violations + 1))
    fi
done

# ── L'ÉPINGLAGE DE LA GREFFE ─────────────────────────────────────────────────
#
# Interdire une pile tierce ne suffit plus depuis que la nôtre vient d'un autre
# dépôt. Deux fautes passeraient sans bruit sous le contrôle ci-dessus, et
# toutes deux changent le code compilé sans qu'une ligne d'ici ait bougé :
#
#   — UNE DÉPENDANCE SUR UNE BRANCHE. `branch = "main"` recompile autre chose à
#     chaque `cargo update`, et un échec de CI ne dirait plus lequel des deux
#     dépôts a changé.
#   — DEUX RÉVISIONS DIFFÉRENTES. `ams-quic` sur un commit et `ams-h3` sur un
#     autre donneraient deux moitiés d'une pile qui n'ont jamais été éprouvées
#     ensemble. Cargo ne s'en plaindrait pas : ce sont deux sources distinctes.
if ! epinglage=$(printf '%s' "$metadata" | python3 -c '
import json, sys
donnees = json.load(sys.stdin)
# On groupe par DEPOT, jamais globalement : `rustls-rustcrypto` vient du depot
# de RustCrypto, et sa revision propre est legitime. Ce qui ne le serait pas,
# c est deux revisions du MEME depot.
depots = {}
branches = []
for paquet in donnees["packages"]:
    source = paquet.get("source") or ""
    if not source.startswith("git+"):
        continue
    depot = source.split("?")[0].split("#")[0]
    if "?rev=" in source:
        revision = source.split("?rev=")[1].split("#")[0]
        depots.setdefault(depot, {}).setdefault(revision, []).append(paquet["name"])
    else:
        branches.append(paquet["name"] + " <- " + source)
for nom in sorted(branches):
    print("BRANCHE " + nom)
for depot in sorted(depots):
    revisions = depots[depot]
    court = depot.rstrip("/").split("/")[-1].removesuffix(".git")
    if len(revisions) > 1:
        print("ECLATE " + court + " " + " ".join(sorted(revisions)))
    for revision in sorted(revisions):
        print("REV " + court + " " + revision + " " + " ".join(sorted(revisions[revision])))
'); then
    echo "ÉCHEC : l'épinglage des dépendances git n'a pas pu être lu."
    exit 1
fi

flottantes=$(printf '%s\n' "$epinglage" | grep '^BRANCHE ' || true)
if [ -n "$flottantes" ]; then
    echo "VIOLATION  des dépendances git ne sont pas épinglées sur un commit :"
    printf '%s\n' "$flottantes" | sed 's/^BRANCHE /           /'
    violations=$((violations + 1))
fi

eclates=$(printf '%s\n' "$epinglage" | grep '^ECLATE ' || true)
if [ -n "$eclates" ]; then
    echo "VIOLATION  un même dépôt est tiré sur plusieurs révisions :"
    printf '%s\n' "$eclates" | sed 's/^ECLATE /           /'
    violations=$((violations + 1))
fi

printf '%s\n' "$epinglage" | grep '^REV ' | while read -r _ depot revision reste; do
    echo "git $depot épinglé sur ${revision:0:7} : $(printf '%s' "$reste" | wc -w) crate(s)"
done
echo

if [ "$nombre_tierces" -eq 0 ]; then
    echo "Aucune crate tierce dans le graphe — RIEN n'a été examiné."
    echo "(c'est vrai tant que le produit n'est pas écrit ; ce ne le restera pas)"
    exit 0
fi

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations pile(s) tierce(s). La pile de ce produit vient"
    echo "        d'\`air-mail-server\` et migrera dans \`air\` (C15)."
    exit 1
fi

echo "OK : aucune pile QUIC ou HTTP/3 tierce dans le graphe."
