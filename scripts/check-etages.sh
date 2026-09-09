#!/usr/bin/env bash
#
# check-etages — les étages 1 et 2 font-ils vraiment ZÉRO entrée-sortie ? (C1)
#
# # CE QUE CE CONTRÔLE DIT, ET QUE LA COMPILATION NE DIRA JAMAIS
#
# Un codec qui se met à lire un fichier compile parfaitement. Il passe clippy, il
# passe les essais. Ce qu'il perd est invisible jusqu'au jour où l'on veut
# l'éprouver : une grammaire qui possède une socket ne s'éprouve qu'en simulant
# un réseau, ce qui mesure la simulation.
#
# **ET C'EST CE CONTRÔLE QUI GARDE LA PILE QUIC TRANSPLANTABLE** (C15). Celle
# d'`air-mail-server` se réutilise ici parce qu'elle a été écrite sous cette
# règle ; la nôtre devra migrer dans `air` sous la même condition.
#
# # LA LISTE DES ÉTAGES EST ICI, ET ELLE NE PEUT PAS DÉRIVER
#
# Une liste écrite dans un script finit toujours par diverger de la réalité —
# quelqu'un ajoute une crate, oublie de la classer, et elle échappe au contrôle
# sans que rien ne le dise.
#
# Ce script ferme ce trou : il lit les membres du workspace et **exige que
# CHACUN soit classé**. Une crate non classée fait échouer le contrôle. On ne
# peut donc pas en ajouter une en silence.
#
# # CE QU'IL NE PEUT PAS VOIR
#
# Il lit du texte. Une entrée-sortie atteinte à travers une dépendance dont le
# nom ne dit rien lui échappe — c'est pourquoi il inspecte AUSSI les manifestes,
# et pourquoi la revue reste nécessaire.

set -euo pipefail

cd "$(dirname "$0")/.."

# ── La classification ────────────────────────────────────────────────────────
#
# Elle vit dans `etages.sh`, et elle y vit SEULE : voir l'en-tête de ce
# fichier pour ce que la duplication avait coûté.
. "$(dirname "$0")/etages.sh"

# ── Ce qui est interdit aux étages 1 et 2 ────────────────────────────────────
#
# `std::io` EN FAIT PARTIE, et c'est délibéré : un codec écrit dans une tranche
# ou dans un `Vec`, jamais dans un `Write`. Laisser entrer le trait ferait entrer
# l'abstraction d'entrée-sortie par la porte du confort.
#
# `SystemTime` et `Instant` aussi : l'heure est un PARAMÈTRE de l'étage 2
# (`docs/contraintes.md` C1), et une machine à états qui la lirait elle-même ne
# se piloterait plus depuis un essai.
# `core::net` N'EST PAS INTERDIT, et il faut le dire ici plutôt que de laisser
# quelqu'un l'ajouter à cette liste par symétrie avec `std::net`. Une `IpAddr`
# est une VALEUR — pas une socket, pas un descripteur, rien qui attende. C'est
# `std::net` qui porte l'entrée-sortie, et c'est lui qui est refusé.
#
# La réimplémenter reviendrait à réécrire un analyseur d'IPv6 pour le plaisir
# d'en avoir un à nous, avec les bogues qui vont avec.
chemins_interdits=(
    'std::fs'
    'std::net'
    'std::io'
    'std::process'
    'std::thread'
    'std::time::SystemTime'
    'std::time::Instant'
    'tokio'
)

# Des crates qu'aucune grammaire ni aucune décision n'a de raison de tirer.
deps_interdites=(
    'tokio'
    'async-std'
    'smol'
    'mio'
    'reqwest'
    'rusqlite'
)

echo 'check-etages — les étages 1 et 2 ne font aucune entrée-sortie (C1)'
echo

# ── Tous les membres sont-ils classés ? ──────────────────────────────────────
mapfile -t membres < <(
    sed -n '/^\[workspace\]/,/^\[/p' Cargo.toml \
        | grep -oE '"crates/[a-z0-9-]+"' \
        | tr -d '"' \
        | sed 's|crates/||'
)

if [ "${#membres[@]}" -eq 0 ]; then
    echo "ÉCHEC : aucun membre lu dans Cargo.toml — le contrôle n'a RIEN examiné."
    exit 1
fi

classees=("${etage1[@]}" "${etage2[@]}" "${hors[@]}")
non_classees=()
for membre in "${membres[@]}"; do
    trouve=0
    for classee in "${classees[@]}"; do
        [ "$membre" = "$classee" ] && trouve=1 && break
    done
    [ "$trouve" -eq 0 ] && non_classees+=("$membre")
done

if [ "${#non_classees[@]}" -gt 0 ]; then
    echo "ÉCHEC : ${#non_classees[@]} crate(s) du workspace ne sont classées dans aucun étage :"
    printf '  %s\n' "${non_classees[@]}"
    echo
    echo "Classez-les dans ce script. Une crate non classée échappe au contrôle,"
    echo "et c'est ainsi qu'une entrée-sortie entre sans que personne ne la voie."
    exit 1
fi

echo "membres du workspace : ${#membres[@]}, tous classés"
echo "sous contrôle        : ${#etage1[@]} de l'étage 1, ${#etage2[@]} de l'étage 2"
echo

# ── Le contrôle lui-même ─────────────────────────────────────────────────────
violations=0
fichiers_lus=0

for crate in "${etage1[@]}" "${etage2[@]}"; do
    src="crates/$crate/src"
    manifeste="crates/$crate/Cargo.toml"

    if [ ! -d "$src" ]; then
        echo "ÉCHEC : $src n'existe pas."
        violations=$((violations + 1))
        continue
    fi

    while IFS= read -r fichier; do
        fichiers_lus=$((fichiers_lus + 1))
        for interdit in "${chemins_interdits[@]}"; do
            # Les lignes de commentaire sont EXCLUES : ce document-ci nomme
            # `tokio` et `std::net` pour expliquer pourquoi ils sont interdits,
            # et une crate a le droit d'en faire autant.
            if grep -nE "^[^/]*(^|[^a-zA-Z_:])${interdit//::/::}" "$fichier" \
                | grep -vE '^\s*[0-9]+:\s*(//|\*)' >/dev/null 2>&1; then
                echo "VIOLATION  $fichier"
                echo "           emploie \`$interdit\` — interdit à l'étage de $crate"
                violations=$((violations + 1))
            fi
        done
    done < <(find "$src" -name '*.rs' -type f)

    for dep in "${deps_interdites[@]}"; do
        if grep -qE "^\s*${dep}\s*[.=]" "$manifeste" 2>/dev/null; then
            echo "VIOLATION  $manifeste"
            echo "           déclare \`$dep\` — aucune grammaire ni décision n'en a besoin"
            violations=$((violations + 1))
        fi
    done
done

echo "fichiers Rust examinés : $fichiers_lus"
echo

if [ "$fichiers_lus" -eq 0 ]; then
    echo "ÉCHEC : aucun fichier Rust examiné — le contrôle ne vaut rien."
    exit 1
fi

if [ "$violations" -gt 0 ]; then
    echo "ÉCHEC : $violations violation(s) de C1."
    exit 1
fi

echo "OK : les étages 1 et 2 ne touchent ni fichier, ni socket, ni horloge."
