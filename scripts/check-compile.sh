#!/usr/bin/env bash
#
# check-compile — tout ce dépôt compile-t-il, essais compris ?
#
# `--all-targets` et non un simple `cargo check` : un essai qui ne compile plus
# est un essai qui ne tourne plus, et `cargo check` seul ne l'apprend jamais.
#
# `--locked` : le `Cargo.lock` est committé. Une barrière qui le laisserait
# bouger en silence ne vérifierait plus le build qu'elle prétend vérifier.
#
# **ET IL COUVRE `fuzz/`, QUE RIEN D'AUTRE ICI NE COMPILE.** Cette crate vit hors
# du workspace : ni `clippy --workspace`, ni `cargo build --workspace`, ni
# `cargo test --workspace` n'y entrent. Son seul autre contrôle serait le job de
# fuzz, bien plus loin — et sur `air-mail-server`, deux tranches y ont perdu une
# campagne pour une signature de trait non répercutée.
#
# Le lancer dès qu'un type public d'`asl-id` change coûte une seconde et évite
# une campagne perdue.

set -euo pipefail

cd "$(dirname "$0")/.."

echo 'check-compile — le workspace et `fuzz/`, essais compris'
echo

violations=0

if cargo check --workspace --all-targets --locked; then
    echo "workspace : compile"
else
    echo "ÉCHEC : le workspace ne compile pas."
    violations=$((violations + 1))
fi

# `--target` NOMMÉ : `cargo-fuzz` 0.13.2 choisit musl par défaut, dont la libc
# statique est incompatible avec le sanitizer. Ici on ne fait que compiler, mais
# nommer la même cible qu'au fuzz évite d'avoir deux réponses selon le script.
if (cd fuzz && cargo check --target x86_64-unknown-linux-gnu --locked); then
    echo "fuzz/     : compile"
else
    echo "ÉCHEC : \`fuzz/\` ne compile pas — et rien d'autre ici ne le dirait."
    violations=$((violations + 1))
fi

if [ "$violations" -gt 0 ]; then
    echo
    echo "ÉCHEC : $violations portée(s) ne compilent pas."
    exit 1
fi

echo
echo 'OK : les deux portées compilent.'
