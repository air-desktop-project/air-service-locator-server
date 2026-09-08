#!/usr/bin/env bash
#
# check-tout — les barrières de ce dépôt, dans l'ordre, d'un seul geste.
#
# # L'ORDRE N'EST PAS ARBITRAIRE
#
# Ce qui répond vite répond tôt : une erreur de type se lit en une seconde, et
# l'apprendre après trois minutes de lints ne l'apprend pas mieux.
#
# LE FORMATAGE EST EN DERNIER, et c'est une leçon payée ailleurs : sur
# `air-mail-server`, il était en premier, il a échoué, et il est resté rouge
# seize poussées pendant lesquelles RIEN de ce qui juge le code n'a tourné. Une
# faute de forme ne doit pas cacher une faute de fond. Le script échoue toujours
# si le formatage cloche — c'est une barrière, pas un avis — mais tout ce qui
# juge le code a déjà parlé quand il le fait.
#
# # CE QUI MANQUE ENCORE, ET QUI EST DIT PLUTÔT QUE TU
#
# `air-mail-server` en porte dix. Ce dépôt en porte QUATRE, parce que les six
# autres mesureraient du vide : la couverture d'un workspace sans code vaut 100 %
# et n'atteste de rien ; le paquet `.deb` et l'installateur n'existent pas ; le
# fuzz n'a aucune grammaire à éprouver. Elles s'ajoutent AVEC le code qu'elles
# jugent, jamais avant — une barrière verte qui n'a rien examiné est un mensonge
# poli.

set -euo pipefail

cd "$(dirname "$0")/.."

barrieres=(
    scripts/check-compile.sh
    scripts/check-clippy.sh
    scripts/check-format.sh
)

echecs=()

for barriere in "${barrieres[@]}"; do
    echo "═══ $barriere"
    if "$barriere"; then
        echo "─── $barriere : OK"
    else
        echo "─── $barriere : ÉCHEC"
        echecs+=("$barriere")
    fi
    echo
done

echo "═══ cargo test --workspace --locked"
if cargo test --workspace --locked; then
    echo "─── essais : OK"
else
    echo "─── essais : ÉCHEC"
    echecs+=("cargo test")
fi
echo

if [ "${#echecs[@]}" -gt 0 ]; then
    echo "ÉCHEC : ${#echecs[@]} barrière(s) refusent :"
    printf '  %s\n' "${echecs[@]}"
    exit 1
fi

echo "OK : les ${#barrieres[@]} barrières et les essais passent."
echo
echo "Le DCO ne fait PAS partie de ce lot : il juge des messages de commit, donc"
echo "il se lance APRÈS avoir committé — scripts/check-dco.sh."
