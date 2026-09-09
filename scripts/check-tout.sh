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
# # L'ORDRE, EN DÉTAIL
#
#   1. `check-toolchain` — INSTANTANÉ, et il passe en premier parce qu'un verdict
#      rendu par la mauvaise toolchain ne vaut rien. Le savoir après trois
#      minutes, c'est jeter les trois minutes.
#   2. `check-etages`    — une seconde, et il dit une chose que la compilation ne
#      dira jamais : qu'un codec a commencé à lire un fichier.
#   3. `check-compile`   — une erreur de type se lit en une seconde.
#   4. `check-pile`      — le graphe résolu, donc les dépendances transitives.
#   5. `check-clippy`    — les lints du produit.
#   6. `cargo test`
#   7. `check-couverture` — LENTE : elle recompile tout sous instrumentation.
#      Elle passe donc APRÈS les essais ordinaires, qui disent la même chose en
#      quelques secondes quand quelque chose est cassé. Il n'y a aucune raison
#      d'attendre une recompilation complète pour apprendre qu'un essai échoue.
#   8. `check-format`    — EN DERNIER (voir ci-dessus).
#
# # CE QUI MANQUE ENCORE, ET QUI EST DIT PLUTÔT QUE TU
#
# `air-mail-server` en porte dix. Ce dépôt en porte SEPT. Celles qui manquent
# encore attendent le code qu'elles jugent : le fuzz n'a qu'une grammaire et pas
# encore de cible, le paquet `.deb` et l'installateur n'existent pas.
#
# `check-couverture` est ENTRÉE avec `asl-id`, la première crate à porter du
# code. Elle serait arrivée trop tard si on l'avait attendue davantage : c'est
# en écrivant la crate qu'on écrit les essais qui la couvrent, pas six mois
# après.
#
# **Et deux de celles qui EXISTENT le disent d'elles-mêmes aujourd'hui** :
# `check-pile` annonce qu'aucune crate tierce n'est dans le graphe, donc qu'il
# n'a rien examiné. C'est la vérité, et elle vaut mieux qu'un OK muet.

set -euo pipefail

cd "$(dirname "$0")/.."

barrieres=(
    scripts/check-toolchain.sh
    scripts/check-etages.sh
    scripts/check-compile.sh
    scripts/check-pile.sh
    scripts/check-clippy.sh
    scripts/check-format.sh
)

# `check-couverture` n'est PAS dans la liste ci-dessus : elle tourne après les
# essais, plus bas, parce qu'elle les relance elle-même sous instrumentation.

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

echo "═══ scripts/check-couverture.sh"
if ./scripts/check-couverture.sh; then
    echo "─── scripts/check-couverture.sh : OK"
else
    echo "─── scripts/check-couverture.sh : ÉCHEC"
    echecs+=("scripts/check-couverture.sh")
fi
echo

if [ "${#echecs[@]}" -gt 0 ]; then
    echo "ÉCHEC : ${#echecs[@]} barrière(s) refusent :"
    printf '  %s\n' "${echecs[@]}"
    exit 1
fi

echo "OK : les ${#barrieres[@]} barrières, la couverture et les essais passent."
echo
echo "Le DCO ne fait PAS partie de ce lot : il juge des messages de commit, donc"
echo "il se lance APRÈS avoir committé — scripts/check-dco.sh."
