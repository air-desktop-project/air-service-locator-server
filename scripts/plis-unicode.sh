#!/usr/bin/env bash
# plis-unicode.sh — régénère la table du PLIAGE SIMPLE DE CASSE d'Unicode que
# lit `asl-registre` (`crates/asl-registre/src/plis.rs`).
#
#     scripts/plis-unicode.sh CaseFolding.txt > crates/asl-registre/src/plis.rs
#
# # POURQUOI UNE TABLE ÉCRITE ICI, ET NON UNE CRATE
#
# L'alias de domaine se cherche « après NFC et pliage simple de casse »
# (`docs/modele.md` §2.11). Le NFC vient d'`unicode-normalization`, en Rust pur ;
# le pliage SIMPLE — un caractère pour un caractère, statuts C et S de
# `CaseFolding.txt` — n'a pas de crate légère : `caseless` fait le pliage
# COMPLET (« ß » devient « ss »), et ICU4X tirerait une vingtaine de paquets
# pour quinze cents paires. Une table de quinze cents paires se relit.
#
# # LA VERSION D'UNICODE EST ÉPINGLÉE, ET C'EST UNE DÉCISION (2026-09-26)
#
# Deux annuaires qui plieraient différemment un caractère récent répondraient
# différemment à la même recherche. La table DOIT donc venir de la même version
# que les tables NFC d'`unicode-normalization`, épinglée à la lettre dans
# `Cargo.toml` : aujourd'hui **17.0.0** des deux côtés, ce que l'essai
# `la_version_d_unicode_est_la_meme_des_deux_cotes` tient. Changer de version
# est une rupture qui se déploie sur les deux racines et les annuaires locaux
# ensemble.
#
# La source se télécharge une fois, se vérifie, et ne se relit plus :
#
#     curl -O https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt
#     sha256sum CaseFolding.txt
#     # ff8d8fefbf123574205085d6714c36149eb946d717a0c585c27f0f4ef58c4183
set -euo pipefail

source="${1:?le chemin de CaseFolding.txt}"
version="$(head -1 "$source" | sed -n 's/^# CaseFolding-\([0-9.]*\)\.txt$/\1/p')"
[ -n "$version" ] || { echo "ce n'est pas un CaseFolding.txt : $(head -1 "$source")" >&2; exit 1; }
empreinte="$(sha256sum "$source" | cut -d' ' -f1)"
paires="$(grep -E '^[0-9A-F]+; [CS]; ' "$source" | awk -F'; ' '{ printf "%06s (0x%s, 0x%s),\n", $1, $1, $3 }' | LC_ALL=C sort | sed 's/^ *[0-9A-F]* /    /')"
combien="$(printf '%s\n' "$paires" | wc -l)"

cat <<EOF
//! Le pliage simple de casse d'Unicode ${version} — GÉNÉRÉ par
//! \`scripts/plis-unicode.sh\`, à ne pas modifier à la main.
//!
//! Source : \`CaseFolding-${version}.txt\`, statuts C et S, SHA-256
//! \`${empreinte}\`.

/// La version d'Unicode de cette table.
pub const VERSION: (u8, u8, u8) = ($(echo "$version" | sed 's/\./, /g'));

/// Chaque caractère qui se plie, et ce en quoi il se plie — triée par le
/// premier, pour la recherche dichotomique.
pub const PLIS: [(u32, u32); ${combien}] = [
${paires}
];
EOF
