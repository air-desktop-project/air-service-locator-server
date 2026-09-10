#!/usr/bin/env bash
#
# Construit le paquet Debian de l'annuaire.
#
# **LA CIBLE DE DÉPLOIEMENT EST UBUNTU**, et c'est elle qui décide du format.
# Debian et Ubuntu partagent `dpkg`, la charte et l'emplacement des unités
# systemd ; ce paquet vaut donc pour les deux, mais c'est la seconde qu'il vise.
#
# ── IL N'ÉCRIT PAS L'UNITÉ, IL L'INSTALLE ───────────────────────────────────
#
# L'unité vit dans `paquet/asl-server.service`, versionnée et relisible. La
# recopier ici donnerait deux textes à maintenir, et c'est celui qu'on oublie
# qui finirait sur la machine.
#
# ── CE QUE CE PAQUET NE FAIT DÉLIBÉRÉMENT PAS ───────────────────────────────
#
# Il n'active ni ne démarre le service, et il lui manque exprès deux choses :
#
#   — `--attestation`, qui n'a pas de défaut (`protocole.md` §2.1) ;
#   — le certificat, qui n'existe pas encore au moment de l'installation.
#
# Un paquet qui démarrerait un service voué à échouer apprendrait à l'exploitant
# que les échecs de ce service sont normaux.
#
# ── ET IL N'EFFACE JAMAIS L'ANNUAIRE ────────────────────────────────────────
#
# Voir `postrm` : même `dpkg --purge` laisse `/var/lib/asl-server` en place. Il
# porte les comptes, les machines et les autorisations que des humains ont
# accordées — un paquet qui les efface sur une commande de nettoyage est un
# paquet qui dépossède des gens de leur compte.
set -euo pipefail

depot=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$depot"

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
sortie="."
construire=1
architecture=$(dpkg --print-architecture 2>/dev/null || echo amd64)

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version="${2-}"; shift 2 ;;
        --sortie) sortie="${2-}"; shift 2 ;;
        --sans-construire) construire=0; shift ;;
        --aide|-h)
            sed -n '3,31p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "paquet.sh : option inconnue : $1" >&2; exit 2 ;;
    esac
done

dit() { printf '  %s\n' "$*"; }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

titre "contrôles préalables"
# **ON REFUSE PLUTÔT QUE DE BRICOLER.** Un `.deb` se fabrique aussi à la main
# avec `ar` et `tar` ; le résultat serait subtilement différent de ce que `dpkg`
# attend, et le défaut se découvrirait sur la machine de quelqu'un.
for outil in dpkg-deb dpkg-shlibdeps; do
    if ! command -v "$outil" > /dev/null 2>&1; then
        echo "paquet.sh : \`$outil\` est absent — il vient du paquet \`dpkg-dev\`" >&2
        exit 1
    fi
done
dit "dpkg-deb et dpkg-shlibdeps sont là"

if [ "$construire" -eq 1 ]; then
    titre "construction"
    cargo build --release --bin asl-server
    dit "binaire construit en release"
fi

if [ ! -x target/release/asl-server ]; then
    echo "paquet.sh : target/release/asl-server est absent" >&2
    exit 1
fi

arbre=$(mktemp -d)
trap 'rm -rf "$arbre"' EXIT

titre "arborescence"
# `/usr/bin` et non `/usr/local` : ce dernier appartient à l'administrateur
# (§9.1.2 de la charte Debian), et un paquet n'y a rien à faire.
install -D -m 0755 target/release/asl-server "$arbre/usr/bin/asl-server"

# **`/usr/lib` ET NON `/lib`** : sur un système à `/usr` fusionné — toute Debian
# depuis bookworm, toute Ubuntu depuis 21.04 — `/lib` EST un lien vers
# `/usr/lib`, et expédier sous l'alias oblige `dpkg` à le démêler.
#
# **ET NON `/etc/systemd/system`**, qui est réservé à ce que l'administrateur
# écrit lui-même : y poser un fichier de paquet lui retirerait l'endroit d'où il
# peut passer devant.
install -D -m 0644 paquet/asl-server.service \
    "$arbre/usr/lib/systemd/system/asl-server.service"

# Le répertoire des clés. Le PAQUET le crée, mais n'y met rien : le certificat
# est émis pour un nom d'hôte qu'un paquet ne connaît pas.
install -d -m 0750 "$arbre/etc/asl-server"

install -d -m 0755 "$arbre/usr/share/doc/asl-server"
install -m 0644 LICENSE "$arbre/usr/share/doc/asl-server/copyright"

# **LE FRAGMENT D'EXEMPLE VA DANS LA DOCUMENTATION, ET NON DANS `/etc`.**
# Posé sous `/etc/systemd/system/asl-server.service.d/`, il serait CHARGÉ — et
# le paquet aurait choisi la posture d'attestation à la place de l'exploitant,
# ce que toute cette affaire s'emploie à éviter.
cat > "$arbre/usr/share/doc/asl-server/attestation.conf.exemple" <<'EXEMPLE'
# À copier sous /etc/systemd/system/asl-server.service.d/attestation.conf,
# APRÈS avoir choisi laquelle des deux postures vous tenez.
#
#   exigee       — conforme à protocole.md §2.1, et AUCUN appareil ne pourra
#                  s'enrôler tant que la vérification n'est pas écrite.
#   facultative  — n'importe qui peut créer un compte sur cet annuaire.
#
# Aucune des deux ne peut être choisie à votre place ; c'est pourquoi le
# service ne démarre pas tant que ce fragment n'existe pas.

[Service]
Environment=ASL_ATTESTATION=facultative
EXEMPLE
chmod 0644 "$arbre/usr/share/doc/asl-server/attestation.conf.exemple"
dit "binaire, unité, /etc/asl-server, documentation"

titre "dépendances, calculées et non devinées"
# **`dpkg-shlibdeps` LIT LE BINAIRE.** Écrire `libc6 (>= 2.34)` à la main serait
# vrai le jour où on l'écrit, et faux à la première mise à jour de la chaîne de
# compilation — exactement la dérive que ce dépôt passe son temps à traquer.
install -d -m 0755 "$arbre/debian"
printf 'Source: asl-server\n\nPackage: asl-server\nArchitecture: any\n' \
    > "$arbre/debian/control"
if ! depends=$(cd "$arbre" && dpkg-shlibdeps -O --ignore-missing-info \
    usr/bin/asl-server 2>"$arbre/debian/plainte" \
    | sed 's/^shlibs:[A-Za-z]*=//'); then
    echo "paquet.sh : \`dpkg-shlibdeps\` a refusé :" >&2
    sed 's/^/    /' "$arbre/debian/plainte" >&2
    exit 1
fi
rm -rf "$arbre/debian"
if [ -z "$depends" ]; then
    echo "paquet.sh : aucune dépendance calculée — c'est invraisemblable" >&2
    exit 1
fi
dit "$depends"

titre "métadonnées et scripts de mainteneur"
install -d -m 0755 "$arbre/DEBIAN"
taille=$(du -sk --exclude=DEBIAN "$arbre" | cut -f1)
cat > "$arbre/DEBIAN/control" <<CONTROL
Package: asl-server
Version: $version
Section: net
Priority: optional
Architecture: $architecture
Depends: $depends
Installed-Size: $taille
Maintainer: Thierry Delhaise <thierry.delhaise@gmail.com>
Homepage: https://github.com/air-desktop-project/air-service-locator-server
Description: annuaire federe de services reseau, ecrit en Rust
 Un daemon prend le port que le systeme lui donne, l'ANNONCE, et ses clients le
 CHERCHENT : aucun n'a besoin d'un port fixe. HTTP/3 sur QUIC, IPv6 d'abord, et
 la connexion EST le bail.
 .
 Le paquet n'active ni ne demarre le service : il lui manque la posture
 d'attestation, qui n'a pas de defaut, et le certificat, qui est emis pour un
 nom d'hote qu'un paquet ne connait pas. Voir /usr/share/doc/asl-server/.
CONTROL

cat > "$arbre/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e

case "$1" in
    configure)
        # LE COMPTE EST SYSTÈME, SANS INTERPRÉTEUR ET SANS MOT DE PASSE : rien
        # ne doit pouvoir s'y connecter, il n'existe que pour porter le service.
        if ! getent passwd asl-server > /dev/null 2>&1; then
            adduser --system --group --no-create-home \
                --home /var/lib/asl-server --shell /usr/sbin/nologin \
                --quiet asl-server || true
        fi
        # **LA CLÉ PRIVÉE SE LIT PAR LE GROUPE, ET PAR PERSONNE D'AUTRE.**
        # Le répertoire appartient à root : le service la LIT, il n'a aucune
        # raison de pouvoir la remplacer.
        chown root:asl-server /etc/asl-server
        chmod 0750 /etc/asl-server
        ;;
esac

#DEBHELPER#

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi

# ON N'ACTIVE RIEN, ET ON DIT POURQUOI.
if [ "$1" = "configure" ] && [ -z "${2-}" ]; then
    cat <<'SUITE'

asl-server est installé, mais NI ACTIVÉ NI DÉMARRÉ : il lui manque deux choses
qu'un paquet ne peut pas décider.

  1. la posture d'attestation — `exigee` refuse tous les enrôlements tant que la
     vérification n'est pas écrite ; `facultative` laisse n'importe qui créer un
     compte. Choisissez, puis :

         systemctl edit asl-server
         # [Service]
         # Environment=ASL_ATTESTATION=facultative

     Le modèle : /usr/share/doc/asl-server/attestation.conf.exemple

  2. le certificat, émis pour le nom sous lequel cet annuaire répond :

         /etc/asl-server/certificat.pem   (chaîne, en PEM)
         /etc/asl-server/cle.pem          (clé privée, 0640 root:asl-server)

  3. puis :

         systemctl enable --now asl-server

SUITE
fi

exit 0
POSTINST

cat > "$arbre/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e

# ON ARRÊTE AVANT DE RETIRER LES FICHIERS. Sans cela, le service tournerait sur
# un binaire effacé jusqu'au prochain redémarrage — et son journal parlerait
# d'une version qui n'est plus là.
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl stop asl-server > /dev/null 2>&1 || true
fi

#DEBHELPER#

exit 0
PRERM

cat > "$arbre/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi

#DEBHELPER#

# ── L'ANNUAIRE SURVIT AU PURGE, ET C'EST DÉLIBÉRÉ ───────────────────────────
#
# `dpkg --purge` efface la configuration d'un paquet. Ici, /var/lib/asl-server
# ne porte AUCUNE configuration — il porte des comptes, des machines, et les
# autorisations que des humains se sont accordées. Les effacer déposséderait des
# gens de leur compte sur une commande dont ce n'est pas l'objet.
#
# La clé privée non plus : elle a été posée par l'exploitant, et l'effacer sur
# un `purge` détruirait un secret que personne n'a demandé à détruire.
if [ "$1" = "purge" ]; then
    if [ -d /var/lib/asl-server ] || [ -d /etc/asl-server ]; then
        cat <<'RESTE'

asl-server : /var/lib/asl-server ET /etc/asl-server ONT ÉTÉ LAISSÉS EN PLACE.

Le premier porte les comptes, les machines et les autorisations ; le second,
votre clé privée. Un `purge` n'est pas une raison de déposséder des gens de leur
compte ni de détruire un secret. Pour les effacer vous-même, en sachant ce que
vous effacez :

    rm -rf /var/lib/asl-server /etc/asl-server
    deluser --system asl-server

RESTE
    fi
fi

exit 0
POSTRM

chmod 0755 "$arbre/DEBIAN/postinst" "$arbre/DEBIAN/prerm" "$arbre/DEBIAN/postrm"
dit "control, postinst, prerm, postrm"

titre "assemblage"
# **LA RACINE DU PAQUET EST `/`**, et son mode s'appliquerait à `/`.
# `mktemp -d` crée en 0700, ce qui est juste pour un répertoire jetable et
# catastrophique pour la racine d'un système.
chmod 0755 "$arbre"
mkdir -p "$sortie"
nom="$sortie/asl-server_${version}_${architecture}.deb"
# `--root-owner-group` : sans lui, les fichiers du paquet appartiendraient au
# compte qui l'a construit, dont le numéro ne veut rien dire ailleurs.
dpkg-deb --root-owner-group --build "$arbre" "$nom" > /dev/null
dit "$nom"

printf '\nOK : %s (%s)\n' "$nom" "$(du -h "$nom" | cut -f1)"
