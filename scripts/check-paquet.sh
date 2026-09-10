#!/usr/bin/env bash
#
# check-paquet — éprouve le paquet Debian que `scripts/paquet.sh` construit.
#
# ── POURQUOI CE CONTRÔLE EXISTE ─────────────────────────────────────────────
#
# Un paquet s'installe sur la machine de quelqu'un d'autre, avec les privilèges
# du superutilisateur, et ses scripts de mainteneur tournent SANS que personne
# les relise. C'est la seule chose de ce dépôt dont un défaut s'exécute en root
# chez un inconnu.
#
# Et ce paquet-ci porte deux promesses qu'aucun essai Rust ne peut tenir : que le
# `purge` ne déposséde personne de son compte, et que le service ne démarre pas
# avec une posture d'attestation choisie à la place de l'exploitant.
set -euo pipefail

racine=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$racine"

fautes=0
rate() { printf '\nÉCHEC : %s\n' "$*" >&2; fautes=$((fautes + 1)); }
titre() { printf '\n── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((70 - ${#1}))))"; }

# **CE QU'UN SCRIPT IMPRIME N'EST PAS CE QU'IL FAIT.** Les scripts de mainteneur
# CITENT les commandes qu'ils recommandent — `systemctl enable`, `rm -rf` — dans
# des « here-documents ». Chercher ces mots sans distinguer le dire du faire
# condamnerait précisément la bonne conduite : dire au lieu de faire.
denuder() {
    awk '
        /<<'"'"'[A-Z]+'"'"'$/ { fin = $NF; gsub(/[<'"'"']/, "", fin); dedans = 1; next }
        dedans && $0 == fin   { dedans = 0; next }
        !dedans               { print }
    ' "$1"
}

avant=0
commencer() { avant=$fautes; }
conclure() { [ "$fautes" -eq "$avant" ] && echo "OK — $1"; return 0; }

# **UNE MACHINE SANS `dpkg` NE PEUT PAS ÉPROUVER UN `.deb`**, et le prétendre
# serait pire que de s'abstenir.
if ! command -v dpkg-deb > /dev/null 2>&1 || ! command -v dpkg-shlibdeps > /dev/null 2>&1; then
    cat >&2 <<'ABSENT'

IGNORÉ : `dpkg-deb` ou `dpkg-shlibdeps` est absent de cette machine.

Ce contrôle ne peut pas s'exécuter, et n'a donc RIEN éprouvé. Il tourne en
intégration continue, où `dpkg-dev` est présent — c'est là que son verdict
compte.

ABSENT
    exit 0
fi

essai=$(mktemp -d)
trap 'rm -rf "$essai"' EXIT

echo "check-paquet — ce qui s'exécutera en root chez quelqu'un d'autre"

titre "1. le paquet se construit"
commencer
# **PAS DE `--sans-construire`.** S'en remettre à `target/release` sans le
# rebâtir, c'est éprouver un paquet qui porte un binaire vieux de plusieurs
# heures. `cargo` est incrémental : quand rien n'a changé, cela ne coûte rien.
if ! ./scripts/paquet.sh --sortie "$essai" > "$essai/construction" 2>&1; then
    rate "la construction échoue :
$(tail -20 "$essai/construction")"
    exit 1
fi
paquet=$(ls "$essai"/asl-server_*.deb)
conclure "$(basename "$paquet")"

titre "2. dpkg le relit, et ses dépendances sont CALCULÉES"
commencer
if ! dpkg-deb --info "$paquet" > "$essai/control" 2>&1; then
    rate "\`dpkg-deb --info\` refuse le paquet"
fi
# Une dépendance ÉCRITE À LA MAIN serait vraie le jour où on l'écrit, et fausse
# à la première mise à jour de la chaîne de compilation.
grep -q '^ Depends: .*libc6' "$essai/control" \
    || rate "les dépendances ne portent pas la libc — elles n'ont pas été calculées"
grep -q '^ Architecture: ' "$essai/control" || rate "pas d'architecture"
conclure "$(sed -n 's/^ Depends: //p' "$essai/control")"

titre "3. où le paquet pose ses fichiers"
commencer
dpkg-deb --contents "$paquet" > "$essai/contenu"
grep -q ' \./usr/local/' "$essai/contenu" \
    && rate "un fichier sous /usr/local, qui appartient à l'administrateur"
grep -q ' \./etc/systemd/system/' "$essai/contenu" \
    && rate "une unité sous /etc/systemd/system, où l'administrateur doit rester seul"
grep -q './usr/lib/systemd/system/asl-server.service' "$essai/contenu" \
    || rate "l'unité n'est pas sous /usr/lib/systemd/system"
grep -q './usr/bin/asl-server' "$essai/contenu" || rate "le binaire n'est pas là"
# **LA RACINE DU PAQUET NE DOIT PAS RESSERRER `/`.** `mktemp -d` crée en 0700 ;
# une racine expédiée dans ce mode rendrait le système inutilisable.
racine_mode=$(awk '$NF == "./" { print $1 }' "$essai/contenu")
[ "$racine_mode" = "drwxr-xr-x" ] \
    || rate "la racine du paquet est en $racine_mode, et non drwxr-xr-x"
conclure "usr/bin, usr/lib/systemd/system, etc/asl-server, usr/share/doc"

titre "4. l'unité du paquet est CELLE du dépôt"
commencer
# **DEUX COPIES D'UN MÊME TEXTE DIVERGENT.** `paquet.sh` installe
# `paquet/asl-server.service` telle quelle ; ce contrôle vérifie qu'aucune
# seconde version ne s'est glissée entre les deux.
install -d "$essai/deballe"
dpkg-deb --extract "$paquet" "$essai/deballe"
if ! cmp -s paquet/asl-server.service \
        "$essai/deballe/usr/lib/systemd/system/asl-server.service"; then
    rate "l'unité empaquetée diffère de paquet/asl-server.service"
fi
conclure "un seul texte, et c'est celui qu'on relit"

titre "5. l'unité tient debout, et n'accorde rien"
commencer
# `systemd-analyze verify` se plaint que `/usr/bin/asl-server` n'est pas là :
# c'est vrai, il n'est pas INSTALLÉ sur cette machine. Toute autre plainte
# compte.
if command -v systemd-analyze > /dev/null 2>&1; then
    systemd-analyze verify paquet/asl-server.service 2>&1 \
        | grep -v 'is not executable' > "$essai/unite" || true
    if [ -s "$essai/unite" ]; then
        rate "systemd se plaint de l'unité :
$(cat "$essai/unite")"
    fi
else
    echo "  (systemd-analyze absent — l'unité n'a pas été relue par systemd)"
fi
# **AUCUNE CAPACITÉ, ET AUCUN PRIVILÈGE À REGAGNER.** Le port par défaut est
# au-dessus de 1024 : cet annuaire n'a besoin de rien.
grep -q '^CapabilityBoundingSet=$' paquet/asl-server.service \
    || rate "l'unité n'écarte pas toutes les capacités"
grep -q '^NoNewPrivileges=yes$' paquet/asl-server.service \
    || rate "l'unité ne pose pas NoNewPrivileges"
grep -q '^User=asl-server$' paquet/asl-server.service \
    || rate "l'unité ne dit pas sous quel compte tourner"
grep -q '^RestrictAddressFamilies=AF_INET AF_INET6$' paquet/asl-server.service \
    || rate "l'unité n'enferme pas les familles d'adresses"
conclure "aucune capacité, aucun privilège à regagner, deux familles d'adresses"

titre "6. LA POSTURE D'ATTESTATION N'EST PAS CHOISIE PAR LE PAQUET"
commencer
# **C'EST LA PROMESSE QUI COMPTE LE PLUS APRÈS LE PURGE.** `facultative` laisse
# n'importe qui créer un compte sur cet annuaire. Un paquet qui la poserait par
# commodité livrerait la posture faible en silence.
# **ON NE REGARDE QUE CE QUI S'EXÉCUTE.** L'unité EXPLIQUE en commentaire
# pourquoi les accolades seraient fausses ; chercher la forme fautive sans
# retirer les commentaires condamnerait l'explication elle-même.
grep -v '^#' paquet/asl-server.service > "$essai/unite-nue"
grep -q 'ASL_ATTESTATION' "$essai/unite-nue" \
    || rate "l'unité ne passe pas la posture par l'environnement"
grep -q '\${ASL_ATTESTATION}' "$essai/unite-nue" \
    && rate "les accolades donneraient un argument VIDE au lieu de le retirer"
grep -q '^Environment=ASL_ATTESTATION' "$essai/unite-nue" \
    && rate "l'unité DÉFINIT la posture — le paquet choisit à la place de l'exploitant"
# Le fragment d'exemple est dans la DOCUMENTATION, d'où rien ne le charge.
grep -q './usr/share/doc/asl-server/attestation.conf.exemple' "$essai/contenu" \
    || rate "le fragment d'exemple n'est pas expédié"
grep -q './etc/systemd/system/asl-server.service.d/' "$essai/contenu" \
    && rate "un fragment posé sous /etc serait CHARGÉ"
conclure "la posture reste à décider, et le modèle est dans la documentation"

titre "7. les scripts de mainteneur sont du shell valide"
commencer
install -d "$essai/CONTROLE"
dpkg-deb --control "$paquet" "$essai/CONTROLE"
for script in postinst prerm postrm; do
    [ -x "$essai/CONTROLE/$script" ] || rate "$script n'est pas exécutable"
    sh -n "$essai/CONTROLE/$script" || rate "$script n'est pas du shell valide"
done
conclure "postinst, prerm, postrm"

titre "8. LE PURGE NE DÉPOSSÈDE PERSONNE"
commencer
# **C'EST LE CONTRÔLE QUI COMPTE LE PLUS.** `/var/lib/asl-server` porte des
# comptes, des machines et des autorisations que des humains se sont accordées ;
# `/etc/asl-server` porte une clé privée. Un `postrm` qui les effacerait le
# ferait en root, sans que personne l'ait relu.
#
# On dénude les here-documents : le `postrm` CITE la commande d'effacement dans
# ce qu'il imprime, et cette citation-là est justement ce qu'on veut — dire au
# lieu de faire.
denuder "$essai/CONTROLE/postrm" > "$essai/postrm-nu"
for interdit in 'rm -rf' 'rm -r' 'deluser' 'userdel' 'shred'; do
    grep -qF "$interdit" "$essai/postrm-nu" \
        && rate "le \`postrm\` EXÉCUTE « $interdit » — il doit le dire, pas le faire"
done
grep -q '/var/lib/asl-server' "$essai/CONTROLE/postrm" \
    || rate "le \`postrm\` ne dit rien de ce qu'il laisse en place"
conclure "l'annuaire et la clé survivent au purge, et le postrm le DIT"

titre "9. le paquet n'active ni ne démarre le service"
commencer
# Il lui manque exprès la posture et le certificat : l'activer ferait échouer le
# service à chaque démarrage de la machine, et apprendrait à l'exploitant que
# cet échec est normal.
denuder "$essai/CONTROLE/postinst" > "$essai/postinst-nu"
grep -qE 'systemctl +(enable|start|restart)' "$essai/postinst-nu" \
    && rate "le \`postinst\` active ou démarre le service"
grep -q 'systemctl daemon-reload' "$essai/postinst-nu" \
    || rate "le \`postinst\` ne recharge pas systemd après avoir posé l'unité"
conclure "installé, ni activé ni démarré"

titre "10. ce qu'on déballe s'exécute, et connaît les options de la SOURCE"
commencer
# UN PAQUET QUI S'INSTALLE ET DONT LE BINAIRE NE PART PAS n'a rien installé.
if ! "$essai/deballe/usr/bin/asl-server" --aide > "$essai/aide" 2>&1; then
    rate "le binaire empaqueté ne s'exécute pas :
$(cat "$essai/aide")"
fi
# **CE QUI COMPTE N'EST PAS QU'IL SOIT IDENTIQUE À `target/release`** — il l'est
# par construction. Ce qui compte est qu'il corresponde à la SOURCE : un binaire
# vieux de quelques heures s'exécute très bien et ignore les options ajoutées
# depuis. On confronte donc les bras de `match` de l'analyseur à son aide.
#
# **L'AIDE SE LIT UNE FOIS** : un `--aide | grep -q` par option est une course au
# `SIGPIPE`, qui rend un faux échec sous charge.
for drapeau in $(grep -oE '"--[a-z]+" =>' crates/asl-server/src/reglages.rs \
        | tr -d '">=' | tr -d ' '); do
    grep -qF -- "$drapeau" "$essai/aide" \
        || rate "le binaire empaqueté ignore $drapeau, que la source connaît"
done
conclure "il part, et son aide dit tout ce que la source lit"

titre "11. la marche à suivre imprimée existe vraiment"
commencer
# CE QU'UN SCRIPT IMPRIME EST CE QUE L'EXPLOITANT RECOPIE.
for chemin in /usr/share/doc/asl-server/attestation.conf.exemple; do
    grep -qF "$chemin" "$essai/CONTROLE/postinst" \
        || rate "le \`postinst\` ne nomme pas $chemin"
    [ -f "$essai/deballe$chemin" ] || rate "$chemin est nommé mais n'est pas expédié"
done
# Les deux chemins de certificat que le postinst annonce sont ceux de l'unité.
for chemin in /etc/asl-server/certificat.pem /etc/asl-server/cle.pem; do
    grep -qF "$chemin" "$essai/CONTROLE/postinst" \
        || rate "le \`postinst\` ne nomme pas $chemin"
    grep -qF "$chemin" paquet/asl-server.service \
        || rate "l'unité ne lit pas $chemin, que le postinst annonce"
done
conclure "chaque chemin imprimé est un chemin qui existe"

titre "12. le postinst S'EXÉCUTE, sous des doublures"
commencer
# **`sh -n` DIT QUE LA GRAMMAIRE EST BONNE, PAS QUE LE SCRIPT MARCHE.** On le
# lance donc pour de vrai, mais chaque commande qui TOUCHE au système est
# remplacée par une doublure qui note son passage.
doublures="$essai/doublures"
install -d -m 0755 "$doublures"
for commande in adduser chown chmod systemctl; do
    cat > "$doublures/$commande" <<DOUBLURE
#!/bin/sh
echo "$commande \$*" >> "$essai/journal-doublures"
exit 0
DOUBLURE
    chmod 0755 "$doublures/$commande"
done
# `getent passwd asl-server` doit dire QUE LE COMPTE N'EXISTE PAS, sans quoi la
# branche qui le crée ne serait jamais parcourue.
cat > "$doublures/getent" <<DOUBLURE
#!/bin/sh
echo "getent \$*" >> "$essai/journal-doublures"
exit 2
DOUBLURE
chmod 0755 "$doublures/getent"

: > "$essai/journal-doublures"
if ! PATH="$doublures:$PATH" sh "$essai/CONTROLE/postinst" configure \
        > "$essai/dit-installation" 2>&1; then
    rate "le \`postinst\` échoue à l'installation :
$(cat "$essai/dit-installation")"
fi
for attendu in "adduser --system" "chown root:asl-server /etc/asl-server" \
               "chmod 0750 /etc/asl-server" "systemctl daemon-reload"; do
    grep -qF "$attendu" "$essai/journal-doublures" \
        || rate "le \`postinst\` n'a pas fait : $attendu"
done
grep -q 'ASL_ATTESTATION' "$essai/dit-installation" \
    || rate "le \`postinst\` n'imprime pas la marche à suivre à l'installation"

# **UNE MISE À JOUR NE RÉPÈTE PAS LA LEÇON.** `dpkg` passe l'ancienne version en
# second argument ; un paquet qui redonnerait les trois étapes à chaque montée
# de version apprendrait à l'exploitant à ne plus lire ce qu'il imprime.
: > "$essai/journal-doublures"
if ! PATH="$doublures:$PATH" sh "$essai/CONTROLE/postinst" configure 0.0.9 \
        > "$essai/dit-montee" 2>&1; then
    rate "le \`postinst\` échoue à la mise à jour :
$(cat "$essai/dit-montee")"
fi
grep -q 'ASL_ATTESTATION' "$essai/dit-montee" \
    && rate "le \`postinst\` répète la marche à suivre à chaque mise à jour"
grep -qF "chmod 0750 /etc/asl-server" "$essai/journal-doublures" \
    || rate "la mise à jour ne reprend pas les droits du répertoire des clés"

# Et le `prerm` arrête AVANT que les fichiers partent.
: > "$essai/journal-doublures"
PATH="$doublures:$PATH" sh "$essai/CONTROLE/prerm" remove > /dev/null 2>&1 \
    || rate "le \`prerm\` échoue"
grep -qF "systemctl stop asl-server" "$essai/journal-doublures" \
    || rate "le \`prerm\` n'arrête pas le service avant de retirer le binaire"
conclure "installation, mise à jour et retrait, sans rien toucher"

if [ "$fautes" -ne 0 ]; then
    printf '\nÉCHEC : %s contrôle(s) du paquet n'"'"'ont pas passé.\n' "$fautes" >&2
    exit 1
fi
printf '\nOK : le paquet pose ce qu'"'"'il dit poser, ne choisit pas la posture,\n'
printf '     et le purge ne dépossède personne.\n'
