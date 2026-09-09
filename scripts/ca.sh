#!/usr/bin/env bash
#
# ca.sh — l'autorité de certification d'`air-desktop-project`, et les
#         certificats de serveur qu'elle émet.
#
# # CE N'EST PAS UNE BARRIÈRE, C'EST UNE CÉRÉMONIE
#
# Elle ne tourne ni en CI ni dans `check-tout.sh`. On la lance à la main, on
# regarde ce qu'elle a produit, et on range la clé privée de la racine. C'est
# pour cela que le fichier ne s'appelle pas `check-…`.
#
# # POURQUOI UNE AUTORITÉ À NOUS, ET PAS UNE CA PUBLIQUE
#
# **Nous tenons les deux bouts.** Le serveur est à nous, et le client aussi —
# `asl-client`, et les applications mobiles. Personne d'autre ne se connecte à
# un annuaire. Une CA publique servirait à convaincre des navigateurs qui ne
# viendront jamais, au prix d'un nom de domaine par annuaire, d'un
# renouvellement automatique et d'un tiers dans la boucle.
#
# Une racine à nous, ÉPINGLÉE dans le client, dit exactement ce qu'on veut
# dire : « ce serveur est un annuaire d'`air-desktop-project` ». Et elle le dit
# sans dépendre de la liste des autorités du système, que l'on ne contrôle pas.
#
# # ET POURQUOI PAS LA CA D'`air`
#
# **Parce que ce n'en est pas une, pour cet usage.** `air-keystore ca create`
# émet des certificats au format **OpenSSH** (`air-ssh-proto::cert`, ADR-109 et
# ADR-162), pour `air-sshd`. Le format n'a rien de commun avec X.509 : une CA SSH
# ne peut pas signer un certificat de serveur TLS, et `air-crypto` écrit
# d'ailleurs que « PEM/DER, certificats X.509 » sont hors de son périmètre.
# `air-tls` est une spécification : elle VALIDE des chaînes X.509, elle n'en
# émet pas.
#
# Le jour où Air aura une autorité X.509, cette cérémonie sera à reprendre — et
# ce commentaire est là pour qu'on sache alors ce qu'elle remplaçait.
#
# # ED25519, ET LA RAISON EST VÉRIFIABLE
#
# Le fournisseur cryptographique sous notre pile TLS est `rustls-rustcrypto`.
# Son module `sign/eddsa.rs` charge une clé **Ed25519 au format PKCS#8** et signe
# avec — c'est exactement ce que produit `openssl genpkey -algorithm ed25519`.
# C'est aussi l'algorithme des clés de machine (`asl-cle`) : une seule courbe
# dans tout le produit, donc une seule à auditer.
#
# # DES SAN D'ADRESSE IP, ET C'EST LA CONSÉQUENCE D'« IPv6 D'ABORD »
#
# **C'est le point qu'un script naïf rate.** Un daemon rejoint un annuaire par
# son ADRESSE, pas nécessairement par un nom : une machine à IPv6 publique n'a
# besoin d'aucun DNS. Un certificat qui ne porterait que des `DNS:` serait alors
# refusé par le client, et le refus serait juste — le nom présenté ne serait pas
# celui qu'on a vérifié.
#
# Les noms passés en argument sont donc classés ici : ce qui ressemble à une
# adresse devient un `IP:`, le reste un `DNS:`.
#
# # POURQUOI OPENSSL, ALORS QUE LE PRODUIT N'A PAS UNE LIGNE DE C
#
# C4 interdit à `asl-client` de LIER du C, parce qu'elle est chargée dans des
# interpréteurs qui ont déjà leur libcrypto. Elle n'interdit pas d'employer un
# outil pour frapper un certificat une fois : rien de ce que fait ce script
# n'entre dans le binaire livré. `check-sans-c.sh` continue de mesurer ce qui
# est construit, et ne verra jamais openssl.
#
# # CE QUE CETTE CÉRÉMONIE N'EST PAS ENCORE
#
# **Il n'y a pas d'intermédiaire.** La racine signe les serveurs directement.
# Un intermédiaire existe pour garder la racine hors ligne, et cela n'a de sens
# que le jour où la racine sera vraiment mise hors ligne. L'ajouter avant
# donnerait la complexité sans la protection.
#
# **Il n'y a pas de révocation.** Ni CRL, ni OCSP. Une validité d'un an sur les
# certificats de serveur est ce qui en tient lieu, et il faut le dire plutôt que
# de laisser croire le contraire.

set -euo pipefail

cd "$(dirname "$0")/.."

# ── Où vont les clés ─────────────────────────────────────────────────────────
#
# `local/` est IGNORÉ PAR GIT, et c'est la seule chose qui compte ici : une clé
# privée de racine dans un dépôt public ne se retire jamais vraiment d'un
# historique. Le certificat de la racine, lui, est public par nature — il a
# vocation à être épinglé dans le client.
# `ASL_CA` la déplace, et c'est ce qui permet à un essai de frapper sa propre
# autorité dans un répertoire temporaire — donc de VÉRIFIER cette cérémonie
# plutôt que de la croire sur parole. Sans cela, l'essai devrait lire la racine
# réelle, et un essai qui lit un secret est un essai qu'on ne lance plus.
AUTORITE="${ASL_CA:-local/ca}"

# Dix ans pour la racine : elle sera épinglée dans des clients déployés chez des
# tiers, et une racine qui expire invalide tout ce qu'elle a signé.
JOURS_RACINE=3650
# Un an pour un serveur. Ce n'est pas un choix de sécurité, c'est un aveu : sans
# révocation, la durée de vie EST la révocation.
JOURS_SERVEUR=365

usage() {
    cat <<'FIN'
ca.sh — l'autorité d'air-desktop-project, et ses certificats de serveur.

  ca.sh racine
      Crée la racine si elle n'existe pas. NE LA REMPLACE JAMAIS.

  ca.sh serveur <nom> [nom-ou-adresse…]
      Émet un certificat pour un annuaire. Le premier nom est le sujet ; tous
      les noms deviennent des SAN, les adresses IP en `IP:`, le reste en `DNS:`.

  ca.sh montrer
      Affiche ce qui existe.

Exemples :
      ca.sh racine
      ca.sh serveur banc localhost ::1 127.0.0.1
      ca.sh serveur racine-1 racine-1.airdesktop.org 2001:db8::1
FIN
}

# Une adresse IP, ou un nom ? On ne devine pas : on demande à `getent`… non, à
# une reconnaissance de forme, parce que `getent` résoudrait des noms.
est_une_adresse() {
    printf '%s' "$1" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:.]*$'
}

creer_la_racine() {
    mkdir -p "$AUTORITE"
    chmod 700 "$AUTORITE"

    if [ -f "$AUTORITE/racine.crt" ]; then
        echo "La racine existe déjà — RIEN N'A ÉTÉ TOUCHÉ."
        echo "  $AUTORITE/racine.crt"
        echo
        echo "La remplacer invaliderait tout ce qu'elle a signé, y compris ce"
        echo "qui est déjà épinglé chez un tiers. Si c'est vraiment ce que vous"
        echo "voulez, effacez le répertoire à la main."
        return 0
    fi

    echo "Création de la racine d'air-desktop-project (Ed25519, $JOURS_RACINE jours)…"

    openssl genpkey -algorithm ed25519 -out "$AUTORITE/racine.key"
    chmod 600 "$AUTORITE/racine.key"

    # `basicConstraints` critique et `keyCertSign` : sans eux, un vérificateur
    # correct refuse la chaîne — une CA qui ne se dit pas CA n'en est pas une.
    openssl req -new -x509 -key "$AUTORITE/racine.key" -out "$AUTORITE/racine.crt" \
        -days "$JOURS_RACINE" -sha512 \
        -subj "/O=air-desktop-project/CN=air-desktop-project Root CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash"

    # Le compteur de numéros de série. Deux certificats de même série sous une
    # même racine sont indistinguables pour un journal d'audit.
    echo 1000 > "$AUTORITE/serie"

    echo "  clé          : $AUTORITE/racine.key  (600 — NE SORT JAMAIS D'ICI)"
    echo "  certificat   : $AUTORITE/racine.crt  (public, à épingler dans le client)"
}

emettre_un_serveur() {
    local nom="$1"
    shift
    local noms=("$nom" "$@")

    if [ ! -f "$AUTORITE/racine.key" ]; then
        echo "ÉCHEC : pas de racine. Lancez d'abord \`scripts/ca.sh racine\`." >&2
        exit 1
    fi

    local sortie="$AUTORITE/$nom"
    mkdir -p "$sortie"

    # ── Les SAN, classés ────────────────────────────────────────────────────
    local san=""
    local vus_ip=0 vus_dns=0
    for candidat in "${noms[@]}"; do
        if est_une_adresse "$candidat"; then
            san="${san:+$san,}IP:$candidat"
            vus_ip=$((vus_ip + 1))
        else
            san="${san:+$san,}DNS:$candidat"
            vus_dns=$((vus_dns + 1))
        fi
    done

    echo "Émission pour « $nom » ($vus_dns nom(s), $vus_ip adresse(s), $JOURS_SERVEUR jours)…"
    echo "  SAN : $san"

    openssl genpkey -algorithm ed25519 -out "$sortie/serveur.key"
    chmod 600 "$sortie/serveur.key"

    openssl req -new -key "$sortie/serveur.key" -out "$sortie/serveur.csr" \
        -subj "/O=air-desktop-project/CN=$nom"

    # `extendedKeyUsage=serverAuth` : un certificat de serveur ne doit pas
    # pouvoir servir de certificat de client, ni l'inverse.
    local extensions
    extensions=$(mktemp)
    cat > "$extensions" <<FIN
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$san
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
FIN

    openssl x509 -req -in "$sortie/serveur.csr" -out "$sortie/serveur.crt" \
        -CA "$AUTORITE/racine.crt" -CAkey "$AUTORITE/racine.key" \
        -CAserial "$AUTORITE/serie" \
        -days "$JOURS_SERVEUR" -extfile "$extensions"

    rm -f "$extensions" "$sortie/serveur.csr"

    # La chaîne que le serveur présente : le certificat, puis rien. La racine
    # n'est PAS dedans — le client la tient déjà, c'est tout l'intérêt de
    # l'épinglage, et l'envoyer ne prouverait rien.
    cp "$sortie/serveur.crt" "$sortie/chaine.pem"

    # ── ON VÉRIFIE CE QU'ON VIENT DE FRAPPER ────────────────────────────────
    #
    # Un script qui émet sans vérifier fait découvrir ses fautes à la poignée
    # de main, c'est-à-dire au pire endroit.
    echo
    openssl verify -CAfile "$AUTORITE/racine.crt" "$sortie/serveur.crt"

    echo "  clé          : $sortie/serveur.key  (600)"
    echo "  certificat   : $sortie/serveur.crt"
    echo "  chaîne       : $sortie/chaine.pem"
}

montrer() {
    if [ ! -f "$AUTORITE/racine.crt" ]; then
        echo "Aucune racine. \`scripts/ca.sh racine\` la crée."
        return 0
    fi
    echo "── la racine ──"
    openssl x509 -in "$AUTORITE/racine.crt" -noout -subject -dates -ext basicConstraints
    for chemin in "$AUTORITE"/*/serveur.crt; do
        [ -f "$chemin" ] || continue
        echo
        echo "── $(basename "$(dirname "$chemin")") ──"
        openssl x509 -in "$chemin" -noout -subject -dates -ext subjectAltName
    done
}

case "${1:-}" in
    racine)  creer_la_racine ;;
    serveur)
        shift
        [ "$#" -ge 1 ] || { usage >&2; exit 1; }
        emettre_un_serveur "$@"
        ;;
    montrer) montrer ;;
    *)       usage; exit 1 ;;
esac
