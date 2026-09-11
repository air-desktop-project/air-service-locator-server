#!/usr/bin/env python3
"""Fabrique une FAUSSE chaîne App Attest, pour éprouver la vérification.

# POURQUOI UNE FAUSSE CHAÎNE

Une attestation réelle ne peut pas servir d'essai : sa chaîne remonte à la
racine d'Apple, dont personne ici n'a la clé, et on ne pourrait donc en fabriquer
qu'UNE — la bonne. Les refus (nonce faux, identifiant faux, autre racine, clé
d'une autre courbe) demandent des certificats qu'Apple ne signera jamais.

Le vérificateur prend donc la racine EN PARAMÈTRE. En production c'est celle
d'Apple ; ici c'est la nôtre, et on signe ce qu'on veut.

# CE QUE ÇA NE PROUVE PAS

Que la forme de l'extension `1.2.840.113635.100.8.2`, la courbe de la feuille et
la disposition d'`authData` sont bien celles qu'Apple emploie. Tout cela vient
de la documentation, et **une capture réelle reste à obtenir**. Ce script
fabrique ce que la documentation décrit, pas ce qu'un iPhone envoie.

# CE QUI EST FABRIQUÉ

    racine.der                       CA auto-signée, P-384 — joue Apple
    intermediaire.der                CA signée par la racine, P-384
    feuille.der                      P-256, signée par l'intermédiaire, nonce
                                     calculé sur auth-data.bin et defi.bin
    feuille-identifiant-faux.der     nonce calculé sur auth-data-identifiant-faux.bin
    feuille-sans-nonce.der           pas d'extension du tout
    feuille-p384.der                 la clé n'est pas sur P-256
    intermediaire-p256.der           CA P-256 signée par la racine — pour que
                                     le vérificateur ECDSA P-256 serve aussi à
                                     une signature de CERTIFICAT, pas seulement
                                     à la clé de la feuille
    feuille-via-p256.der             la même feuille, signée par celle-là
    autre-racine.der                 une seconde CA, étrangère à la chaîne
    defi.bin                         le défi
    auth-data.bin                    les données d'authentificateur, cohérentes
    auth-data-identifiant-faux.bin   les mêmes, avec un identifiant qui ne
                                     correspond à aucune clé
    cle-feuille.bin                  la clé publique de la feuille, point non
                                     compressé (65 octets), pour les assertions

La racine signe en SHA-384, les intermédiaires en SHA-256 : c'est ce que la
documentation laisse entendre de la chaîne d'Apple, et cela exerce les deux
condensats du vérificateur.

Les certificats valent du 2026-01-01 au 2126-01-01 : le vérificateur reçoit
l'heure en paramètre, et les essais l'y placent — ou non.

Relancer ce script régénère TOUT, clés comprises. Les fichiers sont commités :
un essai ne doit pas dépendre d'un `openssl` présent.
"""

import hashlib
import pathlib
import subprocess
import sys
import tempfile

ICI = pathlib.Path(__file__).resolve().parent
NON_AVANT = "20260101000000Z"
NON_APRES = "21260101000000Z"
IDENTIFIANT_APP = "ABCDE12345.ch.narro.essai"
AAGUID_DEV = b"appattestdevelop"
OID_NONCE = "1.2.840.113635.100.8.2"


def openssl(*args, entree=None):
    r = subprocess.run(["openssl", *args], input=entree, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"openssl {' '.join(args)} :\n{r.stderr.decode()}")
    return r.stdout


def cle(courbe, chemin):
    openssl("ecparam", "-name", courbe, "-genkey", "-noout", "-out", str(chemin))


def point_public(cle_pem):
    """Le point non compressé (04 ‖ x ‖ y) de la clé publique."""
    der = openssl("pkey", "-in", str(cle_pem), "-pubout", "-outform", "DER")
    # Le SPKI finit par le BIT STRING : 03 42 00 04 x y — on prend le point.
    return der[-65:]


def ca(nom, cle_pem, sortie_der, signataire=None, condensat="sha384"):
    """Une CA : auto-signée si `signataire` est vide, sinon signée par lui."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        ext = tmp / "ext.cnf"
        ext.write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
        csr = tmp / "csr.pem"
        openssl("req", "-new", "-key", str(cle_pem), "-subj", f"/CN={nom}/O=Banc", "-out", str(csr))
        if signataire is None:
            openssl("x509", "-req", "-in", str(csr), "-key", str(cle_pem), f"-{condensat}",
                    "-not_before", NON_AVANT, "-not_after", NON_APRES,
                    "-extfile", str(ext), "-outform", "DER", "-out", str(sortie_der))
        else:
            ca_pem, ca_cle = signataire
            openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_pem), "-CAkey", str(ca_cle),
                    f"-{condensat}", "-not_before", NON_AVANT, "-not_after", NON_APRES,
                    "-extfile", str(ext), "-outform", "DER", "-out", str(sortie_der))


def feuille(cle_pem, sortie_der, signataire, nonce):
    """Une feuille, avec — ou sans — l'extension d'Apple portant `nonce`."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        ext = tmp / "ext.cnf"
        lignes = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature"]
        if nonce is not None:
            # SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } } — la forme que la
            # documentation d'Apple décrit, encodée en DER à la main.
            interieur = b"\x04\x20" + nonce
            explicite = b"\xa1" + bytes([len(interieur)]) + interieur
            sequence = b"\x30" + bytes([len(explicite)]) + explicite
            lignes.append(f"{OID_NONCE}=DER:{sequence.hex()}")
        ext.write_text("\n".join(lignes) + "\n")
        csr = tmp / "csr.pem"
        openssl("req", "-new", "-key", str(cle_pem), "-subj", "/CN=feuille/O=Banc", "-out", str(csr))
        ca_pem, ca_cle = signataire
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_pem), "-CAkey", str(ca_cle),
                "-sha256", "-not_before", NON_AVANT, "-not_after", NON_APRES,
                "-extfile", str(ext), "-outform", "DER", "-out", str(sortie_der))


def auth_data(identifiant):
    """La disposition de WebAuthn, drapeau ATTESTE levé, compteur à zéro."""
    empreinte = hashlib.sha256(IDENTIFIANT_APP.encode()).digest()
    cose = b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" + b"\x00" * 32 + b"\x22\x58\x20" + b"\x00" * 32
    return (empreinte + b"\x40" + (0).to_bytes(4, "big")
            + AAGUID_DEV + len(identifiant).to_bytes(2, "big") + identifiant + cose)


def nonce_pour(donnees_auth, defi):
    return hashlib.sha256(donnees_auth + hashlib.sha256(defi).digest()).digest()


def principal():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        for nom, courbe in [("racine", "secp384r1"), ("intermediaire", "secp384r1"),
                            ("feuille", "prime256v1"), ("feuille-p384", "secp384r1"),
                            ("intermediaire-p256", "prime256v1"),
                            ("autre-racine", "secp384r1")]:
            cle(courbe, tmp / f"{nom}.key")

        ca("Racine du banc", tmp / "racine.key", ICI / "racine.der")
        ca("Autre racine", tmp / "autre-racine.key", ICI / "autre-racine.der")
        # `x509 -CA` veut du PEM pour la CA.
        racine_pem = tmp / "racine.pem"
        racine_pem.write_bytes(openssl("x509", "-in", str(ICI / "racine.der"), "-inform", "DER"))
        ca("Intermediaire du banc", tmp / "intermediaire.key", ICI / "intermediaire.der",
           (racine_pem, tmp / "racine.key"))
        inter_pem = tmp / "intermediaire.pem"
        inter_pem.write_bytes(openssl("x509", "-in", str(ICI / "intermediaire.der"), "-inform", "DER"))
        signataire = (inter_pem, tmp / "intermediaire.key")
        ca("Intermediaire P-256 du banc", tmp / "intermediaire-p256.key",
           ICI / "intermediaire-p256.der", (racine_pem, tmp / "racine.key"))
        inter_p256_pem = tmp / "intermediaire-p256.pem"
        inter_p256_pem.write_bytes(openssl("x509", "-in", str(ICI / "intermediaire-p256.der"), "-inform", "DER"))

        defi = hashlib.sha256("le défi du banc".encode()).digest()
        (ICI / "defi.bin").write_bytes(defi)

        point = point_public(tmp / "feuille.key")
        assert len(point) == 65 and point[0] == 4, "la clé n'est pas un point non compressé"
        (ICI / "cle-feuille.bin").write_bytes(point)
        identifiant = hashlib.sha256(point).digest()

        bon = auth_data(identifiant)
        (ICI / "auth-data.bin").write_bytes(bon)
        feuille(tmp / "feuille.key", ICI / "feuille.der", signataire, nonce_pour(bon, defi))

        faux = auth_data(hashlib.sha256("une autre clé".encode()).digest())
        (ICI / "auth-data-identifiant-faux.bin").write_bytes(faux)
        feuille(tmp / "feuille.key", ICI / "feuille-identifiant-faux.der", signataire,
                nonce_pour(faux, defi))

        feuille(tmp / "feuille.key", ICI / "feuille-sans-nonce.der", signataire, None)
        feuille(tmp / "feuille.key", ICI / "feuille-via-p256.der",
                (inter_p256_pem, tmp / "intermediaire-p256.key"), nonce_pour(bon, defi))
        feuille(tmp / "feuille-p384.key", ICI / "feuille-p384.der", signataire,
                nonce_pour(bon, defi))

    for f in sorted(ICI.glob("*.der")) + sorted(ICI.glob("*.bin")):
        print(f"{f.name:<34} {f.stat().st_size:>5} octets")


if __name__ == "__main__":
    principal()
