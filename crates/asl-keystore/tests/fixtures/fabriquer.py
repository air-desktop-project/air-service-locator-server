#!/usr/bin/env python3
"""Fabrique la racine RSA du banc, et l'intermédiaire P-256 qu'elle signe.

# POURQUOI CES DEUX-LÀ SEULEMENT

Tout le reste du banc d'`asl-keystore` est fabriqué EN RUST, dans
`tests/forge/mod.rs` : des scalaires fixes, des signatures ECDSA
déterministes, du DER écrit à la main. Rien n'a besoin d'`openssl`.

Sauf RSA. La racine de Google est RSA-4096 et signe son intermédiaire en RSA
PKCS#1 v1.5 : le vérificateur RSA de `signature.rs` doit être éprouvé sous
une racine RSA du banc, et aucune dépendance de développement ne signe en RSA
sans en tirer une nouvelle. `openssl` le fait ici, une fois, et les deux
certificats sont COMMITÉS : un essai ne dépend pas d'un `openssl` présent.

# CE QUI EST FABRIQUÉ

    racine-rsa.der              CA auto-signée, RSA-2048, SHA-256 — joue Google
    intermediaire-sous-rsa.der  CA P-256 signée par la racine en RSA/SHA-256,
                                dont le scalaire est CONNU de la forge
                                (`SCALAIRE_SOUS_RSA` : 01 02 … 20) — c'est
                                elle qui signe les feuilles de cet essai

La clé RSA est jetée : personne n'aura plus jamais à signer sous cette
racine, et c'est le but — ce qu'elle a signé est tout ce qu'elle signera.

Les certificats valent dix ans à partir du jour où ce script tourne
(2026-09-16) : l'essai se place en 2027, et il faudra les refrapper en 2036.
"""

import pathlib
import subprocess
import sys
import tempfile

ICI = pathlib.Path(__file__).resolve().parent
# `openssl x509` 3.0 ne connaît pas `-not_before` : la validité part du jour
# où ce script tourne, pour dix ans. L'essai se place donc en 2027.
JOURS = "3650"
SCALAIRE = bytes(range(1, 33))
OID_P256 = bytes.fromhex("06082a8648ce3d030107")


def openssl(*args, entree=None):
    r = subprocess.run(["openssl", *args], input=entree, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"openssl {' '.join(args)} :\n{r.stderr.decode()}")
    return r.stdout


def cle_ec_depuis_scalaire(chemin):
    """Un ECPrivateKey (RFC 5915) sans point public : openssl le calcule."""
    interieur = b"\x02\x01\x01" + b"\x04\x20" + SCALAIRE + b"\xa0" + bytes([len(OID_P256)]) + OID_P256
    der = b"\x30" + bytes([len(interieur)]) + interieur
    chemin.write_bytes(der)


def principal():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        ext = tmp / "ext.cnf"
        ext.write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")

        racine_cle = tmp / "racine.key"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", str(racine_cle))
        csr = tmp / "racine.csr"
        openssl("req", "-new", "-key", str(racine_cle), "-subj", "/CN=Racine RSA du banc",
                "-out", str(csr))
        openssl("x509", "-req", "-in", str(csr), "-key", str(racine_cle), "-sha256",
                "-days", JOURS, "-extfile", str(ext),
                "-outform", "DER", "-out", str(ICI / "racine-rsa.der"))
        racine_pem = tmp / "racine.pem"
        racine_pem.write_bytes(openssl("x509", "-in", str(ICI / "racine-rsa.der"), "-inform", "DER"))

        inter_cle = tmp / "inter.der"
        cle_ec_depuis_scalaire(inter_cle)
        csr = tmp / "inter.csr"
        openssl("req", "-new", "-key", str(inter_cle), "-keyform", "DER",
                "-subj", "/CN=Intermediaire sous RSA", "-out", str(csr))
        openssl("x509", "-req", "-in", str(csr), "-CA", str(racine_pem), "-CAkey", str(racine_cle),
                "-sha256", "-days", JOURS,
                "-extfile", str(ext), "-outform", "DER",
                "-out", str(ICI / "intermediaire-sous-rsa.der"))

    for f in sorted(ICI.glob("*.der")):
        print(f"{f.name:<30} {f.stat().st_size:>5} octets")


if __name__ == "__main__":
    principal()
