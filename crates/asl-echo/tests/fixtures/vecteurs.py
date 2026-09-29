#!/usr/bin/env python3
"""Calcule les vecteurs figés de l'écho, HORS du code qu'ils éprouvent.

# POURQUOI UN SECOND ÉCRIVAIN

Un aller-retour écrit-puis-relu par le même code passe toujours, y compris
quand l'écriture et la lecture se trompent de la même façon — un champ
inversé, un séparateur mal recopié. Ce script réécrit les quatre formats
depuis `docs/protocole.md` §3 quater SEULEMENT, avec une autre bibliothèque
Ed25519 (`cryptography`, donc OpenSSL), et `tests/vecteurs.rs` exige que le
codec produise ces octets-là, à l'octet près. Ed25519 est déterministe
(RFC 8032) : les signatures aussi sont figées.

# CE QUI EST CALCULÉ

    jeton              193 octets — délivré par la racine R à S, pour C
    sonde-annuaire     384 octets — la racine R sonde C
    sonde-jeton        384 octets — S sonde C, muni du jeton
    reponse-annuaire   132 octets — C répond à R, vu de 203.0.113.7:53211
    reponse-jeton      132 octets — C répond à S, vu de [2001:db8::1c2d]:41877

Les clés sont tirées d'octets constants, jamais du hasard :

    R  racine      graine 0x11 × 32   n-… = SHA-256(domaine ‖ clé)[:16]
    C  cible       graine 0x33 × 32   m-… = 0x70, 0x71, …, 0x7f
    S  sondeur     graine 0x44 × 32   m-… = 0x80, 0x81, …, 0x8f

Lancer : `python3 crates/asl-echo/tests/fixtures/vecteurs.py`, et recopier
la sortie dans `tests/vecteurs.rs` si — et seulement si — le FORMAT change.
"""

import hashlib
import ipaddress
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def cle(graine):
    secrete = Ed25519PrivateKey.from_private_bytes(bytes([graine]) * 32)
    publique = secrete.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return secrete, publique


def adresse(ip, port):
    ip = ipaddress.ip_address(ip)
    if ip.version == 4:
        ip = ipaddress.IPv6Address(b"\x00" * 10 + b"\xff\xff" + ip.packed)
    return ip.packed + struct.pack(">H", port)


def u64(valeur):
    return struct.pack(">Q", valeur)


R, R_pub = cle(0x11)
C, C_pub = cle(0x33)
S, S_pub = cle(0x44)

R_id = hashlib.sha256(b"air-service-locator/v1/identite-de-racine\x00" + R_pub).digest()[:16]
C_id = bytes(range(0x70, 0x80))
S_id = bytes(range(0x80, 0x90))

DEFI_R = bytes(range(0xD0, 0xE0))
DEFI_S = bytes(range(0xE0, 0xF0))

EMIS_A = 1789217731000
EXPIRE_A = EMIS_A + 60000
EMISE_A = 1789217751000

# Le jeton.
contenu = bytes([0x01]) + R_id + C_id + C_pub + S_id + S_pub + u64(EMIS_A) + u64(EXPIRE_A)
jeton = contenu + R.sign(b"air-service-locator/v1/echo-jeton\x00" + contenu)
assert len(jeton) == 193

# La sonde d'annuaire.
contenu = bytes([0x0A, 0x01]) + DEFI_R + R_id + C_id + u64(EMISE_A)
sonde_annuaire = contenu + R.sign(b"air-service-locator/v1/echo-sonde-annuaire\x00" + contenu)
sonde_annuaire += bytes(384 - len(sonde_annuaire))

# La sonde munie du jeton.
contenu = DEFI_S + jeton
sonde_jeton = bytes([0x0A, 0x02]) + contenu + S.sign(b"air-service-locator/v1/echo-sonde\x00" + contenu)
sonde_jeton += bytes(384 - len(sonde_jeton))


def reponse(defi, vu, sondeur):
    contenu = defi + C_id + vu + sondeur
    signature = C.sign(b"air-service-locator/v1/echo-reponse\x00" + contenu)
    octets = bytes([0x0A, 0x81]) + contenu + signature
    assert len(octets) == 132
    return octets


reponse_annuaire = reponse(DEFI_R, adresse("203.0.113.7", 53211), R_id)
reponse_jeton = reponse(DEFI_S, adresse("2001:db8::1c2d", 41877), S_id)

for nom, octets in [
    ("RACINE_ID", R_id),
    ("JETON", jeton),
    ("SONDE_ANNUAIRE", sonde_annuaire),
    ("SONDE_JETON", sonde_jeton),
    ("REPONSE_ANNUAIRE", reponse_annuaire),
    ("REPONSE_JETON", reponse_jeton),
]:
    print(f'const {nom}: &str = "{octets.hex()}";')
