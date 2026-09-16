# Attestation de clé réelle — Fairphone 5, 2026-09-16

La première chaîne d'attestation de clé Android lue par ce dépôt, capturée
selon [`../../capture-keystore.md`](../../capture-keystore.md) par la variante
de débogage de l'app (`capture/CaptureAttestation.kt`). Rien ici n'est un
secret : la chaîne est publique par nature, le défi est un aléa, la clé a été
détruite aussitôt lue.

| Fichier | Quoi |
|---|---|
| `capture.txt` | Le bloc Logcat, tel quel (base64). |
| `cert0.der` … `cert3.der` | La chaîne, feuille d'abord — 686, 503, 920, 1312 octets, **3 421 en tout**. |
| `defi.bin` | Le défi d'attestation, 32 octets. |

**Ce qu'on y lit** (`openssl asn1parse -strparse` sur l'extension
`1.3.6.1.4.1.11129.2.1.17` de la feuille) :

- `attestationVersion` **3**, `attestationSecurityLevel` **1 = TrustedEnvironment**,
  `keymasterVersion` 41, `keymasterSecurityLevel` 1 ; `attestationChallenge` =
  le défi, octet pour octet ; `uniqueId` vide.
- `softwareEnforced` : `creationDateTime` [701] ; `attestationApplicationId`
  [709] = `SEQUENCE { SET { SEQUENCE { "org.airdesktop.servicelocator", 6 } },
  SET { SHA-256 de la signature } }` — le paquet et l'empreinte de la build,
  égaux à `PAQUET=` et `SIGNATURE=`.
- `teeEnforced` : `purpose` {2 = SIGN}, `algorithm` 3 (EC), `keySize` 256,
  `digest` {4 = SHA-256}, `ecCurve` 1 (P-256), `noAuthRequired` [503],
  `origin` [702] = 0 (GENERATED), **`rootOfTrust` [704] = { verifiedBootKey,
  `deviceLocked` TRUE, `verifiedBootState` 0 = Verified, verifiedBootHash }**,
  `osVersion` [705] 150000, `osPatchLevel` [706] 202608, `vendorPatchLevel`
  [718] et `bootPatchLevel` [719] 20260805.
- La chaîne : feuille `CN=Android Keystore Key` (ECDSA) → deux intermédiaires
  `title=TEE` (le second signé en RSA) → **la racine `serialNumber=f92009e853b6b045`**,
  RSA-4096 auto-signée : la racine d'attestation matérielle de Google.

Ce qui suit de là pour `asl-keystore` : la vérification demande **RSA (SHA-256)
ET ECDSA P-256** dans la chaîne ; l'`attestationApplicationId` est lui-même un
DER dans un `OCTET STRING` ; les tags contextuels vont jusqu'à [719] et sont
optionnels ; la borne de 8 Kio tient, avec de la marge.
