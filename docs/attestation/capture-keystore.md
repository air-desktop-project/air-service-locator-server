# Capturer une attestation de clé Android réelle

`asl-keystore` vérifiera une chaîne d'attestation du Keystore d'Android contre
une racine épinglée — hors ligne, sans compte, sans service (C19). Comme pour
App Attest ([`capture-reelle.md`](capture-reelle.md)), sa forme vient d'abord de
la documentation ; **ce document sert à obtenir la première capture réelle**,
et à la confronter au code. Le pendant de Play Integrity
([`capture-play.md`](capture-play.md)) est abandonné.

## Ce qu'il faut, côté toi

| Il faut | Pourquoi |
|---|---|
| Un appareil Android **réel** (le Fairphone 5 convient) | L'attestation vient du TEE ; un émulateur n'en a pas, ou une chaîne sous une racine logicielle. |
| Rien d'autre | Ni compte, ni projet, ni SDK : `setAttestationChallenge` est une fonction du système. |

## Le geste

Dans l'app, en variante de débogage, une clé jetable générée **avec un défi
d'attestation** — c'est le seul écart avec la clé d'appareil de
`CleAppareil.kt` : un `setAttestationChallenge(défi)` de plus, à la génération.

```kotlin
val defi = ByteArray(32).also { SecureRandom().nextBytes(it) }
val spec = KeyGenParameterSpec.Builder("capture-attestation", KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAttestationChallenge(defi)
    .build()
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
    .apply { initialize(spec) }.generateKeyPair()
val chaine = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    .getCertificateChain("capture-attestation")
Log.i("CAPTURE", "──── CAPTURE ATTESTATION ANDROID ────")
Log.i("CAPTURE", "DEFI=" + Base64.encodeToString(defi, Base64.NO_WRAP))
chaine.forEachIndexed { i, c -> Log.i("CAPTURE", "CERT$i=" + Base64.encodeToString(c.encoded, Base64.NO_WRAP)) }
Log.i("CAPTURE", "PAQUET=" + context.packageName)
```

Lance sur l'**appareil**, lis Logcat (étiquette « CAPTURE »), recopie le bloc.
`CERT0` est la feuille, le dernier est la racine.

## Ce que tu me rends

`DEFI`, `CERT0…CERTn`, `PAQUET`, et l'empreinte SHA-256 du certificat de
signature de la build (`apksigner verify --print-certs`). **Rien n'est un
secret** : une chaîne d'attestation est publique par nature, le défi est
jetable, la clé n'a servi qu'à ça.

## Ce que le serveur en fera

Décoder les certificats en fichiers DER, puis
`cargo run --example verifier-une-chaine -- capture/` : la chaîne remonte-t-elle
à la racine de Google (`paquet/racines-android/google.pem`) ? L'extension
`1.3.6.1.4.1.11129.2.1.17` de la feuille porte-t-elle le défi, un
`attestationSecurityLevel` matériel, `verifiedBootState` à `Verified`, et notre
paquet sous notre empreinte ? C'est la capture qui dit la forme exacte —
l'ordre des champs, la version du schéma, la taille de la chaîne — et c'est
elle qui fixe la politique d'`asl-keystore`.

## À noter

- En production, le défi n'est pas un aléa : c'est
  `SHA-256(asl_cle::message_d_attestation(clé, défi, liaison))`, posé à la
  génération de la clé d'appareil elle-même (`protocole.md` §2.1). La clé
  attestée est la clé enrôlée.
- La chaîne d'un appareil certifié remonte à la racine de Google, celle d'un
  GrapheneOS à la racine de GrapheneOS : les deux sont des fichiers, et
  l'exploitant choisit lesquels il épingle (`--android-roots`).
