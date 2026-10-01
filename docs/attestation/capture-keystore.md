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
  `SHA-256(asl_cle::message_d_attestation_de_cle(défi, liaison))` — sans la
  clé, qui n'existe pas encore —, posé à la génération de la clé d'appareil
  elle-même (`protocole.md` §2.1). La clé attestée est la clé enrôlée, et c'est
  le certificat qui la porte.
- La chaîne d'un appareil certifié remonte à la racine de Google, celle d'un
  GrapheneOS à la racine de GrapheneOS : les deux sont des fichiers, et
  l'exploitant choisit lesquels il épingle (`--android-roots`).

## Deux empreintes de signataire, parce que le Play Store resigne

**Depuis 0.46.0 (décision 109), `--android-signer` se répète**, et une
attestation passe dès qu'elle porte **n'importe laquelle** des empreintes
épinglées. La raison n'est pas de confort : l'app sera publiée **gratuitement
sur le Play Store**, et le Play Store **resigne l'APK avec sa propre clé** —
« Play App Signing ». Google garde la clé de publication ; la clé de nos builds
n'est plus que la **clé de téléversement**, celle qui prouve à la console que le
paquet vient de nous. Un appareil qui a installé l'app depuis le magasin
présente donc, dans son `attestationApplicationId`, l'empreinte de **Google**.

Il en faut donc deux, et elles se lisent à deux endroits différents :

| L'empreinte | Où on la lit |
|---|---|
| **Nos builds** — débogage, release installée à la main, la capture ci-dessus | `apksigner verify --print-certs <apk>`, champ `Signer #1 certificate SHA-256 digest` |
| **Celle du magasin** — l'app telle que le Play Store la sert | Google Play Console, *Test and release → Setup → App signing*, empreinte **SHA-256 du certificat de signature de l'app** |

**Attention à la ligne qu'on recopie** : la page *App signing* de la console
montre DEUX certificats, celui de la **clé de signature de l'app** (« App
signing key certificate ») et celui de la **clé de téléversement** (« Upload key
certificate »). C'est le **premier** qu'il faut épingler — c'est lui qui signe
ce que les appareils installent. L'empreinte s'y lit en hexadécimal avec des
deux-points, forme que `--android-signer` accepte telle quelle, majuscules
comprises.

**Ce n'est pas un affaiblissement.** Chaque empreinte est épinglée une par une,
comme l'unique empreinte d'avant : aucune n'est devinée, aucune n'est admise
parce qu'elle remonte à une autorité, aucune n'est négociée par l'appareil. Une
troisième empreinte — une build que personne n'a autorisée — reste refusée
(« app signée par un autre certificat »). Ce qui s'élargit est l'ensemble des
builds reconnues, jamais le pouvoir d'en fabriquer une.

Le démarrage les relit toutes, et les nomme :

```text
asl-server : attestation Android — 1 racine(s) épinglée(s), paquet org.airdesktop.servicelocator, signataire(s) 5ea316f1…, 0123abcd….
```
