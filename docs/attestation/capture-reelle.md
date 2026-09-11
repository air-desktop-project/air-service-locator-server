# Capturer une attestation App Attest réelle

`asl-apple` vérifie une attestation d'Apple, et il est écrit **d'après la
documentation d'Apple, pas d'après un appareil**. Aucun iPhone n'a jamais parlé
à ce dépôt. Tant que c'est vrai, `--attestation exigee` ne peut pas être tenue
pour sûre : le premier appareil légitime serait peut-être le premier refusé,
parce qu'une constante — la forme de l'extension, la façon de hacher la clé,
l'ordre des certificats — diffère de ce que la documentation laisse croire.

**Ce document sert à obtenir cette première capture**, et à la confronter à
notre code. Il faut une chose, une seule, mais elle n'est pas facultative : **un
vrai appareil et un compte développeur Apple.**

## Ce qu'il faut, côté toi

| Il faut | Pourquoi |
|---|---|
| Un iPhone ou iPad **réel**, iOS 14+ | App Attest est inerte au simulateur (`isSupported` y est faux). |
| Un compte au **programme développeur Apple** | App Attest exige un Team ID à 10 caractères ; il n'y a pas de mode anonyme. |
| Xcode, une app de test quelconque | Pour lancer le code de capture sur l'appareil. |

Rien de plus : **pas d'entitlement spécial** pour une capture de développement.
Une app lancée depuis Xcode reçoit une attestation d'environnement
« développement » (l'`aaguid` vaut `appattestdevelop`), et c'est exactement le
cas le plus simple — celui qu'on veut d'abord.

## Le geste, en cinq pas

1. Crée (ou ouvre) une app de test dans Xcode, avec ton équipe de signature.
2. Colle [`CaptureAppAttest.swift`](CaptureAppAttest.swift) dans le projet.
3. Appelle `capturerUneAttestation()` une fois — depuis un bouton, ou
   `applicationDidBecomeActive`.
4. Lance sur l'**appareil** (pas le simulateur), regarde la console d'Xcode.
5. Recopie le bloc `──── CAPTURE APP ATTEST ────`, et **complète l'`APP_ID`** :
   Xcode ne donne pas le Team ID à l'exécution, il est dans
   *Certificates, Identifiers & Profiles*, ou en tête de *Signing & Capabilities*.

Le code ne fait rien de subtil : il tire trente-deux octets de défi, génère une
clé neuve dans le matériel sécurisé, calcule `clientDataHash = SHA256(défi)`,
demande l'attestation, et imprime le tout en base64. **On ne lie rien à une
connexion ici** — une capture valide le FORMAT, pas la liaison de canal, qui est
notre code à nous et déjà éprouvé.

## Ce que tu me rends

Cinq valeurs. Trois viennent du bloc imprimé, deux se complètent :

| Valeur | D'où elle vient |
|---|---|
| `ATTESTATION_B64` | imprimé |
| `DEFI_B64` | imprimé |
| `APP_ID` | imprimé, **le Team ID à compléter** — `ABCDE12345.ch.narro.montest` |
| `ENVIRONNEMENT` | `developpement` (lancé depuis Xcode) ou `production` (TestFlight/App Store) |
| `KEY_ID_B64` | imprimé — facultatif, pour recouper si besoin |

Un simple message avec ces lignes suffit. **Rien là-dedans n'est un secret** :
une attestation est publique par nature, la clé qu'elle certifie n'a pas encore
de compte, et le défi est jetable. On peut donc en discuter à découvert, et même
la commettre comme vecteur d'essai (voir plus bas).

## Ce que j'en fais

Les octets base64 deviennent quatre fichiers dans un dossier :

```
base64 -d <<< "$ATTESTATION_B64" > capture/attestation.cbor
base64 -d <<< "$DEFI_B64"        > capture/defi.bin
printf '%s' "$APP_ID"            > capture/app-id.txt
printf '%s' "$ENVIRONNEMENT"     > capture/environnement.txt
```

Puis l'outil de ce dépôt les rejoue contre la vraie racine d'Apple :

```
cargo run --example verifier-une-capture -- capture/
```

Il dit l'un ou l'autre :

- **✔ VÉRIFIÉE** — notre lecture du format d'Apple est la bonne. On peut tenir
  `--attestation exigee` pour sûre sur cet environnement, et — mieux — commettre
  la capture comme VECTEUR : `asl-apple` serait alors éprouvé contre une
  attestation réelle, et non seulement contre ce que la documentation décrit.
- **✘ REFUSÉE : `<raison>`** — et là, c'est une DÉCOUVERTE, pas un échec de
  capture. L'outil dit laquelle de nos hypothèses est fausse. Les deux plus
  probables, parce que la documentation d'Apple y est la plus vague :
  - `identifiant d'une autre clé` — Apple ne hache pas la clé publique comme
    nous (on hache le point P-256 non compressé de 65 octets). Réglage d'une
    ligne, une fois la bonne forme vue.
  - `extension d'Apple absente` ou `attestation illisible` — la forme exacte de
    l'extension `1.2.840.113635.100.8.2`, ou la disposition d'`authData`, diffère
    de ce qu'on a écrit. On la corrige sur les octets réels.

## Ce qui reste vrai quoi qu'il arrive

Une capture de **développement** valide App Attest en développement. La
**production** (TestFlight, App Store) a un `aaguid` différent, et il faudra une
seconde capture, plus tard, pour la tenir pour sûre à son tour — mais l'essentiel
du format est partagé, et la première capture lève l'essentiel du doute.

**Google Play Integrity n'est pas concerné** : c'est un jeton JWS d'une tout
autre forme, sa vérification n'est pas écrite, et une attestation Google est
aujourd'hui refusée. Sa capture à lui sera un autre document.
