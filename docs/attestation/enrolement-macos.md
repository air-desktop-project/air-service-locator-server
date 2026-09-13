# Consignes — app macOS d'enrôlement (validation clé-d'appareil sur vrai matériel Apple)

## But, et sa limite

Valider **sur un vrai Mac T2** (Secure Enclave + Touch ID) toute la chaîne
**clé-d'appareil P-256** : création de la clé matérielle, geste biométrique,
**preuve de possession**, **création de compte**, enrôlement, transport QUIC réel,
et par ricochet les endpoints mobiles `#1`–`#4` contre un banc.

**Ce que ça NE valide PAS.** App Attest (`DCAppAttestService`) **n'existe pas sur
macOS**. Cette app ne produit donc **aucune** attestation Apple : le compte se crée
en `attestation = Aucune`. `asl-apple` (la vérif d'attestation Apple) reste
confrontée à la documentation seule jusqu'à une capture sur un **vrai iPhone**.
Ce qu'on gagne ici, c'est la validation de `asl-cle` et de l'enrôlement sur du
matériel Apple réel — pas de l'attestation.

## Ce qui existe déjà et se réutilise (dépôt `-ios`, branche `ecrans`)

- `Sources/Coeur/Identite/CleAppareil.swift` — la clé **Secure Enclave P-256**
  (`SecureEnclave.P256.Signing.PrivateKey`). **Elle a déjà les branches macOS** :
  la clé est créée sans `.biometryCurrentSet`, et `signer(_:)` demande Touch ID
  via `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` avant
  **chaque** signature. À vérifier telle quelle sur le Mac.
- `Sources/Coeur/Reseau/Reel/AnnuaireReel.swift` — le transport réel par la lib
  client (`asl_appareil_*`). Il **crée déjà le compte en `ASL_PLATEFORME_AUCUNE`**
  (`asl_appareil_creer_compte(handle, ASL_PLATEFORME_AUCUNE, nil, 0, …)`), prouve
  la possession, et fait les requêtes via `asl_appareil_requete`.
- `Sources/Coeur/Reseau/Annuaire.swift` — l'interface `Annuaire` que l'UI parle.
- Le xcframework `AslClient` — construit par `scripts/construire-mobile.sh` **dans
  le dépôt client**.

## Ce qu'il faut produire (le neuf)

1. **Une cible macOS** (app SwiftUI), qui dépend de `Coeur`. Le plus simple : une
   cible macOS ajoutée au projet `-ios` (multiplateforme), qui réemploie `Coeur`
   tel quel. Pas de nouveau dépôt.

2. **Le xcframework pour macOS.** `construire-mobile.sh` (dépôt client) produit
   aujourd'hui les slices iOS (device + simulateur). Ajouter les **slices macOS** :
   `aarch64-apple-darwin` (et `x86_64-apple-darwin` si un Mac Intel est visé),
   fondues dans `AslClient.xcframework`. C'est un changement **côté dépôt client**
   (`voie-mobile`), et l'ABI ne change pas.

3. **Signature & entitlements.** La Secure Enclave exige une **app signée** (une
   identité de développement suffit ; l'ad-hoc ne marche pas — `CleAppareil` bascule
   alors sur son mode dégradé, comme en CI). Prévoir :
   - `com.apple.developer.kernel.increased-memory-limit` **non** requis ;
   - l'**App Sandbox** peut rester activée ; si un `keychain-access-group` est
     utilisé pour ranger la représentation de la clé, le déclarer dans les
     entitlements ;
   - **Touch ID** ne demande pas d'entitlement particulier, seulement une app
     signée et un Mac T2/Apple Silicon avec Touch ID configuré.

4. **UI minimale — trois gestes** :
   - **« Enrôler ce Mac »** : `CleAppareil.ouOuvrir()` (crée/charge la clé, premier
     Touch ID) → `AnnuaireReel.creerCompte(...)` → afficher l'**identifiant de
     compte** (`u-…`) et d'**appareil** (`a-…`). Les ranger (comme `Carnet` le fait
     déjà) pour rejoindre ensuite sans recréer.
   - **« Lister mes machines »** : `GET /v1/machines` → afficher le tableau (vide au
     début — c'est normal et attendu ; il se remplit si on déclare une machine).
     C'est la preuve de bout en bout que **#1** répond depuis un vrai client Apple.
   - **« Lister mes appareils »** : `GET /v1/appareils` → on doit y voir CET appareil
     avec `attestation: "aucune"` et `revoque: false`. Preuve de **#2**.

5. **Cible réseau** : **`nitrogen.air-desktop.org`**, QUIC/HTTP-3 sur **6630/udp**,
   **IPv6 d'abord**. **Ancrer sur le NOM, jamais sur l'IP** (l'allocation OVH n'est
   pas la nôtre ; `docs/annuaires.md` l'explique). `argon.air-desktop.org` est le
   second banc, en repli.

## Critères de succès (ce que je veux voir de mon côté)

- Un **compte créé sur nitrogen** avec un **appareil P-256** — vérifiable côté
  serveur, et côté app par `GET /v1/appareils` rendant `attestation: "aucune"`.
- Le **prompt Touch ID** à la première signature (possession) et à chaque signature
  suivante.
- `GET /v1/machines` et `GET /v1/appareils` **répondent** (200) depuis l'app macOS
  contre le vrai annuaire — pas l'`Annuaire` simulé.

## Rappels du parc et des conventions

- Les bancs sont en **`ASL_ATTESTATION=facultative`** : n'importe qui peut créer un
  compte, donc `attestation = Aucune` est **accepté**. C'est ce qui rend ce test
  possible sans iPhone. Le jour où ces annuaires deviennent racines pour de vrai,
  cette posture se resserre et un compte `Aucune` sera refusé — ce test macOS
  restera alors un test, pas un usage.
- Le SHA serveur épinglé par le client est **`2cf05dc`** ; nitrogen et argon
  **servent `2cf05dc`** (les quatre verbes). Donc `#1`–`#4` sont réellement
  joignables depuis cette app.
- Conventions du dépôt : commits **français**, **GPG + DCO**, **zéro mention
  d'un outil** ; **aucun secret** dans un commit (ce dépôt est public). Ne pas
  committer de clé, d'identifiant de compte réel, ni de jeton.

## Ce que ça débloque ensuite

Une fois cette app verte, la seule pièce Apple qui manque est l'**attestation App
Attest**, qui exige un iPhone. Côté Google, le pendant est la **capture Play
Integrity sous clés « gérées par moi »** (voir `capture-play.md`) — indépendante de
celle-ci.
