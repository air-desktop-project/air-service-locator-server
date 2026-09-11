# Capturer un jeton Play Integrity réel

`asl-play` sait déchiffrer et vérifier un jeton Play Integrity, mais il **n'en a
jamais vu un vrai** : sa forme — l'emballage `A256KW`, le chiffrement `A256GCM`,
la signature ES256, les champs du verdict — vient de la documentation de Google.
Tant que c'est vrai, `PlateformeAttestation::Google` reste refusée, et la
politique de verdict n'est pas écrite.

**Ce document sert à obtenir la première capture**, et à la confronter à notre
code. C'est le pendant de [`capture-reelle.md`](capture-reelle.md) pour Android.

## Ce qu'il faut, côté toi

| Il faut | Pourquoi |
|---|---|
| Un appareil Android **réel**, avec les services Google Play | Play Integrity est inerte sur un émulateur sans Play, ou un appareil non certifié. |
| Un **projet Google Cloud**, l'API Play Integrity activée | La demande de jeton s'y rattache par son numéro. |
| L'app liée à ce projet dans la **Google Play Console** | C'est là que se règle le chiffrement de réponse. |
| Les **clés de chiffrement de réponse « gérées par moi »** | Sans elles, seul Google peut déchiffrer le jeton ; avec elles, notre serveur le fait hors ligne. |

**Le réglage qui compte, dans la Play Console** : *App integrity → Response
encryption → « Manage and download my response encryption keys »*. Google donne
alors deux valeurs base64 :

- une **clé de déchiffrement** (AES-256) ;
- une **clé de vérification** (clé publique EC, au format SPKI).

Ce sont elles que le serveur tiendra, comme il tient l'`--apple-app` pour Apple.
**Si le chiffrement reste « géré par Google », le jeton ne se déchiffre pas hors
ligne** — il faudrait appeler Google, ce que l'annuaire ne fait pas.

## Le geste, en cinq pas

1. Dans une app de test, ajoute la dépendance
   `com.google.android.play:integrity:1.4.0`.
2. Colle [`CaptureIntegrity.kt`](CaptureIntegrity.kt), et remplis
   `NUMERO_PROJET_CLOUD` (le NUMÉRO du projet, pas son identifiant textuel).
3. Appelle `capturerUnJeton(context)` une fois.
4. Lance sur l'**appareil**, lis Logcat (étiquette « CAPTURE »).
5. Recopie le bloc `──── CAPTURE PLAY INTEGRITY ────`.

## Ce que tu me rends

| Valeur | D'où elle vient |
|---|---|
| `JETON` | imprimé (le jeton chiffré, déjà du texte) |
| `DEFI` | imprimé (le nonce que l'app a posé) |
| `PAQUET` | imprimé |
| clé de **déchiffrement** | Play Console, une fois (base64) |
| clé de **vérification** | Play Console, une fois (base64) |

**Rien là-dedans n'est un secret de session** : le jeton est à usage unique et
le défi est jetable. Les DEUX CLÉS, en revanche, sont des secrets d'exploitation
— la clé de déchiffrement surtout. Envoie-les par un canal que tu juges sûr, pas
en clair dans un dépôt public ; elles finiront dans les réglages de l'annuaire,
jamais dans le code.

## Ce que j'en fais

Les valeurs deviennent un dossier :

```
printf '%s' "$JETON"                        > capture/jeton.txt
base64 -d <<< "$CLE_DECHIFFREMENT_B64"      > capture/cle-dechiffrement.bin
base64 -d <<< "$CLE_VERIFICATION_B64"       > capture/cle-verification.der
```

Puis l'outil de ce dépôt l'ouvre :

```
cargo run --example verifier-un-jeton -- capture/
```

Il dit l'un ou l'autre :

- **✔ OUVERT** — notre déchiffrement et notre vérification sont les bons, et il
  **imprime le verdict JSON**. C'est ce verdict réel qui me dira quels champs
  lire et quelles valeurs accepter — le `nonce` à comparer au défi,
  l'`appRecognitionVerdict`, le `deviceRecognitionVerdict`, le `packageName`,
  l'empreinte du certificat. J'écris alors la politique et je branche
  `PlateformeAttestation::Google`, sur du réel plutôt que sur la documentation.
- **✘ REFUSÉ : `<raison>`** — une DÉCOUVERTE, pas un échec. L'outil dit laquelle
  de nos hypothèses est fausse. La plus probable est l'enveloppe : si Google
  emploie `dir` plutôt que `A256KW`, ou un autre chiffrement, le refus le dira,
  et cela se corrige sur les octets réels.

## Ce qui reste vrai quoi qu'il arrive

Une capture confirme le CHEMIN cryptographique et révèle la forme du verdict. La
politique — quels verdicts d'appareil suffisent (`MEETS_DEVICE_INTEGRITY`,
`MEETS_STRONG_INTEGRITY`), faut-il exiger `PLAY_RECOGNIZED` — reste une décision
de produit, que je te soumettrai une fois le vrai verdict sous les yeux.

**Le nonce, côté production**, portera notre liaison comme pour Apple :
`base64url(asl_cle::message_d_attestation(clé, défi, liaison))`. Pour la
capture, un défi aléatoire suffit — on valide la forme, pas la liaison.
