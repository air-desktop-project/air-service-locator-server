# Captures réelles

Ce que les téléphones ont réellement produit, tel quel — pour confronter
`asl-play` et `asl-apple` à autre chose que la documentation.

| Fichier | Quoi | Où, quand |
|---|---|---|
| `play-integrity-2026-09-12.txt` | Un jeton Play Integrity (`JETON`), le nonce posé par l'app (`DEFI`), le paquet (`PAQUET`) | Fairphone 5, Android 15, `outils-capture/CaptureIntegrity.kt` de l'app Android, projet Cloud `861147308432`, le 2026-09-12 |

**Ce que ce jeton permet, et ce qu'il ne permet pas encore.** Au moment de la
capture, l'application n'était pas dans la Play Console : le jeton est donc
chiffré avec les clés que **Google gère**, et seul Google peut l'ouvrir. Il
confirme la forme (un JWE `A256KW` / `A256GCM`, puis un JWS), pas encore le
verdict. Dès que les clés « gérées par moi » seront posées dans la Play Console
(*App integrity → Response encryption*), un jeton sera recapturé sous ces
clés-là — c'est celui qui s'ouvrira hors ligne avec
`cargo run --example verifier-un-jeton`.

**Les clés, elles, ne sont jamais ici.** Ce dépôt est public ; la clé de
déchiffrement et la clé de vérification vont dans les réglages du serveur, par
un canal privé.
