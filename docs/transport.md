# Le transport : QUIC et HTTP/3, greffés depuis `air-mail-server`

Ce document consigne **ce qui a été repris, ce qui ne pouvait pas l'être, et ce
que la greffe coûte** — mesuré, pas estimé. Il ne redit pas ce que fait QUIC : il
dit ce que ce projet en prend, et pourquoi il en écrit le reste.

Mesures du **2026-09-09**, sur l'épinglage `3f18333` d'`air-mail-server`.

---

## 1. Pourquoi une pile se transplante

Une pile réseau ordinaire ne se déplace pas d'un produit à l'autre : elle tient
une socket, une boucle, un pool de tampons, et tout cela est tissé avec le
serveur qui l'héberge. Celle-ci se déplace, et pour une seule raison.

> `ams-quic`, en tête de son manifeste : « La machine de connexion QUIC, **sans
> entrée-sortie** ».

C'est la contrainte C1 d'`air-mail-server`, et c'est elle qui rend la greffe
possible. Une machine à états qui n'ouvre rien, n'attend rien et ne lit pas
l'heure ne dépend pas du programme qui la pilote. **Elle se prend telle quelle.**

L'imposition de réutiliser ces crates et celle de n'écrire que des codecs sans
entrée-sortie ne sont donc pas deux règles : c'est la même, vue à deux moments.

---

## 2. Ce qui est repris, sans une ligne modifiée

| Crate | Ce qu'elle porte |
|---|---|
| `ams-proto-quic` | La grammaire QUIC : en-têtes, trames, entiers variables. Sans clé. |
| `ams-quic-crypto` | Le chiffrement et le démasquage. Sans grammaire. |
| `ams-quic` | La machine de connexion : c'est là que grammaire et clés se rencontrent. |
| `ams-quic-tls` | La poignée de main TLS de RFC 9001, et l'ALPN `h3`. |
| `ams-proto-h3` | Le cadrage HTTP/3, les types de flux, QPACK. |
| `ams-h3` | Le conducteur : quel flux ouvrir, dans quel ordre, où rattacher les octets. |
| `ams-proto-http` | Méthodes, statuts, têtes de requête, bornes. |
| `ams-field-codec` | L'encodage des champs, tiré par `ams-proto-h3`. |
| `ams-tls` | Le fournisseur cryptographique, tiré par `ams-quic-tls`. |
| `ams-dane` | Tiré par `ams-tls`. **C'est une feuille** — elle ne dépend que de `sha2`. |

`ams-dane` mérite le mot : c'est de l'infrastructure de courrier (les
enregistrements TLSA), et elle entre ici sans qu'on la demande. Elle n'entraîne
rien derrière elle, donc on la laisse plutôt que de forker `ams-tls` pour
l'ôter — mais c'est une arête à couper le jour où ces crates migreront dans
`air`.

---

## 3. Ce qui NE pouvait pas être repris

### `ams-quic-client` — ce n'est pas une bibliothèque cliente

Le nom promet le contraire, et il fallait ouvrir la crate pour le savoir. Elle
expose :

- `SANS_OPENSSL: &str = "ce test EXIGE openssl…"` ;
- `atelier(nom) -> Atelier`, qui crée un répertoire temporaire ;
- `materiel(repertoire)`, qui **fabrique des certificats d'essai** ;
- des identifiants de connexion **fixes**, `ORIGINE` et `CLIENT` ;
- `envoyer_une_requete` / `attendre_la_reponse`.

**C'est un harnais d'essai.** Rien de cela n'a sa place dans un produit, et le
client daemon devra être écrit sur `ams-quic` + `ams-quic-tls` + `ams-h3`
directement.

### `ams-loop-tokio` — c'est la boucle d'un autre produit

Son `serve_quic<App, Arret>` est générique par sa forme, et l'on pourrait croire
qu'il suffit. Il est tissé avec `ams-guard`, le garde anti-abus du serveur de
courrier, et avec sa notion de source. Le reprendre ferait entrer ici les
décisions d'un autre produit — et un garde conçu pour du SMTP n'est pas celui
d'un annuaire.

**Nous écrivons donc notre boucle**, dans `asl-loop-tokio`. C'est la seule chose
que la greffe oblige à réécrire, et c'est aussi la seule qui touche une socket.

---

## 4. Le joint, et pourquoi il tombe à l'étage 2

`ams-h3` demande un `Service` :

```rust
fn serve<'o>(&mut self, tete: &RequestHead<'_>, corps: &[u8], sortie: &'o mut [u8]) -> Reponse<'o>;
```

**Cette fonction est pure.** Elle n'ouvre rien, n'attend rien, ne lit pas
l'heure. Le joint entre la pile et notre produit n'est donc pas un point
d'entrée-sortie : c'est une décision.

C'est pourquoi `asl-session` existe, à l'étage 2, sous le régime de couverture —
et non dans `asl-loop-tokio`. L'y loger aurait mis **le traitement des requêtes
du produit entier** hors de toute mesure, au prétexte que le voisin tient une
socket.

`asl-loop-tokio` ne garde donc que ce qui ne peut pas être ailleurs : `Pont`,
qui marie `ams_h3::Transport` et `ams_quic_tls::Connection`. La règle de
l'orphelin interdit ce mariage partout ailleurs, et c'est le bon endroit — il
demande une vraie connexion pour être éprouvé.

---

## 5. Ce que la greffe coûte, mesuré

|  | Avant | Après |
|---|---|---|
| Paquets **résolus** | 32 | **120** |
| Unités **construites** | 30 | **99** |
| dont tierces | 21 | **89** |
| Objets C produits | 0 | **0** |

Le graphe est donc multiplié par quatre. C'est le prix d'une pile QUIC et
HTTP/3 complète en Rust pur, et il faut le mettre en regard de ce qu'il évite :
`ring` ou `aws-lc-rs` remplaceraient une trentaine de ces crates par une
bibliothèque C que l'on ne peut pas charger dans un interpréteur Python.

### `ring` est dans le résolu, et n'est pas construit

`rustls` déclare `ring` en dépendance **optionnelle** ; nous ne l'activons pas,
puisque le fournisseur retenu est `rustls-rustcrypto`, en Rust pur. Mais `ring`
reste dans `Cargo.lock`, et il amène `cc` avec lui.

**`check-sans-c.sh` aurait annoncé « VIOLATION cc » sur une crate que le
compilateur ne touche jamais** — et « VIOLATION windows-sys » sur une plateforme
qui n'est pas la nôtre. C'est ce qui l'a fait passer de `cargo metadata` (le
résolu) à `cargo build --unit-graph` (le construit).

C'est la deuxième fois que ce script accuse à tort, et la leçon est la même
qu'à la première : **un contrôle qui crie au loup s'apprend à s'ignorer.**

### `ed25519-dalek` est passée en 3, et c'est la greffe qui l'a exigé

`rustls-rustcrypto` en tire la 3. Rester en 2 aurait mis **deux implémentations
d'Ed25519 dans le même binaire** — celui-là même qu'un daemon tiers lie. Le
passage n'a coûté aucune ligne de code : `asl-cle` n'emploie que `VerifyingKey`,
`SigningKey`, `Signature`, `Signer` et `Verifier`, dont la forme n'a pas bougé.

---

## 6. Ce que la greffe fait accepter, et qu'il faut savoir

Ces trois points ne sont pas des défauts à corriger ici : ce sont des choix
d'`air-mail-server` dont nous héritons parce que C15 impose de réutiliser. Ils
sont écrits pour être décidés en connaissance de cause, pas découverts un jour de
panne.

1. **Le fournisseur cryptographique de TLS est un pré-livrable, sur un rev git.**
   `rustls-rustcrypto 0.0.2-alpha`, épinglée sur `cb967bd6` du dépôt RustCrypto.
   C'est une dépendance `git` **dans** une dépendance `git` : `cargo audit` ne la
   voit pas. Elle amène `rsa 0.10.0-rc.18`, également pré-livrable.

   **C'est le prix du « aucune ligne de C ».** Les deux fournisseurs mûrs de
   `rustls` sont `ring` et `aws-lc-rs`, et tous deux compilent du C — ce que C4
   interdit, structurellement, parce qu'`asl-client` est chargée dans des
   interpréteurs Python et Ruby.

2. **La toolchain diverge de celle de l'amont.** `air-mail-server` est épinglé
   sur **stable 1.98.0** ; ce dépôt est sur **`nightly-2026-07-11`**, celle
   d'Air, et C16 l'exige. La pile est donc compilée ici par une toolchain sous
   laquelle son propre dépôt ne la vérifie jamais. Elle passe — c'est mesuré —
   mais une régression d'amont ne serait pas vue par la CI d'amont.

3. **`x25519-dalek` est construite deux fois**, en 2.0.1 et en 3.0.0. Le doublon
   vient d'`air-mail-server` et existait avant nous.

---

## 7. Ce qui manque pour qu'un serveur tourne

Nommé ici pour ne pas être redécouvert :

- **La socket UDP et le routage des paquets vers les connexions** — c'est le
  gros de `asl-loop-tokio`, et il n'existe pas encore.
- **L'horloge des délais de renvoi**, et l'expiration des connexions.
- **D'où viennent les certificats.** Un serveur QUIC en présente un. Le produit
  n'a pas dit s'il est auto-signé, obtenu par ACME, ou fourni par
  l'administrateur de l'annuaire — et la réponse change ce que la boucle lit au
  démarrage. **C'est une décision, pas un détail d'implémentation.**
- **L'entrepôt.** `asl-session` route et refuse correctement ; tout ce qui se
  route rend `501`, parce qu'aucune ressource de cette API ne se sert sans état.
