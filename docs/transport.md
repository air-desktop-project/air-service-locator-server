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

|  | Avant | Après la greffe | Avec la boucle |
|---|---|---|---|
| Paquets **résolus** | 32 | 120 | **130** |
| Unités **construites** | 30 | 99 | **107** |
| dont tierces | 21 | 89 | **97** |
| Objets C produits | 0 | 0 | **0** |

La boucle UDP a coûté huit unités — `tokio` et ses dépendances. La borne de C4
est à 120 : il en reste treize, et **c'est l'entrepôt qui les demandera**.

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

- ~~La socket UDP et le routage des paquets vers les connexions.~~ **Fait** :
  `asl-loop-tokio::quic`, et §9 ci-dessous.
- ~~L'horloge des délais de renvoi.~~ **Faite**, dans la même boucle.
- ~~D'où viennent les certificats.~~ **Tranché le 2026-09-09 — voir §8.**
- ~~L'entrepôt.~~ **Fait**, et le produit est bouclé : un daemon annonce le port
  que son système lui a donné, et un pair autorisé le retrouve, sur une AUTRE
  connexion. Ce qui reste : le motif de départ réel, et ce qui CRÉE
  les objets — comptes, machines, autorisations passent encore par l'entrepôt à
  la main. **La sonde mesure** (`asl-loop-tokio::sonde`), et seulement le
  candidat réflexif — voir `modele.md` §4.3 pour ce que sonder une adresse
  annoncée aurait coûté.

---

## 8. Les certificats : une autorité à nous, et pourquoi

Tranché le **2026-09-09**. La cérémonie est `scripts/ca.sh`.

### La CA d'`air` ne pouvait pas servir, et il faut dire pourquoi

C'était la première piste, et elle est fausse : **l'autorité d'`air` est une CA
SSH.** `air-keystore ca create` et `cert issue-host` émettent au format
**OpenSSH** (`air-ssh-proto::cert`, ADR-109 et ADR-162), pour `air-sshd`. Le
format n'a rien de commun avec X.509, et `air-crypto` écrit noir sur blanc que
« PEM/DER, certificats X.509 » sont **hors de son périmètre**. `air-tls`, elle,
est une spécification : elle *valide* des chaînes X.509, elle n'en émet pas.

Une CA SSH ne peut pas signer un certificat de serveur TLS. Le jour où Air aura
une autorité X.509, cette cérémonie sera à reprendre.

### Une racine à nous, épinglée, plutôt qu'une CA publique

**Nous tenons les deux bouts** : le serveur est à nous, et le client aussi —
`asl-client` et les applications mobiles. Aucun navigateur ne se connectera
jamais à un annuaire.

Une CA publique coûterait un nom de domaine par annuaire, un renouvellement
automatique, et un tiers dans la boucle — pour convaincre des logiciels qui ne
viendront pas. Une racine `air-desktop-project` épinglée dans le client dit
exactement ce qu'on veut dire, et le dit **sans dépendre de la liste des
autorités du système**, que nous ne contrôlons pas.

### Ed25519, et la raison est vérifiable

Le fournisseur cryptographique sous notre pile est `rustls-rustcrypto`. Son
module `sign/eddsa.rs` charge une clé **Ed25519 au format PKCS#8** et signe avec
— exactement ce que produit `openssl genpkey -algorithm ed25519`. C'est aussi
l'algorithme des clés de machine (`asl-cle`) : **une seule courbe dans tout le
produit**, donc une seule à auditer.

### Des SAN d'ADRESSE, et c'est « IPv6 d'abord » qui l'impose

C'est le point qu'une cérémonie naïve rate. Un daemon rejoint un annuaire par
son **adresse**, pas nécessairement par un nom : une machine à IPv6 publique n'a
besoin d'aucun DNS. Un certificat qui ne porterait que des `DNS:` serait refusé,
et le refus serait juste.

`ca.sh` classe donc ses arguments : ce qui a la forme d'une adresse devient un
`IP:`, le reste un `DNS:`.

### `openssl` frappe le certificat, et C4 n'en souffre pas

C4 interdit à `asl-client` de **lier** du C, parce qu'elle est chargée dans des
interpréteurs qui ont déjà leur libcrypto. Employer un outil pour frapper un
certificat une fois n'a rien à voir : rien de ce que fait la cérémonie n'entre
dans le binaire livré, et `check-sans-c.sh` — qui mesure ce qui est **construit**
— ne verra jamais openssl.

### CE QUI EST VÉRIFIÉ, ET PAS SEULEMENT AFFIRMÉ

`ca.sh` finit par `openssl verify`, et **cela ne prouve rien** : openssl s'y
donne raison à lui-même. Deux essais d'intégration (`asl-loop-tokio/tests/`)
frappent donc une autorité dans un répertoire temporaire, puis la font charger
par la pile qui servira réellement, via `ams_tls::quic_server_config` :

  1. une chaîne et sa clé sont **acceptées** — ce qui éprouve l'algorithme, le
     format PKCS#8 et l'encodage ;
  2. la clé d'un serveur croisée avec le certificat d'un autre est **refusée** —
     ce qui éprouve que le contrôle d'accord est vivant. Sans lui, un serveur
     monté sur une clé dépareillée démarrerait pour échouer à la première
     connexion.

Ils n'ouvrent jamais la racine réelle : `ASL_CA` déplace la cérémonie, et
`local/` — où vit la vraie — est ignoré par git.

### CE QUE LA CÉRÉMONIE N'EST PAS ENCORE, ET QU'IL NE FAUT PAS CROIRE

- **Pas d'intermédiaire.** La racine signe les serveurs directement. Un
  intermédiaire sert à garder la racine hors ligne, et cela n'a de sens que le
  jour où elle le sera vraiment.
- **Pas de révocation.** Ni CRL, ni OCSP. La validité d'un an des certificats de
  serveur en tient lieu — c'est un aveu, pas un choix.
- **La racine de production n'existe pas.** Celle que `ca.sh` crée aujourd'hui
  est une racine de développement. Le certificat de la vraie racine sera à
  épingler dans `asl-client`, et sa clé privée relève d'une cérémonie hors ligne
  qui reste à écrire.

---

## 9. La boucle UDP : ce qui a été écrit, et ce qui ne l'a pas été

Écrite le **2026-09-09**, dans `asl-loop-tokio`.

### Trois modules, et aucun ne décide

| Module | Ce qu'il fait |
|---|---|
| `quic` | La socket, la carte des connexions, la boucle, l'extinction en deux temps. |
| `pont` | Marie `ams_h3::Transport` et `ams_quic_tls::Connection`. |
| `h3` | Présente `asl-session` à `ams-h3`, connexion par connexion. |

### Une seule tâche, et non une par connexion

TCP donne une socket par connexion ; UDP n'en donne qu'une pour tout le monde.
Une tâche par connexion demanderait de recopier chaque datagramme vers une file
et de partager la socket d'émission — **deux synchronisations pour un travail
qui tient dans une boucle**.

La contrepartie est réelle : une connexion coûteuse retarde les autres. Elle est
tenable parce qu'aucune ne fait d'entrée-sortie — l'étage 2 ne peut pas, par
construction.

### Ce qui diffère d'`air-mail-server`, et pourquoi

**Pas de garde anti-abus.** `ams-loop-tokio` consulte `ams-guard` avant
d'accepter un `Initial`, et passe une `Source` à chaque rendez-vous de son
`Application`. Nous n'avons pas ce garde, et le trait porte donc une
`SocketAddr` — **pour une raison qui n'est pas la sienne** : l'adresse d'où un
daemon parle est de la DONNÉE pour l'annuaire (`Origine`, `VuDepuis` dans
`asl-proto`), la seule qu'on ait constatée plutôt qu'entendue.

**Une session par connexion.** `asl_session::Session` portera la machine
authentifiée, et la connexion QUIC **est** le bail : une session partagée entre
connexions ferait hériter une requête des droits d'une autre.

### `configuration_tls`, pour qu'un ALPN ne s'oublie pas

`ams_tls::quic_server_config` monte tout sauf l'ALPN, et le dit. Une
configuration qui l'oublie se construit, démarre, et échoue à la première
poignée de main — loin du fichier où l'oubli a eu lieu. Notre fonction n'a pas
de paramètre : **ce qu'on ne peut pas exprimer ne peut pas être faux.**

### CE QUI EST ÉPROUVÉ, ET COMMENT

Quatre essais d'intégration, dont deux qui font tourner **la chaîne entière** :
la cérémonie frappe un certificat, `configuration_tls` le monte, `servir_quic`
écoute sur une vraie socket UDP, et un vrai client QUIC — `ams-quic-client`,
employé ici comme ce qu'il est — monte la poignée de main et envoie une requête.

Ils affirment sur les champs **décodés**, jamais sur des octets. La première
version cherchait `no-store` dans la charge du flux et échouait : `cache-control:
no-store` est une entrée de la table statique de QPACK, donc il voyage sur un
seul octet d'index et la chaîne n'apparaît jamais sur le fil. **Un essai qui
cherche des octets ne distingue pas « absent » de « mieux encodé que je ne
croyais ».**

Ils vérifient aussi que le corps fait exactement la longueur annoncée — ce qui
éprouve, sur le fil, la réservation que le fuzz avait imposée à
`asl_session::composer`.

### Ce que la boucle ne fait pas, et qu'il ne faut pas croire

- **Elle ne suit pas les migrations** (§9 de RFC 9000). Une connexion qui change
  d'adresse cesse d'être servie : les suivre demande de valider le nouveau
  chemin, faute de quoi un paquet rejoué ferait rediriger le trafic vers une
  victime. Ici s'ajoute une raison de produit — une adresse qui change en
  silence ferait annoncer un service à une adresse que personne n'a vérifiée.
- **Elle ne négocie pas de version** (§6.1). Elle n'en sert qu'une, et jette ce
  qui demande autre chose ; §6.2 prévoit que le client abandonne.
- **Elle n'a aucune défense par source.** La seule borne est le nombre de
  connexions vivantes, qui vient de l'appelant. C'est une borne de MÉMOIRE, pas
  une protection contre un pair hostile qui ouvrirait des connexions valides.
