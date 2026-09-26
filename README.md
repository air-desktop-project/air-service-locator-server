# air-service-locator-server

Le service d'**air-service-locator** : un annuaire de daemons réseau, écrit en
Rust.

> ## État : une arborescence, et rien d'autre
>
> **Ce dépôt ne sert rien.** Il compile, il est formaté, il est linté, et il
> porte deux gates de CI — mais ses huit crates sont des coquilles qui ne
> contiennent que leur intention.
>
> C'est délibéré. L'arborescence a été posée AVANT les spécifications, et
> `docs/` consigne ce qui n'est pas décidé plutôt que d'inventer ce qui l'aurait
> été. Le binaire `asl-server` le dit lui-même quand on le lance, plutôt que de
> démarrer une boucle vide qui aurait l'air de servir.

## Ce que les spécifications ont arrêté

Elles sont écrites, dans [`docs/`](docs/). Les quatre décisions qui gouvernent
tout le reste :

- **IPv6 d'abord, IPv4 en repli.** Ce n'est pas une préférence : une machine
  avec une IPv6 publique n'est derrière aucun NAT et tient l'exigence de
  joignabilité sans rien faire. Le NAT est le cas dégradé d'IPv4.
- **HTTP/3 sur QUIC, connexion tenue.** Le daemon garde une connexion ouverte ;
  la connexion *est* le bail. Un arrêt propre devient instantané, et l'annuaire
  peut parler au daemon.
- **L'accès est une arête entre deux comptes**, jamais un jeton porteur. Rien ne
  se lit anonymement.
- **Des clés, et rien d'autre.** Aucun mot de passe, aucun secret partagé : une
  machine détient une paire Ed25519 générée sur place dont la partie privée ne
  sort jamais, un téléphone détient une clé dans son matériel sécurisé.
- **Aucune donnée personnelle hébergée.** Ni courriel, ni numéro, ni nom. La
  seule exception est un **alias public**, facultatif, qui sert à être retrouvé
  et ne rend qu'un identifiant.
- **La pile QUIC et HTTP/3 est celle d'`air-mail-server`**, réutilisée et jamais
  réécrite — elle est transplantable parce qu'elle a été écrite comme un codec
  sans entrée-sortie. Elle migrera dans `air`.
- **Une seule toolchain, celle d'Air** : `nightly-2026-07-11`. Ce dépôt n'a
  besoin de rien de ce que nightly apporte — et c'est justement pour cela que la
  contrainte se violerait par inadvertance.
- **L'annuaire n'affirme jamais ce qu'il n'a pas mesuré.** Le mot « en ligne »
  n'apparaît nulle part : `annoncé`, `joignable` (avec sa date), `parti`.

Et il y a **plusieurs annuaires**. Deux racines, sur deux adresses IPv6 dont les
clés sont inscrites dans le code, servent de **registre et d'entremetteur** : un
annuaire neuf s'y fait recenser, ce qui ne lui donne accès à rien. **La confiance
est ensuite bilatérale**, acceptée par les deux administrateurs concernés, et
chacun choisit ce qu'il réplique chez lui en suivant la chaîne de possession
([`docs/annuaires.md`](docs/annuaires.md)).

## Le problème

Un daemon qui écoute sur un port choisi au démarrage — parce qu'il en a demandé
un libre au système, ou parce qu'il en change — est un daemon que ses clients ne
savent plus joindre. Le réflexe est de figer un numéro de port ; il se paie en
collisions, en pare-feu à rouvrir, et en un service qui ne peut pas tourner deux
fois sur la même machine.

`air-service-locator` déplace la question. Le daemon obtient le port qu'il veut,
puis **l'annonce** ; ses clients **le demandent** avant de se connecter.

## Les acteurs

| Qui | Ce qu'il fait |
|---|---|
| **L'utilisateur** | Se crée un compte depuis l'application iOS ou Android. Obtient un identifiant public. |
| **La machine** | Déclarée par l'utilisateur, connue par un identifiant public. |
| **Le daemon** | Tourne sur la machine. Annonce son port au démarrage, rafraîchit tant qu'il vit. |
| **Le client** | Demande à l'annuaire où joindre le daemon. |
| **L'annuaire** | Ce dépôt. Tient l'état, et répond « en ligne » ou « hors ligne ». |

## Les quatre dépôts

| Dépôt | Ce qu'il porte |
|---|---|
| `air-service-locator-server` | Ce dépôt — le service, en Rust. **Et les spécifications.** |
| `air-service-locator-client` | La bibliothèque que les daemons lient, ses liaisons et l'utilitaire `asl`. |
| `air-service-locator-ios` | L'application iOS (Swift). |
| `air-service-locator-android` | L'application Android (Kotlin). |

**Le modèle et le protocole sont spécifiés ICI**, dans `docs/`, et les trois
autres dépôts y renvoient par lien. Quatre copies vieilliraient, et trois d'entre
elles en silence.

Les deux applications ne s'installent que sur des appareils capables de
confirmer localement l'identité de leur porteur — Face ID, Touch ID, ou leur
équivalent Android. **Cette confirmation a lieu sur l'appareil et n'en sort
pas** : ce que le serveur constate est une signature matérielle, jamais une
identité. La nuance est écrite là où elle s'applique,
`crates/asl-auth/src/lib.rs`.

## Le découpage

Trois étages, et la frontière entre le deuxième et le troisième est la seule qui
compte. Le raisonnement complet est en tête de [`Cargo.toml`](Cargo.toml).

| Étage | Crates | Ce qu'elles n'ont pas le droit de faire |
|---|---|---|
| 1. Grammaires | `asl-id`, `asl-proto`, `asl-api` | Ouvrir une socket, lire un fichier, regarder l'heure. |
| 2. Décisions | `asl-annuaire`, `asl-auth` | Attendre. Elles reçoivent l'heure, elles ne la demandent pas. |
| 3. Exécution | `asl-store`, `asl-loop-tokio` | Décider quoi que ce soit. |
| Binaire | `asl-server` | Avoir une logique à lui. |

`asl-client` **a quitté ce dépôt** pour `air-service-locator-client` : c'est un
produit à part, avec ses liaisons Python, Ruby, C++, Kotlin et Swift, son
utilitaire en ligne de commande, et ses contraintes d'ABI. Il tire d'ici
`asl-id` et `asl-proto`, et rien d'autre — la frontière de dépôt rend littérale
la règle qui n'était qu'un conseil.

## Les barrières

Neuf, plus la couverture et le fuzz. Elles n'étaient que quatre tant que le
graphe était vide : les autres n'avaient rien à mesurer, et un rapport vert qui
n'a rien examiné est un mensonge poli.

```sh
scripts/check-tout.sh     # tout : étages, pile, sans-C, clippy, essais, fuzz, couverture, format
scripts/check-dco.sh      # après avoir committé : DCO et paternité
scripts/check-version.sh  # après avoir committé : la version a changé, et toutes les crates la partagent
```

**Chaque PR change la version** (`CLAUDE.md`), et `check-version` la tient : une
PR dont `[workspace.package] version` est celle de `main` ne se merge pas.
`asl-server --version` dit la version et le commit du binaire ;
`GET /v1/version` la rend à qui interroge l'annuaire, avec sa **posture**
d'attestation (`required`, `optional` ou `invitation`) — de quoi savoir, avant
d'ouvrir un compte, s'il faut un code d'invitation.

L'ordre n'est pas arbitraire, et le formatage est en dernier : une faute de forme
ne doit pas cacher une faute de fond.

## Lancer un annuaire

```sh
scripts/ca.sh racine
scripts/ca.sh serveur banc localhost ::1 127.0.0.1

cargo run -p asl-server -- \
    --store       local/annuaire.redb \
    --certificate local/ca/banc/chaine.pem \
    --key         local/ca/banc/serveur.key \
    --attestation optional      # ou `required` : il n'y a pas de défaut
```

**Deux racines qui se répliquent** (`docs/replication.md`) tiennent chacune une
clé d'identité, la clé publique de l'autre, et l'autorité qui valide son
certificat TLS :

```sh
asl-server --new-identity-key local/nitrogen.key      # écrit .key (0600) et .key.pub,
                                                      # imprime la clé publique et le n-…
cargo run -p asl-server -- … \
    --identity-key local/nitrogen.key \
    --peer         argon.air-desktop.org:6630 \
    --peer-key     local/argon.key.pub \              # le .pub de l'AUTRE
    --peer-ca      local/ca/racine.crt                # l'autorité de la cérémonie
```

**L'attestation de clé des Android** (`docs/protocole.md` §2.1, C19) se
vérifie hors ligne, contre des racines que VOUS épinglez — des fichiers PEM,
jamais un service appelé :

```sh
cargo run -p asl-server -- … \
    --android-roots  paquet/racines-android/google.pem \   # répétable
    --android-app    org.airdesktop.servicelocator \
    --android-signer 5ea316f1b50f2ce54b8225aba85ff5cc8238a710b8fae44b4f3a195aadeb5f68
```

Les trois vont ensemble, comme `--apple-app` et `--apple-environment` pour App
Attest. L'empreinte est celle du certificat qui signe la build de l'app
(`apksigner verify --print-certs`) — celle ci-dessus est la build de
**débogage** du Fairphone 5 ; la build de release en a une autre. Sans ces
réglages, un appareil qui présente une attestation Android est refusé, et le
journal d'exploitation dit pourquoi. `paquet/racines-android/google.pem` est la
racine de Google, telle que la capture réelle l'a rendue ; aucune n'est
épinglée par défaut.

**Les notifications** (`docs/protocole.md` §2.2, **servies depuis 0.19.0**) :
une autorisation accordée sur CETTE racine réveille les appareils vivants du
bénéficiaire d'un `POST` **vide** vers le point UnifiedPush que chacun a
déposé, et écrit `{"quoi":"autorisation"}` sur les flux `GET /v1/nouvelles`
qu'ils tiennent ici. Aucun serveur d'Apple ni de Google n'est appelé :

```sh
cargo run -p asl-server -- … \
    --push-roots /etc/ssl/certs/ca-certificates.crt   # les autorités des serveurs de poussée
```

`--push-roots` se lit comme `--peer-ca` et `--android-roots` : un fichier PEM
que VOUS désignez, rien de téléchargé, rien d'épinglé par défaut. **Pour
joindre ntfy.sh et les distributeurs publics, le paquet de certificats de la
distribution suffit** (`ca-certificates` sur Ubuntu) ; un distributeur
auto-hébergé sous votre propre autorité se joint en nommant un fichier qui la
porte. **Sans ce réglage, rien ne part** — ni résolution, ni connexion —, le
démarrage le dit, et `GET /v1/nouvelles` reste servi. C'est le seul appel
sortant d'une racine en dehors de son pair, et il est borné : le nom est
résolu à chaque envoi et **toutes** ses adresses doivent être unicast globales
(une seule adresse privée, de bouclage, de lien local… refuse l'envoi), la
connexion va à l'adresse vérifiée, TLS 1.3 seulement, cinq secondes, une
tentative, aucune redirection suivie ; un réveil par minute et par appareil,
soixante envois par minute et par hôte, huit en vol. Le journal
d'exploitation dit les points morts (`404`/`410`) et chaque refus des règles
d'adresse.

Les quatre vont ensemble. Sans `--identity-key`, la racine tourne seule et le
dit au démarrage. Chacune ouvre une connexion sortante vers l'autre et y **tire
sans fin** ce que l'autre a écrit ; une écriture faite chez l'une est chez
l'autre en moins d'une seconde, voie ouverte. `GET /v1/replication`, **sur la
voie machine**, rend l'état : `{"pair":"n-…","voie":"ouverte","compteur":…,
"ecrit":…,"applique":…}`, ou `{"voie":"seule","compteur":…,"ecrit":…}` sans
pair.

**Les trois nombres, et celui qui conclut.** `compteur` est l'horloge de cette
racine — elle se hisse aussi sur ce qu'elle REÇOIT, donc elle ne dit pas ce
qu'on a écrit ; `ecrit` est la dernière estampille qu'elle a écrite
ELLE-MÊME ; `applique` est jusqu'où elle a appliqué le pair. **Ce qui se
conclut : `applique` de l'une égale `ecrit` de l'autre ⇒ tout ce que l'autre a
écrit est ici** ; en dessous, il manque exactement la différence. Comparer
`applique` au `compteur` du pair ne dit rien : c'est l'erreur que ce dépôt a
faite une fois, sur le banc, le 2026-09-21. **Rien à reprendre au déploiement
de 0.17.0** — `ecrit` est une clé de plus dans une table qui existe déjà, le
format de l'entrepôt reste le troisième, et une base d'avant retrouve sa
valeur à l'ouverture, depuis son journal. La voie ne se coupe pas ; un banc
d'avant lit sans peine ce que le nouveau écrit, et un client qui ne lit pas
`ecrit` ne remarque rien.

### Mettre deux bancs en réplication

Les bancs — `nitrogen` et `argon` — tournent en 0.4.x avec des bases sans
estampille. La réplication les reprend sans rien perdre ; voici l'ordre exact.

1. **Frappez l'identité de chaque banc, EN TANT QUE `asl-server`.** La clé est
   lue par le service, qui tourne sous ce compte ; la frapper en `root` puis
   oublier de la lui donner à lire est la faute la plus facile.

   ```sh
   sudo -u asl-server asl-server --new-identity-key /etc/asl-server/identite.key
   # ou, si vous l'avez frappée en root :
   sudo chown root:asl-server /etc/asl-server/identite.key* && sudo chmod 0640 /etc/asl-server/identite.key
   ```

   Le binaire imprime la clé publique (`identite.key.pub`) et l'identifiant
   `n-…` qu'elle donne. **C'est ce `.pub` qu'on porte chez l'autre banc.**

2. **Échangez les `.pub`** : `nitrogen/identite.key.pub` va chez `argon` en
   `/etc/asl-server/pair.pub`, et réciproquement. Comparez les `n-…` imprimés à
   l'œil — deux bancs qui parlent de la même clé impriment le même.

3. **Posez `racine.crt`** — l'autorité de la cérémonie, celle que le client
   épingle déjà (`scripts/ca.sh racine`) — en `/etc/asl-server/racine.crt` sur
   les deux. C'est elle qui valide le certificat TLS d'en face (`--peer-ca`).

4. **Le drop-in**, sur chaque banc, avec l'adresse de l'AUTRE :

   ```sh
   systemctl edit asl-server
   # [Service]
   # Environment="ASL_REPLICATION=--identity-key /etc/asl-server/identite.key --peer argon.air-desktop.org:6630 --peer-key /etc/asl-server/pair.pub --peer-ca /etc/asl-server/racine.crt"
   ```

   Le modèle est expédié sous
   `/usr/share/doc/asl-server/replication.conf.exemple`. **L'affectation est
   citée, en entier** : `Environment=` découpe sa ligne sur les espaces avant
   d'y lire des affectations, et sans les guillemets `ASL_REPLICATION` ne vaut
   que `--identity-key` — l'annuaire refuse de démarrer, « attend une valeur ».
   Les guillemets sont pour systemd, pas pour la valeur : c'est ensuite le
   `$ASL_REPLICATION` de l'unité, lui non cité, qui la découpe en arguments,
   et les quatre `--peer…` arrivent séparés.

   **Entre deux bancs d'un même /64 chez un hébergeur, IPv6 peut ne pas
   passer** — la voie reste « coupée, la poignée de main n'a pas abouti à
   temps » alors que chacun se joint de l'extérieur. Le voisin est `FAILED`
   (`ip -6 neigh`) : l'hébergeur ne relaie pas la découverte de voisin entre
   ses hôtes. Une route `/128` vers l'autre banc par la passerelle du réseau
   règle le cas (`ip -6 route add <l'autre>/128 via <passerelle>`), à rendre
   persistante — un fragment netplan à part, sans toucher à celui de
   l'hébergeur. C'est un réglage de l'hôte, pas de l'annuaire.

5. **Redémarrez, l'un puis l'autre** — l'ordre est sans importance, chacun
   rappelle l'autre jusqu'à ce qu'il réponde. Au **premier** démarrage avec une
   clé, chaque banc **ré-estampille** ce qu'il avait écrit sans identité (sous
   `n-` seize zéros) sous son identité réelle, une fois, dans une transaction,
   et le journal le dit avec le nombre :

   ```
   asl-server : 3 214 enregistrements et opérations estampillés sans identité (n-AAAA…) sont passés sous n-… — une fois, dans une transaction.
   asl-server : voie vers argon… ouverte, prouvée dans les deux sens — état : ouverte
   asl-server : … amorcé par instantané — … cadres, … octets, … parts
   ```

6. **Vérifiez.** `asl` n'a pas encore de verbe pour l'état de la voie ; on
   interroge `GET /v1/replication` en brut, depuis une machine enrôlée (elle est
   **sur la voie machine**, pas publique — elle ne se rend pas à un inconnu). Un
   compte créé chez l'un doit se lire chez l'autre en une seconde, et
   `"applique"` doit rejoindre `"compteur"`. Le chantier `asl replication` est
   noté côté client.

**La reprise et les doublons de comptes.** Les deux bancs ont créé des comptes
CHACUN de leur côté (sur `nitrogen` et `argon` séparément), avec des
identifiants tirés indépendamment : ce sont donc, presque sûrement, des comptes
DIFFÉRENTS pour les mêmes personnes. La réplication ne les fusionne pas — un
identifiant à 128 bits ne collisionne pas —, elle les additionne : après la
première synchronisation, **chaque personne qui s'était inscrite sur les deux
bancs a deux comptes**, chacun avec ses machines. Ce qui est départagé, c'est
l'unicité : un **alias** réclamé des deux côtés va au compte dont la réclamation
est la plus ancienne (`docs/replication.md` §3.2), et le perdant garde sa
réclamation en file. Aucune donnée n'est perdue ; l'exploitant verra des
comptes en double, et c'est à prévoir, pas à corriger dans le code.

`asl-server --help` dit le reste. **La grammaire est en anglais** — options,
valeurs, texte de l'aide — parce que c'est la langue universelle des outils en
ligne de commande ; les messages d'exécution, eux, restent en français. Trois
choses qui surprendraient sinon :

- **Il refuse de démarrer en root** (C8). Il écoute au-dessus de 1024 et n'a
  besoin d'aucun privilège ; il refuse plutôt que d'en abandonner, parce qu'un
  abandon est un endroit où l'on se trompe.
- **Le port par défaut est 6630/udp**, libre au registre de l'IANA en TCP comme
  en UDP — le raisonnement complet est au-dessus de `asl_proto::PORT_PAR_DEFAUT`.
- **L'écoute est en double pile**, explicitement : `IPV6_V6ONLY` est mis à zéro
  plutôt que laissé au sysctl du noyau. « IPv6 d'abord, IPv4 en repli » est une
  décision de produit, et la faire dépendre de `net.ipv6.bindv6only` reviendrait
  à ne pas l'avoir prise.

Il s'éteint sur `SIGTERM` ou `SIGINT`, en deux temps (§5.2 de RFC 9114) : il dit
d'abord « n'ouvre plus rien » sans rien condamner de ce qui est en vol, puis
ferme.

## Installer un annuaire

La cible de déploiement est **Ubuntu**, et c'est elle qui décide du format.

```sh
scripts/paquet.sh                    # asl-server_<version>_amd64.deb
sudo dpkg -i asl-server_0.21.0_amd64.deb
```

**`asl-server` a vocation à tourner sur Linux, macOS et Windows.** Aujourd'hui :
Linux est la cible déployée, et **macOS se construit et tourne** — le binaire
écoute en double pile et le client `asl` le joint en IPv4 et en IPv6. Le système
ne se voit qu'à deux endroits, `crates/asl-server/src/entropie.rs` (le CSPRNG du
noyau : `getrandom` sur Linux, `getentropy` sur les BSD) et
`crates/asl-server/src/socket.rs` (les drapeaux de la socket, `sin6_len`), sous
`cfg(target_os)`. **C'est le job `macOS` de la CI, et non ces `cfg`, qui fait
que cela reste vrai** — il construit le workspace et lance les essais du
binaire hors harnais QUIC, dont `ams-quic-client` ne finit pas ses flux sur
macOS (le vrai client, lui, passe). **Windows reste à faire** : l'entropie
(`BCryptGenRandom`) et la socket y sont à écrire, et rien ne l'atteste encore.
Les étages 1 et 2 ne touchent ni fichier, ni socket, ni horloge : ils sont
portables par construction.

**Deux choses apprises en faisant tourner l'annuaire sur un Mac**, qui ne
sont pas des défauts du binaire mais que l'exploitant doit savoir — chacune a
coûté une heure à comprendre, et la seconde vaut pour tout système :

- **Le pare-feu de macOS ne laisse entrer l'UDP que vers un binaire SIGNÉ.**
  Un `asl-server` sorti de `cargo build` n'est pas signé ; le pare-feu
  l'inscrit bien dans sa liste (« Allow incoming connections ») et jette
  quand même tout ce qui arrive du réseau — la boucle locale passe, ce qui
  rend la panne trompeuse. Une signature ad hoc suffit :
  `codesign -s - target/release/asl-server`, puis autoriser le binaire
  (`socketfilterfw --add`, `--unblockapp`), **et le relancer** : le pare-feu
  juge le processus, pas le fichier.
- **Un hôte à deux adresses sur le même réseau répond par celle de sa route
  par défaut.** L'annuaire se lie à toutes les adresses (`[::]`), et le noyau
  choisit la source de chaque réponse d'après la route vers le client — pas
  d'après l'adresse à laquelle le client a écrit. Un Mac en Wi-Fi ET en
  Ethernet sur le même LAN, joint par son adresse Wi-Fi, répond par
  l'Ethernet ; le client QUIC voit une réponse venue d'une autre adresse et
  la jette, **à raison** — c'est ce que la validation de chemin existe pour
  faire. Rien ne se journalise, ni d'un côté ni de l'autre. Joignez un tel
  annuaire par l'adresse de sa route par défaut, ou liez-le à une adresse
  précise. `asl diagnose` sur la boucle locale ne révèle pas ce cas.

**Le paquet n'active ni ne démarre le service**, et il lui manque exprès deux
choses qu'un paquet ne peut pas décider :

1. **La posture d'attestation**, qui n'a pas de défaut (`protocole.md` §2.1).
   `required` refuse TOUS les enrôlements tant qu'aucune plate-forme n'est
   configurée ; `optional` laisse n'importe qui créer un compte. Elle se pose par
   `systemctl edit asl-server`, et le modèle est expédié sous
   `/usr/share/doc/asl-server/attestation.conf.exemple`.
2. **Le certificat**, émis pour le nom sous lequel cet annuaire répond, à poser
   en `/etc/asl-server/certificat.pem` et `/etc/asl-server/cle.pem`.

Et une troisième, **facultative** : les racines d'attestation Android. Le paquet
expédie celle de Google sous `/usr/share/doc/asl-server/racines-android/google.pem`
et **n'en épingle aucune** (C19) — copiez-la sous `/etc/asl-server/`, vérifiez
son empreinte (en tête du fichier), et posez les trois réglages dans un drop-in
sur le modèle de `/usr/share/doc/asl-server/android.conf.exemple` :

```sh
systemctl edit asl-server
# [Service]
# Environment="ASL_ANDROID=--android-roots /etc/asl-server/racines-android/google.pem --android-app org.airdesktop.servicelocator --android-signer <SHA-256 de la signature de la build>"
```

L'affectation est **citée en entier**, comme celle de la réplication, et pour
la même raison. Vide, `$ASL_ANDROID` laisse la racine refuser les attestations
Android en le disant au journal.

**La posture `invitation`** (`docs/protocole.md` §2.2, **servie depuis
0.14.0**). Pour une racine qui ne veut aucun fabricant dans sa boucle :
personne n'ouvre de compte sans un code que l'exploitant a émis.

```sh
systemctl edit asl-server
# [Service]
# Environment="ASL_ATTESTATION=invitation --operator-key /etc/asl-server/exploitant.pub"
```

**`--attestation` ne se répète pas ici**, et c'est le piège de ce drop-in :
l'unité écrit déjà `--attestation $ASL_ATTESTATION` (`paquet/asl-server.service`),
donc la variable porte **la valeur, puis les réglages qui la suivent** — pas le
drapeau. L'écrire deux fois donnerait `--attestation --attestation invitation`,
et le service refuserait de démarrer en le disant. L'affectation est **citée en
entier**, comme les autres ; `$ASL_ATTESTATION` n'a pas d'accolades à dessein,
si bien que systemd découpe sa valeur en mots et que `--operator-key` et son
chemin arrivent comme deux arguments.

- **`--operator-key <fichier>`**, la clé publique Ed25519 dont la signature
  ouvre `POST /v1/invitations`. **Obligatoire sous cette posture** : sans elle
  le service refuse de démarrer, parce qu'une racine qui exige une invitation
  sans pouvoir en émettre est une racine où personne n'entre. Sous les autres
  postures, la ressource n'existe pas et répond `404`.
- **`--invitation-ttl <durée>`**, vingt-quatre heures par défaut, une semaine
  au plus. Un code d'invitation s'envoie à quelqu'un qui n'est pas devant
  vous ; les dix minutes d'un code d'enrôlement de machine en feraient un
  rendez-vous.
- La partie privée de la clé d'exploitation **ne se pose pas sur le banc** :
  elle vit là où l'exploitant émet ses invitations. Le banc n'en connaît que
  le `.pub`, comme pour `--peer-key`.
- **À poser sur les DEUX bancs**, la même : un code émis chez l'un se présente
  chez l'autre (l'alias tire au hasard), et les invitations se répliquent.
- **Rien à reprendre au déploiement de 0.14.0.** La table des invitations
  s'ajoute vide à l'ouverture, aucun enregistrement existant ne change de
  taille ni de sens, et le format de l'entrepôt reste le troisième : la voie
  ne se coupe pas, le journal d'opérations n'est pas vidé. Déployer les deux
  bancs à la suite suffit. **N'en passez aucun en `invitation` tant que les
  deux ne servent pas 0.14.0** : un banc d'avant ne saurait pas lire les
  opérations `invitation` (18) et `invitation-consommee` (19), et fermerait
  la voie en le disant — il ne saute rien.
**Les notifications** (`docs/protocole.md` §2.2, **servies depuis 0.19.0**),
facultatives, sur le modèle de `/usr/share/doc/asl-server/poussee.conf.exemple` :

```sh
systemctl edit asl-server
# [Service]
# Environment="ASL_POUSSEE=--push-roots /etc/ssl/certs/ca-certificates.crt"
```

- **DÉPLOYEZ LES DEUX RACINES EN 0.19.0 AVANT QU'UN APPAREIL DÉPOSE UN
  POINT.** Le point se réplique par l'opération `point-de-poussee` (genre 20),
  et une racine d'avant ne la connaît pas : elle fermerait la voie en le
  disant, et ne sauterait rien. L'ordre sûr est celui des invitations —
  les deux bancs à la suite, puis seulement l'app Android qui dépose.
- **Rien à reprendre au déploiement.** Les points ont leur propre table,
  `points-de-poussee`, qui naît vide à l'ouverture ; aucun enregistrement
  existant ne change de taille ni de sens, le format de l'entrepôt reste le
  troisième, la voie ne se coupe pas et le journal d'opérations n'est pas
  vidé.
- **`apns` et `fcm` sont refusés** (`400`) à `PUT /v1/appareils/{a}/poussee` :
  aucune app ne les déposait. Les jetons déjà rangés restent lisibles et ne
  servent à rien.
- **Le pare-feu doit laisser sortir TCP vers le port 443** — la table
  expédiée (`nftables-asl.conf`) ne filtre pas la sortie.
- Le point est **répliqué** pour que la racine où l'autorisation s'ÉCRIT le
  trouve ; c'est elle, et elle seule, qui envoie (décision 9). Ce qu'une
  racine apprend en envoyant — un point mort, un hôte trop sollicité — reste
  en mémoire, chez elle.

### Frapper la clé d'exploitation, et émettre (depuis 0.15.0)

Les deux gestes sont dans le même binaire, et **aucun ne tourne sur un banc** :
`asl-server` est un exécutable autonome, qu'on copie sur la machine de
l'exploitant. C'est là que vit la moitié privée de sa clé, et nulle part
ailleurs.

```sh
# Une fois, chez l'exploitant — jamais sur une racine.
asl-server --new-operator-key ~/.config/asl/exploitant.key
# → la privée en 0600, la publique à côté ; portez le `.pub` sur les DEUX bancs.

# À chaque arrivant, contre un annuaire QUI TOURNE.
asl-server --invite \
  --directory asl-root.air-desktop.org:6630 \
  --ca racine.crt \
  --operator-secret ~/.config/asl/exploitant.key
# → 4K9M2-P7R1T
```

- **`--invite` n'arrête rien et n'ouvre aucun entrepôt** — c'est ce qui le
  sépare de `--forget`. Il ouvre une connexion, tire un défi, signe
  `genre ‖ défi ‖ liaison`, et poste soixante-cinq octets. Émettre pendant que
  l'annuaire sert est le geste ordinaire de cette posture.
- **Le code sort SEUL sur la sortie standard**, son échéance sur la sortie
  d'erreur : `asl-server --invite … | pbcopy` ne copie que le code. Il vaut
  **un** compte, vit ce que dit `--invitation-ttl`, et **ne sera pas
  réaffiché** — l'annuaire n'en garde que l'empreinte (C14). Il ne s'écrit
  dans aucun fichier et n'apparaît dans aucun journal.
- Les trois refus se distinguent, parce qu'ils appellent trois gestes
  différents : « cette racine n'émet pas d'invitations » (`404` — mauvaise
  posture, ou pas de `--operator-key`), « la racine a refusé la signature »
  (`401` — ce n'est pas la bonne clé privée), « trop d'échecs depuis cette
  adresse » (`429` — attendez une minute).
- `--ca` est l'autorité qui valide le certificat TLS de la racine : le
  `racine.crt` de la cérémonie (`scripts/ca.sh`), celui-là même qu'un client
  épingle.

- **L'usage unique tient par racine, et à la seconde près entre les deux.**
  Un même code présenté des deux côtés de la fenêtre de réplication ouvre
  DEUX comptes, et l'annuaire ne les départage pas : il les laisse vivre et
  dit au journal que le code a servi deux fois, avec les deux `u-…`. C'est
  écrit dans la spécification (décision 26) — effacer automatiquement l'un
  des deux serait une arme. Tranchez hors ligne si vous le voulez
  (`--forget`).
- **La limite de débit est en mémoire**, cinq échecs par minute et par
  adresse, et **ne se réplique pas** : chaque banc compte les siens. Elle ne
  survit pas à un redémarrage, et c'est voulu — ce n'est pas un état du
  produit, c'est une garde du moment.

**Les comptes qui s'effacent** (`docs/modele.md` §2.1, depuis 0.11.0). Un
compte se ferme depuis un appareil, de la même main qui l'a ouvert
(`DELETE /v1/compte`) ; l'annuaire, lui, n'efface de lui-même que **les
orphelins** — un compte dont TOUS les appareils sont révoqués, trente jours
après la révocation du dernier, cause `orphelin`, une ligne au journal. Jamais
sur le silence : un téléphone dans un tiroir est un appareil vivant (C6).

- **`--orphans <jours>`**, trente par défaut, `0` pour jamais. **L'unité ne
  change pas** : le défaut suffit, et le paquet ne le pose pas. Si vous le
  réglez, **posez la même valeur sur les deux bancs** — la règle de conflit
  tranche pour l'effacement, donc c'est le délai le plus court qui gagnerait.
  Le passage a lieu au démarrage, puis toutes les heures.
- **`asl-server --forget <u-…> --store /var/lib/asl-server/annuaire.redb
  --identity-key /etc/asl-server/identite.key`** efface UN compte hors ligne,
  cause `exploitant` : c'est l'exception pour une clé qu'on SAIT perdue — un
  simulateur remis à zéro, une app qui a écrit sa clé au mauvais endroit —,
  que la règle des orphelins n'attrape pas. Ce n'est pas un outil de
  modération. Il s'exécute **service arrêté** (`systemctl stop asl-server` ;
  il refuse en le disant si le daemon tient l'entrepôt) et **en tant que
  `asl-server`** (`sudo -u asl-server …` : il refuse root, et le fichier est à
  ce compte). Il écrit l'opération au journal d'opérations : **sur UN banc
  suffit**, la réplication porte l'autre. Sans `--identity-key`, l'opération
  est estampillée sous seize zéros et le daemon la fera passer sous son
  identité au démarrage suivant — donnez la clé, c'est plus net.

**Un appareil qui rejoint s'atteste lui-même** (`docs/protocole.md` §2.2,
depuis 0.13.0). Le premier appareil d'un compte entre attesté à sa création ;
le second n'avait aucun moyen de l'être — `POST /v1/appareils` ne porte que la
clé, et l'ancien appareil ne peut pas apporter une chaîne liée au canal du
nouveau. Le nouvel appareil tire donc un défi sur sa connexion nue AVANT de
générer sa clé, la montre à l'ancien (qui l'apporte), puis prouve sa clé ET
présente sa chaîne d'un même défi par **`POST /v1/attestation`**, sur la
connexion tenue depuis le début. Sous `--attestation optional`, l'appareil
apporté entre `aucune` et sa chaîne le fait passer à `android`/`apple` (refusée,
`204` quand même) ; sous `required`, il entre **`attendue`** — visible,
révocable, `401` à toute preuve nue — jusqu'à ce que sa chaîne tienne (sinon
`403`). **Rien à faire au déploiement** : `attendue` est une cinquième valeur
d'attestation, un octet dans un champ qui existait déjà — un entrepôt d'avant
se relit tel quel, et seule une version ANCIENNE relisant une base neuve
buterait sur l'octet, comme pour tout retour arrière. `attendue` ne s'expire
pas.

**La reprise au format des dates** (0.11.0) : à sa première ouverture par ce
binaire, un entrepôt de 0.5.0 à 0.10.1 est repris dans une transaction — les
appareils déjà révoqués reçoivent la date de la reprise pour « révoqué le »,
c'est de là que la règle des orphelins comptera pour eux —, et **le journal
d'opérations repart vide** : l'autre banc s'amorce par instantané, comme à la
reprise de 0.5.0. Le journal le dit. Le temps que les deux bancs soient à la
même version, la voie est coupée — une opération du nouveau format ne se lit
pas avec l'ancien, et c'est dit plutôt que sauté ; elle se rouvre d'elle-même
au second déploiement.

Tant que la première manque, le service échoue en disant `--attestation attend
une valeur` — un message qui nomme exactement ce qu'il reste à décider. Un paquet
qui démarrerait un service voué à échouer apprendrait à l'exploitant que les
échecs de ce service sont normaux.

**Le pare-feu est expédié comme un EXEMPLE**, sous
`/usr/share/doc/asl-server/nftables-asl.conf`, et le paquet ne le charge pas : il
déciderait de ce qui entre sur une machine qu'il ne connaît pas, et la première
chose qu'il fermerait est la porte par laquelle on vient le corriger. La table
porte sa propre marche à suivre, **filet de sécurité compris** — un retour en
arrière armé avant le chargement, qu'on n'annule qu'une fois une NOUVELLE session
`ssh` passée. L'ancienne survit par `ct state established` et ne prouve rien.

**`dpkg --purge` n'efface ni l'annuaire ni la clé.** `/var/lib/asl-server` porte
les comptes, les machines et les autorisations que des humains se sont
accordées ; `/etc/asl-server` porte un secret. Le `postrm` dit ce qu'il laisse en
place et comment l'effacer soi-même, plutôt que de le faire à votre place.

`scripts/check-paquet.sh` est la barrière qui juge tout cela — y compris que le
paquet ne choisisse pas la posture, et que le `purge` ne dépossède personne.

## L'autorité de certification

Ce n'est **pas** une barrière : on la lance à la main, et le fichier ne s'appelle
donc pas `check-…`.

```sh
scripts/ca.sh racine                              # la racine air-desktop-project
scripts/ca.sh serveur banc localhost ::1          # un certificat de serveur
scripts/ca.sh montrer                             # ce qui existe
```

Elle écrit dans `local/`, **ignoré par git** : une clé privée poussée sur un
dépôt public ne se retire jamais vraiment d'un historique. Le pourquoi de
l'autorité, de l'algorithme et des SAN d'adresse est en
[`docs/transport.md` §8](docs/transport.md).

## Licence

MPL-2.0 — voir [LICENSE](LICENSE).
