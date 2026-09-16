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
`GET /v1/version` la rend à qui interroge l'annuaire.

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

Les quatre vont ensemble. Sans `--identity-key`, la racine tourne seule et le
dit au démarrage. Chacune ouvre une connexion sortante vers l'autre et y **tire
sans fin** ce que l'autre a écrit ; une écriture faite chez l'une est chez
l'autre en moins d'une seconde, voie ouverte. `GET /v1/replication`, **sur la
voie machine**, rend l'état : `{"pair":"n-…","voie":"ouverte","compteur":…,
"applique":…}`, ou `{"voie":"seule","compteur":…}` sans pair.

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
sudo dpkg -i asl-server_0.8.2_amd64.deb
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
   `required` refuse TOUS les enrôlements tant que la vérification n'est pas
   écrite ; `optional` laisse n'importe qui créer un compte. Elle se pose par
   `systemctl edit asl-server`, et le modèle est expédié sous
   `/usr/share/doc/asl-server/attestation.conf.exemple`.
2. **Le certificat**, émis pour le nom sous lequel cet annuaire répond, à poser
   en `/etc/asl-server/certificat.pem` et `/etc/asl-server/cle.pem`.

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
