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

## Les trois dépôts

| Dépôt | Ce qu'il porte |
|---|---|
| `air-service-locator-server` | Ce dépôt — le service, en Rust. **Et les spécifications.** |
| `air-service-locator-client` | La bibliothèque que les daemons lient, ses liaisons et l'utilitaire `asl`. |
| `air-service-locator-ios` | L'application iOS (Swift). |
| `air-service-locator-android` | L'application Android (Kotlin). |

**Le modèle et le protocole sont spécifiés ICI**, dans `docs/`, et les deux
dépôts mobiles y renvoient par lien. Trois copies vieilliraient, et deux d'entre
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

Quatre aujourd'hui, et le fait qu'elles soient quatre et non dix est expliqué en
tête de [`scripts/check-tout.sh`](scripts/check-tout.sh) : les six autres
mesureraient du vide.

```sh
scripts/check-tout.sh     # compile, clippy, essais, format — dans cet ordre
scripts/check-dco.sh      # après avoir committé : DCO et paternité
```

L'ordre n'est pas arbitraire, et le formatage est en dernier : une faute de forme
ne doit pas cacher une faute de fond.

## Licence

MPL-2.0 — voir [LICENSE](LICENSE).
