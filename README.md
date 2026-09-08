# air-service-locator-server

Le service d'**air-service-locator** : un annuaire de daemons réseau, écrit en
Rust.

> ## État : une arborescence, et rien d'autre
>
> **Ce dépôt ne sert rien.** Il compile, il est formaté, il est linté, et il
> porte deux gates de CI — mais ses neuf crates sont des coquilles qui ne
> contiennent que leur intention.
>
> C'est délibéré. L'arborescence a été posée AVANT les spécifications, et
> `docs/` consigne ce qui n'est pas décidé plutôt que d'inventer ce qui l'aurait
> été. Le binaire `asl-server` le dit lui-même quand on le lance, plutôt que de
> démarrer une boucle vide qui aurait l'air de servir.

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
| `air-service-locator-server` | Ce dépôt — le service, en Rust. |
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
| Tiers | `asl-client` | Dépendre de l'étage 2 ou 3 — un daemon qui s'annonce n'embarque pas la base de données de l'annuaire. |

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
