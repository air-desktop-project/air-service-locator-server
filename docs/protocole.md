# Protocole

Trois conversations, trois publics, trois rythmes. Elles partagent un transport
en v1 — HTTPS — et ce document dit pourquoi, et à quelle condition cela cessera.

Le vocabulaire (candidat, bail, `annoncé` / `joignable` / `expiré`) est défini
dans [`modele.md`](modele.md). Ce document ne le redéfinit pas.

---

## 0. Le transport

**HTTP/3 sur QUIC, pour les trois voies. IPv6 d'abord, IPv4 en repli.**

Ce n'est pas un compromis entre des options : c'est ce que le produit exige, et
ce que nous pouvons nous permettre parce que **nous tenons les deux bouts** — la
bibliothèque cliente est de nous, le serveur aussi.

### Ce que QUIC donne ici, et qu'aucun autre transport ne donne

| | Pourquoi ça compte pour CE produit |
|---|---|
| **Connexion tenue, à coût faible** | Le daemon garde une connexion ouverte plutôt que de réannoncer périodiquement. C'est le bail (`modele.md` §4.1). |
| **Le keepalive maintient le mapping NAT** | Sur IPv4 dégradé, c'est le même mécanisme qui tient la connexion et la porte. Rien de séparé à écrire. |
| **L'annuaire peut PARLER au daemon** | Les deux extrémités sont en ligne au même instant. C'est ce qui laisse ouverte la route du rendez-vous pour un perçage de NAT (`modele.md` §6.3), qu'un protocole requête-réponse fermerait d'avance. |
| **Migration de connexion** | Une machine qui change d'adresse — bascule 4G, renumérotation IPv6 — ne perd pas son bail. Sur un transport ordinaire, elle apparaîtrait partie. |
| **Reprise à zéro aller-retour** | Une reconnexion après coupure coûte presque rien, et la bascule d'un annuaire à l'autre s'en trouve rapide (`annuaires.md` §3). |

### Ce que cela coûte, et il faut le regarder en face

**QUIC est la dépendance la plus lourde qu'on puisse imposer à un daemon
tiers.** C'était l'argument contre, et il ne disparaît pas parce qu'on a choisi
autrement — il se paie autrement : par la qualité de la bibliothèque cliente.

Deux choses le rendent tenable :

1. **La pile QUIC existe déjà, et on la RÉUTILISE** (contrainte C15).
   `ams-quic`, `ams-quic-crypto`, `ams-quic-tls`, `ams-proto-quic`,
   `ams-proto-h3`, `ams-h3`, `ams-quic-client` — écrites pour
   `air-mail-server`, sur tokio, **sans une ligne de C**, et déjà éprouvées par
   un autre produit.

   **Elles sont réutilisables parce qu'elles ont été écrites comme des CODECS**
   (C1) : des octets vers des messages, et retour, sans posséder de socket. Une
   pile qui aurait mêlé sa boucle à sa grammaire ne se transplanterait pas.

   Elles ont vocation à **migrer dans `air`**. La dépendance pointe aujourd'hui
   vers `air-mail-server` parce que c'est là qu'elles vivent ; ce jour-là, c'est
   la source qui changera, pas le code.
2. **Les liaisons sont un livrable, pas une arrière-pensée.** Python, Ruby, C++,
   Kotlin, Swift. Un développeur qui écrit un daemon ne doit jamais avoir à
   savoir que sa découverte de service passe par QUIC.

### IPv6 d'abord

L'annuaire écoute sur les deux. Le client tente **IPv6 en premier**, et ne
retombe sur IPv4 qu'après échec.

**C'est plus qu'un ordre de préférence** (`modele.md` §1) : une machine qui a une
IPv6 publique n'est derrière aucun NAT, et tient l'exigence de joignabilité sans
rien faire. IPv4 est le chemin où les problèmes commencent, et le nommer
« repli » plutôt que « alternative » garde cette asymétrie visible dans le code.

### Le cadrage

**JSON** au-dessus de HTTP/3 en v1. Il se lit, se débogue, et ne coûte rien à
l'échelle où ce produit vit. Un cadrage binaire est nommé et repoussé (§4.3) —
et **`asl-proto` est la seule crate qui verrait la différence**, ce qui est
exactement pourquoi elle est séparée.

---

## 1. La voie du daemon — `asl-proto`, `asl-client`

**Le daemon ouvre une connexion QUIC et la TIENT.** Tout ce qui suit passe
dedans.

### 1.1 S'annoncer

À l'ouverture de la connexion, authentifiée par le secret de la machine — qui
doit porter la capacité `annonce` (`modele.md` §2.3) :

```jsonc
{
  "machine": "m-7q2h8k3m9x4v6b1n5r0t2w8y3z",
  "service": "depot-de-messages",
  "points": [
    { "protocole": "tcp", "port": 49152 },
    { "protocole": "udp", "port": 49152 }
  ],
  "adresses_locales": ["2001:db8::1c2d", "192.168.1.20"]
}
```

La réponse :

```jsonc
{
  "service": "s-4k9m2p7r1t6v3x8z5b0d2f4h6j",
  "keepalive_secondes": 15,
  "inactivite_secondes": 45,
  "vu_depuis": { "adresse": "2001:db8::1c2d", "port": 51840, "famille": "ipv6" },
  "derriere_nat": false,
  "joignabilite": [
    { "protocole": "tcp", "port": 49152, "verdict": "joignable",
      "candidat": "[2001:db8::1c2d]:49152", "a": "2026-09-08T13:02:11Z" },
    { "protocole": "udp", "port": 49152, "verdict": "non_sonde",
      "raison": "l'UDP ne se sonde pas" }
  ]
}
```

**`vu_depuis`, `derriere_nat` et `joignabilite` sont la moitié utile de cette
réponse**, et non un ornement de diagnostic.

- `vu_depuis` dit au daemon **sous quelle adresse l'annuaire l'a vu**. Aucun
  autre moyen ne le lui apprend.
- `derriere_nat` est le verdict que l'annuaire est **seul** à pouvoir rendre : il
  compare ce que le daemon annonce avec ce qu'il observe. En IPv6 il vaut
  presque toujours `false`, et c'est le signe que tout va bien.
- `joignabilite` lui dit **si quelqu'un peut réellement l'atteindre**, à la
  seconde où il démarre — et non le jour où un utilisateur s'en plaint.

**Les valeurs de temps viennent du serveur** et ne sont pas figées dans le
client : le bon delta de keepalive se mesure et n'est pas encore mesuré
(`modele.md` §4.1). Le figer côté client exigerait de mettre à jour tous les
daemons installés chez des tiers — ce qui ne se produira jamais.

### 1.2 Tenir — le keepalive

**La connexion EST le bail.** Il n'y a pas de verbe « rafraîchir » : le
keepalive QUIC suffit, et il n'y a rien à écrire au-dessus.

Un daemon dont un point d'écoute change réannonce dans la même connexion. Une
réannonce du même nom remplace la précédente (`modele.md` §2.4), et **déclenche
une nouvelle sonde** puisque les candidats ont changé.

### 1.3 Partir

**Fermer la connexion suffit, et c'est instantané.** L'extinction QUIC en deux
temps distingue un arrêt propre d'une coupure : l'annuaire rend `parti
(volontaire)` dans un cas, `parti (inactivité)` dans l'autre — deux choses que
celui qui regarde ne traitera pas pareil.

C'est le gain le plus net du transport tenu. Avec des annonces périodiques, un
daemon arrêté proprement restait faussement présent jusqu'à l'expiration de son
bail.

### 1.4 Reprise — ce que fait `asl-client` quand l'annuaire ne répond pas

**L'annuaire injoignable NE DOIT PAS empêcher un daemon de démarrer.** Un
service de découverte en panne rendrait sinon indisponibles tous les daemons qui
en dépendent — la faute exacte que ce genre de composant existe pour ne pas
commettre.

`asl-client` :

1. **rend la main immédiatement** ; la connexion s'établit en arrière-plan ;
2. **essaie les annuaires dans l'ordre**, IPv6 avant IPv4, et bascule sur le
   second dès que le premier ne répond pas ;
3. **réessaie avec un recul exponentiel** — 1 s, 2 s, 4 s… plafonné, **avec un
   bruit aléatoire de ±20 %** ;
4. **n'abandonne jamais.** Un daemon qui tourne depuis un mois doit se
   réannoncer tout seul quand l'annuaire revient.

**Le bruit aléatoire n'est pas du raffinement.** Sans lui, mille daemons dont
l'annuaire vient de tomber se reconnectent à la même seconde et le remettent à
terre à l'instant où il se relève. Il coûte une ligne.

**C'est aussi le mécanisme de bascule entre les deux racines**, et il n'y en a
pas d'autre : l'état vivant n'est délibérément pas répliqué, parce qu'il se
reconstruit ici, tout seul, en un keepalive (`annuaires.md` §3).

---

## 2. La voie des applications mobiles — `asl-api`

### 2.1 Enrôler un appareil

Il n'y a **pas de mot de passe** dans ce produit. Un compte est un jeu
d'appareils enrôlés, et rien d'autre.

1. L'application génère une paire de clés **dans le matériel sécurisé** —
   Secure Enclave, ou Keystore adossé au TEE — avec un contrôle d'accès qui
   **exige la biométrie pour s'en servir** (`kSecAccessControlBiometryCurrentSet`,
   `setUserAuthenticationRequired(true)`).
2. Elle envoie la clé publique et, quand la plate-forme en fournit une,
   l'**attestation** de la plate-forme (App Attest, Play Integrity) qui certifie
   que cette clé vit bien dans du matériel.
3. Toute requête ultérieure est **signée par cette clé**.

**Ce que le serveur vérifie est la signature, pas une identité.** Il ne reçoit
jamais d'empreinte ni de gabarit : la biométrie est une condition d'usage de la
clé, appliquée par le matériel. Un client modifié ne peut pas contourner cela —
il peut mentir sur ce qu'il affiche, jamais produire la signature.

**Ce qui reste ouvert :** que faire quand l'attestation manque ou échoue —
appareil rooté, émulateur, plate-forme sans attestation. Refuser ferme des
appareils légitimes ; accepter vide la garantie de sa substance. La v1
**refuse**, et journalise, parce qu'un refus se relâche plus tard alors qu'une
acceptation ne se resserre jamais sans casser des comptes existants.

### 2.2 Le reste

| Verbe | Ce qu'il fait |
|---|---|
| `POST /v1/comptes` | Crée le compte et enrôle le premier appareil. Rend `u-…`. |
| `POST /v1/appareils` | Enrôle un appareil de plus. **Signé par un appareil déjà enrôlé.** |
| `PUT /v1/appareils/{a}/poussee` | Dépose ou renouvelle le jeton APNs / FCM. |
| `DELETE /v1/appareils/{a}` | Révoque. Un appareil ne peut pas se révoquer lui-même — sinon un téléphone volé et déverrouillé révoque les autres et confisque le compte. |
| `POST /v1/machines` | Déclare une machine, avec ses **capacités** (`annonce`, `lecture`). **Rend un code d'enrôlement** — court, à usage unique, valable quelques minutes. |
| `PATCH /v1/machines/{m}` | Change le nom ou les capacités. |
| `POST /v1/machines/{m}/enrolement` | Émet un nouveau code, pour ré-enrôler une machine dont la clé a été révoquée ou perdue. |
| `DELETE /v1/machines/{m}/cle` | Révoque la clé. Effet immédiat : connexions fermées, baux tombés. |
| `PUT /v1/alias` | Enregistre ou change l'alias public. **La seule donnée que l'utilisateur nous confie.** |
| `DELETE /v1/alias` | Le retire. |
| `GET /v1/alias/{alias}` | Rend l'identifiant, **et rien d'autre**. Public — c'est l'emploi de l'alias, et son coût (`modele.md` §2.1). |
| `GET /v1/machines/{m}/services` | Les services, leurs candidats, leur état et la date de la dernière sonde. |
| `GET /v1/utilisateurs/{u}` | **Confirme qu'un identifiant existe**, et rien d'autre : ni nom, ni machines, ni services. Sert à ce qu'une faute de frappe ne produise pas une autorisation muette. |
| `POST /v1/autorisations` | Accorde. Bénéficiaire `u-…`, portée, étiquette. Déclenche la notification. |
| `GET /v1/autorisations` | Les deux sens : ce que j'ai accordé, ce qu'on m'a accordé. |
| `DELETE /v1/autorisations/{g}` | Révoque. Effet immédiat. |

**`GET /v1/utilisateurs/{u}` ne rend qu'un booléen, et c'est délibéré.** Il
confirme l'existence à qui détient déjà l'identifiant — 128 bits, donné par son
porteur. Il ne rend jamais de nom : il n'y a rien, dans ce produit, qui permette
de retrouver un compte autrement que par son identifiant.

---

## 3. La voie de la résolution — la machine qui cherche un port

Le troisième public : le programme qui veut JOINDRE un daemon. Il tourne sur une
machine de B, et **il ne s'agit plus d'un inconnu** — c'est une machine déclarée,
portant la capacité `lecture`, et agissant au nom d'un compte.

```
GET /v1/ou/{machine}/{service}
        (dans une connexion QUIC authentifiée par la CLÉ de la machine
         qui demande, laquelle doit porter la capacité `lecture`)
```

**Rien ne s'interroge anonymement, et rien ne s'interroge sur présentation d'un
jeton.** La signature authentifie la machine, la machine désigne son
propriétaire, et l'annuaire ne rend que ce que ce propriétaire a le droit de
voir : ses propres services, et ceux qu'une autorisation lui a accordés
(`modele.md` §2.5).

**L'authentification est portée par la CONNEXION, pas par la requête**, et c'est
un effet direct du transport tenu : la clé est prouvée une fois à
l'établissement, puis toutes les requêtes de cette connexion en héritent. Il n'y
a pas de jeton à joindre, donc pas de jeton à intercepter, à rejouer, ni à
expirer.

```jsonc
{
  "service": "s-4k9m2p7r1t6v3x8z5b0d2f4h6j",
  "machine": { "identifiant": "m-7q2h…", "nom": "grenier" },
  "etat": "annonce",
  "annonce_a": "2026-09-08T13:02:11Z",
  "candidats": [
    { "protocole": "tcp", "adresse": "203.0.113.4", "port": 49152,
      "origine": "reflexif", "joignable_a": "2026-09-08T13:02:11Z" },
    { "protocole": "tcp", "adresse": "192.168.1.20", "port": 49152,
      "origine": "annonce" }
  ]
}
```

### Résoudre les cinq instances d'un coup

Le scénario du produit n'est pas « un service » mais « le même daemon sur cinq
machines ». Demander une machine à la fois obligerait B à connaître les cinq
identifiants, et à les tenir à jour quand A en ajoute une sixième.

```
GET /v1/ou?service=depot-de-messages
```

Rend **toutes** les instances portant ce nom que le demandeur a le droit de
voir, chacune avec sa machine et ses candidats. C'est la forme que le client
emploiera en pratique ; la forme par machine reste pour désigner une instance
précise.

### Les candidats sont ordonnés

**Le client les essaie dans l'ordre.** Ce n'est pas à lui de deviner lequel
vaut : l'annuaire sait lequel il a sondé avec succès, et le met en tête.

**La joignabilité depuis l'Internet est l'exigence du produit** (`modele.md`
§1) — mais l'annuaire la MESURE, il ne la garantit pas. `joignable_a` dit
« depuis l'annuaire, à cette date » ; il ne dit pas « depuis vous, maintenant ».
Un client qui traiterait l'absence de réponse comme une anomalie de l'annuaire
se tromperait de coupable.

### Ce qui rend l'annuaire non énumérable

- **Aucune lecture anonyme.** C'est la première barrière, et la seule qui compte
  vraiment : il n'existe aucune requête de résolution qui rende quoi que ce soit
  hors d'une connexion authentifiée par une clé de machine.
- Un identifiant porte **128 bits** : il ne se devine pas.
- **L'alias est la seule surface énumérable**, et il ne rend qu'un identifiant —
  jamais une machine, jamais un service, jamais un état (`modele.md` §2.1).
- **Un service hors de la portée du demandeur et un service inexistant rendent
  la même réponse, après le même délai** (contrainte C9). Sans cela, l'écart de
  temps dit à B que la machine d'A existe alors qu'il n'y a pas droit — et c'est
  tout ce qu'il cherchait.

### Ce qu'une machine `lecture` compromise donne à celui qui la prend

Tout ce que son propriétaire a le droit de voir : ses services, et **ceux que
ses amis lui ont accordés** — donc des adresses IP de machines qui ne lui
appartiennent pas.

C'est la raison pour laquelle les capacités ne sont pas cumulées par défaut
(`modele.md` §2.3), et pourquoi le remplacement du secret d'une machine est une
opération visible dans l'application plutôt qu'enfouie dans un menu.

---

## 4. Ce qui est nommé et repoussé

### 4.1 La sonde réflexive UDP

Le problème reste entier : **le candidat réflexif de la connexion QUIC est celui
de la socket QUIC, pas celui du service.** Un daemon qui sert en UDP sur 49152 a
une socket QUIC distincte, avec son propre mapping NAT — savoir sous quelle
adresse celle-là est vue n'apprend rien sur l'autre.

**La connexion tenue ouvre pourtant une solution simple**, qu'un protocole
requête-réponse n'aurait pas permise : l'annuaire **demande au daemon**, dans la
connexion, d'émettre un datagramme *depuis la socket de service* vers une
adresse qu'il lui donne. Il observe alors le mapping de CETTE socket, et rend au
daemon le candidat réflexif de son service.

C'est le mécanisme de STUN, obtenu presque gratuitement parce que le canal de
commande existe déjà.

**Ce n'est pas un travail de v1** — il faut un point d'écoute d'observation, un
jeton à usage unique dans le datagramme pour qu'on ne puisse pas faire attribuer
n'importe quel mapping à n'importe qui, et une borne sur ce qu'un daemon peut
faire émettre. Mais c'est désormais une extension, et non un second protocole.

### 4.2 La traversée de NAT

L'annuaire dit ce qu'il observe et ce qu'il atteint. Il n'aide personne à
percer. Les trois suites possibles et leur coût sont dans `modele.md` §6.3.

### 4.3 Un cadrage binaire

Le JSON coûte quelques centaines d'octets à l'annonce — et **plus rien ensuite**,
puisque le keepalive est celui de QUIC et ne transporte aucun corps. Le calcul
qui aurait rendu un cadrage binaire intéressant a donc largement perdu de sa
force en passant à la connexion tenue.

**Le jour où il redeviendrait vrai, c'est le cadrage qui changerait, pas
l'architecture** : `asl-proto` est la seule crate qui verrait la différence, et
c'est exactement pourquoi elle est séparée.
