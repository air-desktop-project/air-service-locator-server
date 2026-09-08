# Protocole

Trois conversations, trois publics, trois rythmes. Elles partagent un transport
en v1 — HTTPS — et ce document dit pourquoi, et à quelle condition cela cessera.

Le vocabulaire (candidat, bail, `annoncé` / `joignable` / `expiré`) est défini
dans [`modele.md`](modele.md). Ce document ne le redéfinit pas.

---

## 0. Le transport, et la décision qui le fixe

**v1 : HTTPS sur TLS 1.3, corps JSON, pour les trois voies.**

Les raisons, dans l'ordre où elles pèsent :

1. **`asl-client` est embarqué par des daemons tiers.** Ce qu'il tire, un tiers
   l'embarque. Un client HTTPS est ce qui coûte le moins à imposer à quelqu'un
   qui voulait juste annoncer un numéro de port.
2. **HTTPS traverse ce qui existe.** Un daemon derrière un proxy d'entreprise
   n'a aucune autre voie. Un protocole qui échouerait là échouerait précisément
   chez les administrateurs que ce produit vise.
3. **Il se débogue avec `curl`.** Le premier utilisateur qui écrira un daemon
   n'aura pas nos outils.

**Ce que cela coûte, et qui n'est pas caché** : une poignée de main TLS toutes
les trente secondes si la connexion n'est pas tenue ouverte. `asl-client`
maintient donc une connexion persistante et rouvre à la coupure — ce qui ramène
le coût à quelques centaines d'octets par rafraîchissement.

**Ce que cela ne permet PAS**, et qui justifie la voie réservée en §4 : obtenir
un candidat réflexif UDP utilisable. Cela exige d'annoncer depuis la socket
d'écoute, ce qu'une requête HTTPS ne fait pas (`modele.md` §3).

---

## 1. La voie du daemon — `asl-proto`, `asl-client`

Trois messages, et rien de plus.

### 1.1 Annoncer — `POST /v1/annonce`

```jsonc
{
  "machine": "m-7q2h8k3m9x4v6b1n5r0t2w8y3z",
  "service": "sauvegarde",
  "points": [
    { "protocole": "tcp", "port": 49152 },
    { "protocole": "udp", "port": 49152 }
  ],
  "adresses_locales": ["192.168.1.20", "fe80::1c2d:3e4f:5a6b:7c8d"]
}
```

Autorisation : `Authorization: Bearer sm-…`, le secret de la machine — qui doit
porter la capacité `annonce` (`modele.md` §2.3).

**`adresses_locales` ne sert PAS à joindre le daemon depuis l'Internet** — c'est
`vu_depuis` qui compte pour cela. Il est là pour deux autres raisons :

1. **Il permet à l'annuaire de trancher que la machine est derrière un NAT**, en
   comparant ce que le daemon dit avec ce qu'il observe. Le daemon peut le faire
   lui-même, mais l'annuaire est le seul à pouvoir le lui AFFIRMER.
2. Un client qui se trouve sur le même réseau y gagne une route directe. Ce
   n'est pas le cas visé par le produit, et cela ne coûte rien.

La réponse :

```jsonc
{
  "service": "s-4k9m2p7r1t6v3x8z5b0d2f4h6j",
  "bail_secondes": 90,
  "rafraichir_dans_secondes": 30,
  "vu_depuis": { "adresse": "203.0.113.4", "port": 61003 },
  "joignabilite": [
    { "protocole": "tcp", "port": 49152, "verdict": "joignable",
      "candidat": "203.0.113.4:49152", "a": "2026-09-08T13:02:11Z" },
    { "protocole": "udp", "port": 49152, "verdict": "non_sonde",
      "raison": "l'UDP ne se sonde pas" }
  ]
}
```

**`vu_depuis` et `joignabilite` sont la moitié utile de cette réponse**, et non
un ornement de diagnostic.

- `vu_depuis` dit au daemon **s'il est derrière un NAT** : il lui suffit de
  comparer avec ses propres adresses. Aucun autre moyen ne le lui apprend.
- `joignabilite` lui dit **si quelqu'un peut réellement l'atteindre**, à la
  seconde où il démarre — et non le jour où un utilisateur s'en plaint.

Un daemon bien écrit journalise les deux à son démarrage. La documentation
d'installation le recommandera, parce que c'est ce qui transforme une panne de
réseau silencieuse en une ligne de journal lisible.

### 1.2 Rafraîchir — `POST /v1/annonce`

**Le même message.** Il n'y a pas de verbe « rafraîchir » : réannoncer EST
rafraîchir, et cela n'est pas une économie de conception.

Un daemon qui redémarre après une coupure ne sait pas si son bail court encore.
Avec deux verbes, il devrait le demander pour choisir lequel employer — un
aller-retour de plus, et une branche de code de plus, pour une question dont la
réponse ne change rien à ce qu'il veut. Avec un seul, il annonce, et l'annuaire
tranche.

L'annuaire ne resonde PAS à chaque rafraîchissement : une fois par bail accordé,
et à chaque changement de candidat.

### 1.3 Se retirer — `DELETE /v1/annonce/{service}`

Un arrêt propre se dit. **Mais le silence suffit** : une machine qu'on débranche
ne dit rien, et le retrait n'est donc jamais une condition de correction. Il
n'est qu'une politesse qui évite jusqu'à quatre-vingt-dix secondes d'état faux.

### 1.4 Reprise — ce que fait `asl-client` quand l'annuaire ne répond pas

**L'annuaire injoignable NE DOIT PAS empêcher un daemon de démarrer.** C'est la
règle qui gouverne toute cette section : un service de découverte en panne
rendrait sinon indisponibles tous les daemons qui en dépendent, ce qui est la
faute exacte que ce genre de composant existe pour ne pas commettre.

`asl-client` :

1. **rend la main immédiatement** ; l'annonce se fait en arrière-plan ;
2. **réessaie avec un recul exponentiel** — 1 s, 2 s, 4 s… plafonné à la
   cadence de rafraîchissement, **avec un bruit aléatoire de ±20 %** ;
3. **n'abandonne jamais.** Un daemon qui tourne depuis un mois doit se
   réannoncer tout seul quand l'annuaire revient.

**Le bruit aléatoire n'est pas du raffinement.** Sans lui, mille daemons dont
l'annuaire vient de tomber réessaient à la même seconde, et le remettent à
terre à l'instant où il se relève. Il coûte une ligne.

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
| `POST /v1/machines` | Déclare une machine, avec ses **capacités** (`annonce`, `lecture`). **Rend le secret de machine, UNE SEULE FOIS.** |
| `PATCH /v1/machines/{m}` | Change le nom ou les capacités. |
| `POST /v1/machines/{m}/secret` | Remplace le secret. Invalide l'ancien à la seconde. |
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
Authorization: Bearer sm-…        (le secret de la machine QUI DEMANDE)
```

**Rien ne s'interroge anonymement.** Le secret authentifie la machine, la
machine désigne son propriétaire, et l'annuaire ne rend que ce que ce
propriétaire a le droit de voir : ses propres services, et ceux qu'une
autorisation lui a accordés (`modele.md` §2.5).

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
  vraiment : il n'existe aucune requête qui rende quoi que ce soit sans un
  secret de machine valide.
- Un identifiant porte **128 bits** : il ne se devine pas.
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

### 4.1 La voie d'annonce UDP

**C'est la seule façon d'obtenir un candidat réflexif UDP utilisable** : il faut
annoncer *depuis la socket d'écoute*, ce qu'une requête HTTPS ne fait pas.

Elle apporterait aussi le maintien du mapping NAT — d'où la cadence de 25 s
plutôt que 30 (`modele.md` §4.1).

Elle exige d'écrire nous-mêmes retransmission, anti-rejeu et chiffrement. **Ce
n'est pas un travail de v1**, et le faire à moitié serait pire que ne pas le
faire : un rafraîchissement rejouable permettrait de maintenir en vie le bail
d'un daemon mort.

### 4.2 La traversée de NAT

L'annuaire dit ce qu'il observe et ce qu'il atteint. Il n'aide personne à
percer. Les trois suites possibles et leur coût sont dans `modele.md` §6.3.

### 4.3 Un cadrage binaire

Le JSON coûte quelques centaines d'octets par rafraîchissement. À mille daemons
c'est négligeable ; à un million cela cesse de l'être. **Le jour où ce calcul
changera, c'est le cadrage qui changera, pas l'architecture** : `asl-proto` est
la seule crate qui verrait la différence, et c'est exactement pourquoi elle est
séparée.
