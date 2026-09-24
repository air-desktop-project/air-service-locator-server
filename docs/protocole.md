# Protocole

Trois conversations, trois publics, trois rythmes. Elles partagent un transport
en v1 — HTTPS — et ce document dit pourquoi, et à quelle condition cela cessera.
Une quatrième, entre les deux racines, n'a qu'un public et tient ici en une
section (§3 bis) ; son fond est dans [`replication.md`](replication.md).

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
  "keepalive_secondes": 10,
  "inactivite_secondes": 30,
  "vu_depuis": { "adresse": "2001:db8::1c2d", "port": 51840 },
  "derriere_nat": "non",
  "joignabilite": [
    { "protocole": "tcp", "port": 49152, "verdict": "joignable",
      "candidat": "[2001:db8::1c2d]:49152", "origine": "reflexif",
      "a": 1789217731000 },
    { "protocole": "udp", "port": 49152, "verdict": "non_sonde",
      "raison": "protocole_non_sondable" }
  ]
}
```

### Trois écarts avec la première rédaction de ce document

Ils ont été trouvés **en écrivant les types**, et corrigés ici plutôt que laissés
en contradiction avec le code.

**`derriere_nat` N'EST PLUS UN BOOLÉEN.** L'annuaire tranche en comparant ce
qu'il observe à ce que le daemon annonce. Si le daemon n'a annoncé **aucune**
adresse locale, il n'y a rien à comparer — et un booléen forcerait alors à
répondre `false`, c'est-à-dire à affirmer une chose qu'on n'a pas mesurée. Un
daemon derrière un NAT qui lirait « non » chercherait la panne partout sauf là où
elle est. **C'était une violation de C6 dans le schéma**, et les trois valeurs
sont `oui`, `non`, `indetermine`.

**`famille` A DISPARU.** Elle se déduit de l'adresse. Un champ redondant est un
champ qui peut CONTREDIRE l'autre — `"famille":"ipv6"` sur une adresse v4
obligerait un lecteur à choisir un gagnant, et deux lecteurs choisiraient
différemment. C'est la même faute que les champs en double, écrite dans le schéma
au lieu du document.

**`a` EST UN ENTIER DE MILLISECONDES D'ÉPOQUE**, et non une date RFC 3339. Un
analyseur de date est une surface d'analyse entière — années bissextiles,
longueurs de mois, la soixantième seconde, les décalages — exposée au réseau pour
transporter un nombre. Et `asl-client` expose ceci à cinq langages qui ont chacun
leur type de date : leur rendre un entier est plus honnête que leur rendre une
chaîne qu'ils devront analyser. Le prix est réel : un humain qui lit avec `curl`
voit `1789217731000`. L'afficher lisiblement est le travail de l'application ou
de l'utilitaire `asl`, pas celui du protocole.

**Et `raison` est une valeur, non une phrase.** `"protocole_non_sondable"` se
compare ; « l'UDP ne se sonde pas » se traduit et se reformule.

### Un quatrième verdict : `en_cours`

**L'annuaire ne fait pas attendre le démarrage d'un daemon.**

Répondre en portant déjà les verdicts suppose de SONDER avant de répondre — donc
de faire attendre le démarrage le temps d'une connexion TCP vers une machine qui
peut ne jamais répondre. Un daemon dont le démarrage dépend d'un délai d'attente
réseau est un daemon qui démarre mal.

La connexion est TENUE (§0) : l'annuaire répond donc tout de suite `en_cours`,
sonde, et **pousse le verdict ensuite**. C'est précisément ce que le transport a
été choisi pour permettre, et ce qu'un protocole requête-réponse aurait fermé.

### Chaque verdict porte exactement ses champs

| Verdict | Champs |
|---|---|
| `joignable` | `candidat`, `origine`, `a` |
| `injoignable` | `a` |
| `non_sonde` | `raison` |
| `en_cours` | aucun |

**Un champ hors de propos est REFUSÉ**, pas ignoré : une date sur un `en_cours`,
un candidat sur un `non_sonde`, et l'émetteur dit quelque chose que le verdict ne
peut pas porter. Le lire « au mieux » reviendrait à décider à sa place.

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

**Le type refuse cependant ce qui est absurde** : une inactivité inférieure au
DOUBLE du keepalive fait tuer un daemon parfaitement sain à la première perte de
paquet. Il refuse l'absurde, il n'impose pas le prudent — la politique du produit
est de trois pour un, et elle reste mesurable.

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

**ET LE RETRAIT N'EST PAS UN MESSAGE — il ne le sera jamais.** Une version
antérieure de ce document listait un `DELETE /v1/annonce/{service}`, hérité d'une
conception requête-réponse. Avec une connexion tenue, un tel verbe ferait deux
façons de dire la même chose, et un annuaire devrait décider quoi faire d'un
retrait suivi d'une connexion qui reste ouverte. Fermer suffit, et une seule
façon de partir vaut mieux que deux.

### 1.4 La poussée de verdict

**L'annuaire répond souvent `en_cours`** (§1.1) : il ne fait pas attendre le
démarrage d'un daemon le temps d'une sonde. Le verdict arrive ensuite, dans la
connexion déjà tenue.

```
GET /v1/poussees
        (dans la même connexion QUIC, après l'annonce)
```

**LA RÉPONSE À CE VERBE NE SE TERMINE JAMAIS.** L'annuaire répond `200`, garde le
flux ouvert, et y écrit un objet à chaque verdict. Un client le lit à mesure, sans
attendre de fin.

Elle ne porte **ni corps d'ouverture, ni `content-length`** : le premier octet est
la première poussée, et une longueur déclarée sur un corps qui s'allonge est un
message qui se contredit — un intermédiaire aurait raison de la couper.

**Les objets se suivent sans enveloppe**, et non dans un tableau : un tableau
attend un crochet fermant qui ne viendra jamais, et un lecteur qui l'attendrait
n'afficherait rien.

**Le flux n'est pas ouvert d'office.** Un daemon qui ne le demande pas ne reçoit
rien : il a lu `en_cours` et s'en contente. Le verbe exige la capacité `annonce` —
une machine de lecture seule n'a aucun service, donc aucun verdict, et lui ouvrir
ce flux tiendrait une ressource des deux côtés pour rien.

**On ne pousse que ce qui a CHANGÉ.** Un verdict tardif — le service est parti,
réannoncé, ou déjà mesuré autrement — ne produit rien : une connexion qu'un daemon
tient pour des mois n'a pas à porter du bruit.

```jsonc
{
  "vu_depuis": { "adresse": "203.0.113.4", "port": 61003 },
  "derriere_nat": "oui",
  "joignabilite": [
    { "protocole": "tcp", "port": 49152, "verdict": "injoignable", "a": 1789217752000 }
  ]
}
```

**Elle ne porte AUCUN identifiant de service.** La connexion le détermine déjà ;
l'y remettre serait un champ qui peut CONTREDIRE la connexion sur laquelle il
arrive — la même faute que le `famille` retiré de `vu_depuis`.

**Elle porte la liste ENTIÈRE, et non un delta.** Un delta oblige le receveur à
fusionner, donc à décider quoi faire d'une entrée inconnue ou d'un ordre
inattendu ; deux receveurs qui fusionnent différemment lisent deux états dans les
mêmes messages. Une liste entière se remplace, et il n'y a rien à décider.

**Elle porte aussi `vu_depuis` et `derriere_nat`, parce qu'ils peuvent changer.**
QUIC fait migrer une connexion quand la machine change d'adresse — bascule 4G,
renumérotation IPv6 — et l'observation de l'annuaire change avec elle. C'est une
conséquence directe du transport choisi, et le daemon doit l'apprendre : il peut
être passé derrière un NAT sans avoir rien fait.

**Elle ne porte PAS le bail.** Il est accordé une fois, à l'annonce. Le changer
en cours de connexion demanderait son propre message et sa propre règle — que
devient un keepalive déjà en vol ? — et rien de cela n'est décidé.

### 1.5 Reprise — ce que fait `asl-client` quand l'annuaire ne répond pas

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

### 2.0 Le verbe qui manquait, et par où la clé d'une machine arrive

`POST /v1/machines/{m}/enrolement` ÉMET un code depuis l'application. **Rien ne
disait par où la machine le RAPPORTE**, alors que `modele.md` §2.3 décrit
pourtant le geste : « la machine génère sa paire de clés, et présente sa clé
publique avec le code ». C'était un trou, et il est comblé :

```
POST /v1/enrolement
     (dans une connexion QUIC, sans aucune authentification préalable)

     corps = code (10 octets) ‖ clé publique (32) ‖ preuve (64)
```

**IL NE NOMME PAS LA MACHINE, ET C'EST TOUT LE DISPOSITIF.** Un verbe sous
`/v1/machines/{m}` aurait obligé la machine à se désigner elle-même — et
l'annuaire à croire sur parole celui qui la nomme. Ici, **le code désigne la
machine**, et personne d'autre ne la désigne.

**L'annuaire ne garde pas les codes, il garde leurs EMPREINTES** (SHA-256,
domaine séparé). Deux conséquences :

— une base qui fuit ne livre aucune machine en cours d'enrôlement ;
— il n'y a **rien à comparer** : la recherche se fait par l'empreinte. La
  fonction de comparaison en temps constant qui existait pour C9 n'a plus
  d'appelant, et la meilleure façon de tenir une comparaison en temps constant
  reste de ne pas avoir de comparaison à faire.

**La preuve est une PREUVE DE POSSESSION**, et non la signature ordinaire d'un
défi : la machine ne peut pas signer son identifiant, puisqu'elle ne le connaît
pas. Elle signe donc la CLÉ qu'elle présente, sous un domaine distinct — sans
quoi une preuve d'authentification captée ailleurs vaudrait preuve de possession
ici.

**Un code inconnu et un code périmé rendent le même refus**, et pour cause : un
code consommé est SUPPRIMÉ, pas marqué. L'annuaire ne fait pas la différence, et
n'a donc rien à en dire.

**La réponse rend l'identifiant de la machine, ET celui de son propriétaire** :
`{"machine": "m-…", "proprietaire": "u-…"}`. La machine ne connaissait ni l'un
ni l'autre — le code désignait tout —, et elle doit pouvoir dire pour qui elle
agit sans repasser par l'annuaire : l'utilitaire range les deux dans son fichier
d'identité, et `asl identity` les rend hors ligne. Une machine enrôlée avant
cette ligne les apprend par `GET /v1/moi` (§3).

### 2.1 Enrôler un appareil

Il n'y a **pas de mot de passe** dans ce produit. Un compte est un jeu
d'appareils enrôlés, et rien d'autre.

1. L'application génère une paire de clés **dans le matériel sécurisé** —
   Secure Enclave, ou Keystore adossé au TEE — avec un contrôle d'accès qui
   **exige la biométrie pour s'en servir** (`kSecAccessControlBiometryCurrentSet`,
   `setUserAuthenticationRequired(true)`).

   **Et cette clé est donc P-256, pas Ed25519.** La Secure Enclave ne fait que
   cette courbe, StrongBox aussi : une clé Ed25519 ne peut pas y entrer. Les
   machines gardent Ed25519 — un daemon sur un Linux n'a pas d'enclave —, les
   appareils signent en ECDSA P-256 (`asl_cle::CleAppareil`, 33 octets SEC1
   compressés, signature `r ‖ s` sur 64 octets). Le message signé est le même ;
   c'est la clé rangée dans l'annuaire qui dit, par sa forme, comment vérifier.
   Décidé le 2026-09-11, quand l'attestation a fait remonter que la v1 disait
   « dans le matériel » et n'en permettait pas le moyen.
2. Elle envoie la clé publique et, quand la plate-forme en fournit une,
   l'**attestation** de la plate-forme (App Attest, Play Integrity).

   **Ce que l'attestation prouve, et ce qu'elle ne prouve pas.** App Attest
   n'atteste pas la clé de l'appareil : il atteste une clé À LUI, qui ne signe
   que pour lui, et iOS n'atteste aucune autre clé. Ce qui est prouvé est donc
   qu'**une build authentique de notre app, sur un appareil réel, a présenté
   cette clé** — et c'est le code de cette build qui l'a mise dans l'enclave. Ce
   n'est pas « cette clé vit dans du matériel », que ce document affirmait, et
   que rien ne peut établir depuis le serveur sur iOS. (Android, lui, a une
   attestation de clé qui le pourrait ; ce sera une case de plus, plus tard.)
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

#### Et aujourd'hui, la vérification n'est pas écrite — d'où un réglage sans défaut

App Attest et Play Integrity demandent les racines d'Apple et de Google, du CBOR,
et une chaîne à valider. **Exiger l'attestation aujourd'hui, c'est donc refuser
TOUS les enrôlements.**

**Depuis le 2026-09-11, la GRAMMAIRE est écrite** — `asl-attest`, étage 1 : un
lecteur CBOR borné qui ne sert que les cinq types majeurs qu'App Attest emploie,
et l'objet d'attestation lui-même (`fmt`, `attStmt.x5c`, `attStmt.receipt`,
`authData` et la disposition de WebAuthn qu'il porte). Couverte à 100 %, fuzzée,
et elle ne vérifie RIEN : elle dit ce que les octets contiennent, pas ce qu'ils
prouvent.

**Et la VÉRIFICATION aussi** — `asl-apple`, étage 2 : la chaîne `x5c` remontée
jusqu'à la racine d'Apple par `rustls-webpki` (avec des vérificateurs ECDSA
écrits ici, sur `p256` et `p384`), le nonce — `SHA-256(authData ‖
SHA-256(défi))` — comparé à l'extension `1.2.840.113635.100.8.2` de la feuille,
l'empreinte de sa clé publique comparée à l'identifiant, le `rpIdHash` comparé à
l'empreinte de l'identifiant d'app, l'`aaguid` à l'environnement, le compteur à
zéro. La racine est un PARAMÈTRE : les essais signent leur propre chaîne sous
leur propre racine, et c'est ainsi que chaque refus a pu être éprouvé — Apple ne
signera jamais une feuille au nonce faux.

Ce qui manque encore, et qui n'est pas une formalité :

  1. **Le défi.** La vérification compare le nonce à un défi que le serveur a
     émis ; rien, aujourd'hui, n'en émet ni n'en garde. C'est une décision de
     protocole : qui le donne, combien de temps il vaut, à quoi il est lié.
  2. **Une place sur le fil.** `POST /v1/comptes` porte aujourd'hui une clé et
     une preuve, à champs de longueur fixe : **il n'y a pas d'endroit où mettre
     une attestation.**
  3. **Play Integrity**, qui est d'une tout autre forme — un jeton JWS signé par
     Google, pas une chaîne X.509 — et qui ne se décidera pas en même temps.
  4. **UNE CAPTURE RÉELLE.** Toute la disposition ci-dessus vient de la
     documentation d'Apple, et aucun iPhone n'a jamais parlé à ce dépôt. Les
     essais éprouvent que le lecteur lit ce qu'il croit lire et que la
     vérification refuse ce qu'elle doit refuser SUR UNE CHAÎNE FABRIQUÉE
     D'APRÈS LA DOCUMENTATION ; ils n'éprouvent pas que c'est bien ce qu'Apple
     envoie — ni la forme exacte de l'extension, ni la présence d'un
     `extendedKeyUsage` (on n'en exige aucun, faute de savoir), ni l'ordre des
     certificats dans `x5c`. **Tant qu'une attestation réelle
     n'aura pas été lue, `required` ne peut pas être tenue pour sûre** : le premier
     appareil légitime serait aussi le premier refusé.

Les deux postures sont défendables et **aucune ne peut être le défaut** : exiger
livrerait un annuaire qui ne crée aucun compte, dispenser livrerait en silence la
posture faible. `asl-server` n'a donc **pas de valeur par défaut** — il refuse de
démarrer tant qu'on ne lui a pas dit laquelle il tient :

```
asl-server --attestation required   # la posture de ce document, et rien ne passe
asl-server --attestation optional   # n'importe qui crée un compte, et c'est dit
                                    # au démarrage, dans le journal d'exploitation
```

**Depuis le 2026-09-11, elle est écrite et branchée.** `POST /v1/comptes` porte
une attestation (§2.1 bis), `asl_apple::verifier` la vérifie contre la racine
d'Apple, et `asl_auth::decider_attestation` reçoit enfin un `atteste` qui n'est
plus toujours faux. L'annuaire a besoin de deux réglages pour une attestation
Apple — `--apple-app <équipe.bundle>` et `--apple-environment
<production|development>` —, parce que le `rpIdHash` se compare à l'empreinte
de l'app et que l'environnement sépare la production du développement. La racine,
elle, est la même pour tous et vit dans le binaire.

**Le défi est partagé.** `GET /v1/defi` tire un défi ; la preuve de possession le
signe, et l'attestation le couvre via son challenge — `asl_cle::message_d_attestation`
compose `DOMAINE ‖ clé ‖ défi ‖ liaison`, et l'appareil en hache le condensat
pour App Attest. Un seul aller-retour, une seule valeur à usage unique, et
l'attestation se trouve liée À LA clé présentée : sans ce lien, App Attest
n'atteste qu'une clé à lui, jamais celle qu'on enrôle.

**Et toujours : aucune capture réelle côté Apple.** La chaîne, la forme de
l'extension et l'environnement viennent de la documentation d'Apple ;
`--attestation required` ne peut pas être tenue pour sûre tant qu'un vrai iPhone
n'a pas été lu — le premier appareil légitime serait sinon le premier refusé.

#### Décidé le 2026-09-16 : l'attestation n'appelle personne, et Play Integrity est abandonné

**Le principe, avant le moyen** (C19) : air-desktop ne dépend ni de Google ni
d'Apple pour fonctionner. L'attestation est une **garantie que l'exploitant
d'une racine choisit** — jamais une condition du service : les racines tournent
en `optional` depuis le premier jour, et tout marche. Et quand elle est choisie,
**aucun tiers n'est appelé** : ce que l'annuaire vérifie, il le vérifie hors
ligne, contre des **racines de confiance qui sont des fichiers**, épinglés par
l'exploitant comme `--peer-ca` l'est pour la réplication.

**Play Integrity contredisait ce principe, et il est abandonné.** Il demandait
un compte développeur Google Play, l'app dans la Play Console, des clés de
réponse « gérées par moi », et les services Google Play sur l'appareil ; son
verdict était l'opinion de Google sur l'appareil ET sur la distribution par le
Play Store. C'était le mauvais outil : `asl-play` est retiré, la dépendance
`com.google.android.play:integrity` avec lui, et aucun compte Google ne sera
ouvert. Le jeton capturé le 2026-09-12 reste dans `docs/attestation/captures/`
comme trace de ce qu'on a lu, pas comme chemin. `asl-jwt` — le découpage
JWS/JWE qu'`asl-play` était seul à tirer — est retiré à son tour le
2026-09-21 (0.12.0), avec sa cible de fuzz : une grammaire que personne ne
lit n'est pas une réserve, c'est une surface.

**Ce qui le remplace : l'attestation de clé d'Android (Keystore).** C'est ce
que ce document appelait plus haut « une case de plus, plus tard », et c'est
MIEUX que ce qu'on quitte : elle atteste **la clé elle-même** — générée dans le
TEE ou StrongBox, non exportable —, l'état du démarrage vérifié (`verifiedBootState`,
bootloader verrouillé), le niveau de correctif, et **l'application qui détient
la clé** (nom du paquet et empreinte de sa signature, dans
`attestationApplicationId`). Exactement la question posée en §2.1 — « une vraie
build de notre app, sur un vrai appareil, a présenté cette clé » —, et pour
Android c'est bien « cette clé vit dans du matériel », ce qu'iOS ne sait pas
dire. Rien n'est appelé : la chaîne X.509 remonte à une racine, et la racine est
un fichier.

- **Sur le fil**, la case de plate-forme `2` de `POST /v1/comptes` (§2.1 bis)
  devient **Android** — elle ne désignait Google que sur le papier, aucune
  attestation `2` n'a jamais été acceptée. L'attestation est la chaîne,
  **feuille d'abord**, chaque certificat DER précédé de sa longueur sur deux
  octets grand-boutiens ; la racine peut être omise (l'annuaire la tient). Une
  chaîne réelle fait quatre certificats et de 4 à 6 Kio — la borne de 8 Kio
  reste, et la capture réelle dira si elle tient.
- **La liaison au défi.** Le `attestationChallenge` de la clé est
  `SHA-256(asl_cle::message_d_attestation_de_cle(défi, liaison))`, posé à la
  GÉNÉRATION de la clé (`setAttestationChallenge`) — la clé attestée EST la
  clé enrôlée, sans le détour qu'App Attest impose. **Sans la clé dans le
  message, et ce n'est pas un oubli** (corrigé le 2026-09-16, 0.9.1 : la
  première rédaction reprenait le message d'App Attest, qui contient la clé —
  impossible à poser à la génération de cette clé). Le certificat d'attestation
  PORTE la clé publique, et `asl-keystore` compare la feuille à la clé
  enrôlée : la liaison à la clé est là, plus forte qu'un condensat. Le défi n'a
  à lier que ce que le certificat ne porte pas — la connexion, par le défi tiré
  (`GET /v1/defi`) et la liaison de canal. D'où l'ordre côté app : se connecter
  nu, tirer le défi, composer le message, GÉNÉRER la clé avec son condensat,
  puis `POST /v1/comptes`. Un domaine à part
  (`air-service-locator/v1/attestation-de-cle`), pour qu'un message
  d'attestation d'une voie ne vaille jamais sur l'autre.
- **Ce que l'annuaire vérifie** (`asl-keystore`, étage 2, comme `asl-apple`) :
  la chaîne jusqu'à une racine épinglée (`--android-roots <fichier PEM>`, une ou
  plusieurs), l'extension `1.3.6.1.4.1.11129.2.1.17` de la feuille — le
  `attestationChallenge` égal au condensat attendu, la clé publique de la feuille
  égale à celle qu'on enrôle, `attestationSecurityLevel` et
  `keymintSecurityLevel` à `TrustedEnvironment` ou `StrongBox`,
  `verifiedBootState` à `Verified`, et `attestationApplicationId` portant NOTRE
  paquet et NOTRE empreinte de signature (`--android-app <paquet>` et
  `--android-signer <empreinte SHA-256>`, les pendants de `--apple-app`). La
  politique sur le niveau de correctif et la liste de révocation de Google
  (`attestation/status`) restent à trancher après la capture — et cette liste
  serait un tiers appelé : si elle sert, c'est un fichier rafraîchi par
  l'exploitant, pas un appel de l'annuaire.
- **Les racines sont celles que l'exploitant choisit.** Celle de Google, pour
  les Android certifiés — publiée, un fichier, aucun compte ; celle de
  GrapheneOS, pour les siens ; ou aucune. Le dépôt expédie les deux en exemple
  sous `paquet/`, et n'en impose aucune. Un appareil dont la chaîne ne remonte
  à aucune racine épinglée est traité comme sans attestation : refusé en
  `required`, admis en `optional`, avec sa valeur `aucune`.
- **La capture réelle vient du Fairphone 5**, sans rien demander à personne —
  c'est aussi ce qui rend cette voie éprouvable là où App Attest attend un
  iPhone. `docs/attestation/capture-keystore.md` en donne le geste.

**Écrit et branché le 2026-09-16 (0.9.0) : `asl-keystore`.** La case ci-dessus
est servie telle quelle — `n` certificats DER, feuille d'abord, chacun précédé
de sa longueur sur deux octets grand-boutiens, racine omissible, huit
certificats et 8 Kio au plus. La chaîne réelle du Fairphone 5
(`docs/attestation/captures/keystore-fp5-2026-09-16/`, 3 421 octets en quatre
certificats) remonte à la racine de Google dans les essais de la crate, et
chaque valeur que la capture a montrée en sort telle quelle. Ce qui est jugé :
la chaîne jusqu'à une racine de `--android-roots`, la clé de la feuille égale à
la clé enrôlée (comparée sous sa forme compressée, celle du fil),
`attestationChallenge` égal à `SHA-256(message_d_attestation_de_cle)`, les deux
niveaux de sécurité matériels, `rootOfTrust` côté matériel — `Verified` et
verrouillé —, `origin` `GENERATED` côté matériel, et NOTRE paquet sous NOTRE
empreinte dans `attestationApplicationId`. Ce qui est rendu sans être jugé :
`osVersion`, `osPatchLevel`, `vendorPatchLevel`, `bootPatchLevel` — la
politique de correctif reste à écrire. Les balises que le lecteur ne connaît
pas sont sautées, jamais refusées : le schéma change à chaque Android. Chaque
refus est dit au journal d'exploitation avec sa cause, sans la chaîne. La
plate-forme `3` (invitation) est servie depuis le 2026-09-24, sous la posture
du même nom — voir « Émettre une invitation » en §2.2. Le dépôt n'expédie que
la racine de Google (`paquet/racines-android/google.pem`, celle de la capture) : celle de
GrapheneOS n'a pas pu être obtenue hors ligne de façon sûre, et une racine
qu'on ne peut pas vérifier ne s'expédie pas.

**Une troisième posture, pour une racine sans aucun fabricant : l'invitation.**
`--attestation invitation` : l'exploitant émet un code d'invitation — même
forme que le code d'enrôlement (§2.3 de `modele.md` : dix symboles, usage
unique, l'annuaire n'en garde que l'empreinte) —, et `POST /v1/comptes` le
présente sous la plate-forme `3`, dans la case d'attestation (dix octets). Un
compte s'ouvre parce que quelqu'un l'a voulu, pas parce qu'un fabricant l'a
dit ; l'appareil entre avec la valeur `invitation`. **Comment l'exploitant émet
le code** : `POST /v1/invitations`, sur l'annuaire en marche, sous une clé
d'exploitation qu'un réglage déclare — tranché le 2026-09-24, et écrit en §2.2,
« Émettre une invitation ».

**Ce qui reste, honnêtement.** La racine de confiance d'une attestation est
celle de qui a fabriqué l'enclave — Google pour les Android certifiés, Apple
pour iOS. C'est inhérent à « prouver du matériel », et c'est un fichier, pas un
service. Sur iOS, il n'y a pas d'autre attestation que celle d'Apple, et App
Attest reste : vérifié hors ligne, sans autre compte que celui qui signe déjà
l'app. Et **les notifications** (§2.6 de `modele.md`) passent encore par APNs et
FCM — c'est la dépendance qui reste à regarder, sous le même principe ;
UnifiedPush est la voie à instruire pour Android.

### 2.1 bis Ce que porte chaque corps, et pourquoi ce n'est pas toujours du JSON

**Les corps qui portent des CLÉS et des SIGNATURES sont des octets bruts**, à
champs de longueur fixe :

| Verbe | Corps | Taille |
|---|---|---|
| `POST /v1/defi` | genre ‖ identifiant (17) ‖ signature (64) | 81 |
| `POST /v1/comptes` | plate-forme (1) ‖ clé d'appareil (33) ‖ preuve (64) ‖ attestation (0…8 Kio) | 98 + attestation |
| `POST /v1/appareils` | clé d'appareil (33) | 33 |
| `POST /v1/attestation` | genre `a` ‖ identifiant (17) ‖ signature (64) ‖ plate-forme (1) ‖ attestation (0…8 Kio) | 82 + attestation |
| `POST /v1/enrolement` | code (10) ‖ clé de machine (32) ‖ preuve (64) | 106 |
| `POST /v1/invitations` | genre `o` ‖ signature (64) — **sans identifiant** : il n'y a qu'une clé d'exploitation, celle du réglage | 65 |

**Deux tailles de clé, et ce n'est pas une inadvertance.** La clé d'un
APPAREIL fait 33 octets (P-256 compressé, la courbe de la Secure Enclave) ; la
clé d'une MACHINE en fait 32 (Ed25519). L'enrôlement porte une clé de machine,
les deux autres une clé d'appareil.

**`POST /v1/comptes` et `POST /v1/attestation` sont les deux seuls corps à
champ variable de toute l'API**, et les seuls où la règle des longueurs fixes
plie : une chaîne de certificats n'a pas de taille. Le corps est donc un
préfixe fixe — 98 octets pour l'un, 82 pour l'autre —, puis l'attestation, qui
est tout le reste — **aucune longueur n'est lue des octets pour autant**, il n'y
a pas de champ de longueur à déplacer. Les deux portent la même case, sous les
mêmes plates-formes ; le second est la preuve d'un appareil qui rejoint,
augmentée de sa chaîne (voir « Attester un appareil qui rejoint », §2.2 — il
n'y avait pas de place pour elle, et c'était le trou).

La plate-forme se note `0` aucune, `1` Apple, `2` Android (l'attestation de
clé du Keystore, décidé le 2026-09-16 — la case disait Google, et n'a jamais
été acceptée), `3` invitation ; `0` interdit toute attestation derrière, `3`
porte le code d'invitation, `1` et `2` l'exigent. `asl_api::CreationDeCompte`
isole les trois tranches sans les interpréter, et la lecture de
`POST /v1/attestation` isole les siennes de la même façon ; `asl-attest`
refuse ensuite le moindre octet en trop DANS l'objet.

C'est l'argument d'`asl_cle::message_a_signer`, appliqué au transport : un
cadrage JSON demanderait d'encoder ces octets, donc **deux écritures possibles du
même contenu** — sur un chemin cryptographique, trois occasions de se tromper
pour zéro gain. Aucune longueur ne vient du réseau : le corps fait exactement la
taille attendue, ou il est refusé.

**Les corps qui portent des NOMS et des IDENTIFIANTS sont du JSON**, parce
qu'eux se débogueront avec `curl` :

```jsonc
POST /v1/machines       {"nom": "grenier", "capacites": ["annonce"]}
POST /v1/autorisations  {"a": "u-…", "portee": "tout"}
POST /v1/autorisations  {"a": "u-…", "portee": "m-…"}
```

**La portée est un seul champ, et le genre de l'identifiant la désigne.** Un
objet `{"sorte": …, "cible": …}` aurait rendu représentable une demande
incohérente — `{"sorte":"machine","cible":"s-…"}` — qu'il faudrait refuser à la
main. Et `tout` ne se confond avec aucun identifiant, qui en fait vingt-huit
caractères.

### 2.1 ter Ce que la création d'un compte prouve, et ce qu'elle ne prouve pas

**`POST /v1/comptes` porte une preuve de possession, et elle authentifie la
connexion.** L'appareil signe la clé qu'il présente, sur le défi de cette
connexion, lié à ce canal ; l'annuaire lui attribue alors un identifiant — qu'il
n'a donc pas pu signer, puisqu'il n'existait pas. Refaire le tour par `/v1/defi`
coûterait deux allers-retours pour rejouer la même démonstration.

**`POST /v1/appareils` n'en porte AUCUNE, et c'est l'autre moitié de la règle.**
Le nouveau téléphone ne parle pas sur cette connexion : c'est un appareil DÉJÀ
enrôlé qui apporte sa clé, lue d'un code affiché à l'écran. Un compte qui ajoute
une clé que personne ne détient n'a nui qu'à lui-même, et il lui reste l'appareil
qui vient de le faire.

La règle, en une phrase : **celui qui PRÉSENTE une clé signe qu'il la détient ;
celui pour qui un tiers déjà authentifié l'apporte ne signe pas.**

C'est aussi ce qui fixe le sens du geste entre les deux écrans : c'est le
NOUVEL appareil qui montre sa clé, et l'ANCIEN qui la lit — jamais l'ancien qui
« exporte » le compte vers le nouveau (`modele.md` §2.2). Le nouveau, une fois
sa clé rangée, apprend l'identifiant du compte et le sien par le même canal, à
l'envers, et prouve la clé sur sa propre connexion avec `POST /v1/defi` — ou,
**depuis le 2026-09-21, avec `POST /v1/attestation`**, qui est la même preuve
augmentée de la chaîne d'attestation de sa clé : celui qui rejoint ne signe
pas qu'on l'apporte, mais il signe qu'il détient, et c'est à cette signature-là
que sa chaîne s'attache (« Attester un appareil qui rejoint », §2.2).

### 2.1 quater Ce que « effet immédiat » veut dire, et ce qu'il coûte

Effacer une clé dans l'entrepôt suffit à refuser la PROCHAINE authentification.
Cela ne suffit pas à arrêter une machine : **une connexion déjà authentifiée
porte son pair avec elle** — c'est tout l'intérêt du transport tenu (§3) —, et
elle continuerait de servir jusqu'à ce qu'elle tombe d'elle-même.

La révocation d'une clé de machine, et celle d'un appareil, **ferment donc les
connexions de ce pair**. Et comme **la connexion EST le bail** (§1.2), les
annonces du daemon tombent avec elle, par le chemin ordinaire d'un départ — il
n'y a pas de second mécanisme à écrire, ni à tenir d'accord avec le premier.

Ce que cela coûte, et il faut le dire : la fermeture n'est pas synchrone de la
réponse. L'annuaire répond `204` à l'application, puis ferme au tour de boucle
suivant. **Aucune requête de plus n'est servie entre les deux** — le rendez-vous
qui ferme passe avant la lecture du datagramme suivant —, mais un daemon peut
avoir des octets en vol au moment où la porte se ferme.

**La révocation d'une AUTORISATION ne ferme rien**, et n'en a pas besoin : la
résolution relit l'entrepôt à chaque requête, donc l'effet est immédiat sans
qu'on touche à quoi que ce soit de vivant.

### 2.1 quinquies Ce qu'un retrait répond, et pourquoi c'est toujours la même chose

| Cas | Réponse |
|---|---|
| C'est fait | `204`, sans corps |
| L'objet n'existe pas | `404` |
| L'objet existe et **n'est pas à nous** | `404`, le même |
| Un appareil se révoque lui-même | `403` |
| Le compte s'efface (`DELETE /v1/compte`) | `204`, puis la connexion est fermée — la clé qui a demandé n'existe plus |
| L'alias demandé est pris | `409` |

**Les deux `404` sont le même `404`, et c'est la propriété qui compte.** Les
distinguer dirait à qui essaie des identifiants au hasard lesquels existent — et
un identifiant qui existe est un compte qu'on vient de découvrir. C'est la même
règle que pour la résolution (§3, contrainte C9).

**Le `403` est le seul refus qui ne se cache pas**, et il le peut : celui qui
demande connaît déjà son propre identifiant. Le lui taire ne protégerait rien et
l'empêcherait de comprendre.

### 2.2 Le reste

| Verbe | Ce qu'il fait |
|---|---|
| `POST /v1/comptes` | Crée le compte et enrôle le premier appareil. Rend `u-…`. |
| `POST /v1/appareils` | Enrôle un appareil de plus. **Signé par un appareil déjà enrôlé.** L'appareil entre `aucune` en posture facultative, **`attendue` en posture exigée** — vivant seulement quand il aura présenté sa chaîne (voir ci-dessous). |
| `POST /v1/attestation` | **La preuve d'un appareil qui rejoint, avec la chaîne d'attestation de sa clé** — le `POST /v1/defi` du genre `a`, augmenté de la plate-forme et de la chaîne, sur la connexion où le défi a été tiré AVANT que la clé soit générée. N'exige rien : c'est elle, la preuve. `204` ; la connexion est désormais celle de cet appareil, et son `attestation` dit sous quoi il est entré. Voir ci-dessous. |
| `GET /v1/appareils` | Les appareils de MON compte, révoqués compris et marqués : l'écran « Compte ». Chacun rend `appareil`, `attestation`, `revoque`, et — s'il les a posés — `plateforme` et `modele`. |
| `PUT /v1/appareils/{a}/poussee` | Dépose ou renouvelle le jeton APNs / FCM. **Pour soi seulement** ; voir ci-dessous. |
| `PUT /v1/appareils/{a}/description` | Dit ce que cet appareil est : `{"plateforme": "macos", "modele": "MacBook Pro (2019)"}`, la plate-forme parmi `ios`, `android`, `macos`. **Pour soi seulement**, même règle que la poussée ; voir ci-dessous. |
| `DELETE /v1/appareils/{a}` | Révoque. Un appareil ne peut pas se révoquer lui-même — sinon un téléphone volé et déverrouillé révoque les autres et confisque le compte. **Il est marqué, non effacé** : l'écran qu'on regarde après avoir perdu un téléphone doit montrer ce qu'on a retiré. La révocation du **dernier** appareil vivant ouvre le délai des orphelins (`modele.md` §2.1). |
| `DELETE /v1/compte` | **Efface MON compte** — celui de la clé qui signe. Tout part dans une transaction : appareils, machines et services, autorisations dans les deux sens, alias libéré ; reste l'identifiant marqué effacé. `204`, puis l'annuaire ferme la connexion : la clé qui a demandé est révoquée. Voir ci-dessous. |
| `POST /v1/invitations` | **Émet un code d'invitation**, sous la clé déclarée par `--operator-key`. Rend le code EN CLAIR, une fois — l'annuaire n'en garde que l'empreinte. N'existe que sous la posture `invitation` ; ailleurs, `404`. Voir ci-dessous. |
| `POST /v1/machines` | Déclare une machine, avec son **nom** et ses **capacités** (`annonce`, `lecture`). **Rend un code d'enrôlement** — dix symboles, à usage unique, valable dix minutes. La machine n'a **pas encore de clé**. |
| `GET /v1/machines` | Les machines de MON compte : l'écran « Machines ». Chacune rend `machine`, `nom`, `capacites`, et `cle` (`enrolee` ou `attendue`). |
| `PATCH /v1/machines/{m}` | Change le nom ou les capacités. **Ce qui est absent ne change pas** ; voir ci-dessous. |
| `POST /v1/machines/{m}/enrolement` | Émet un nouveau code, pour ré-enrôler une machine dont la clé a été révoquée ou perdue. **Le code précédent meurt à l'émission du suivant.** |
| `DELETE /v1/machines/{m}/cle` | Révoque la clé. **Effet immédiat : connexions fermées, baux tombés** (voir ci-dessous). La machine reste — son nom, ses capacités, ses services ; elle perd le moyen de prouver qu'elle est elle. |
| `PUT /v1/alias` | Enregistre ou change l'alias public. **La seule donnée que l'utilisateur nous confie.** Un alias déjà pris rend `409`, et non `403` : la demande est légitime, c'est l'état du monde qui s'y oppose. |
| `DELETE /v1/alias` | Le retire. |
| `GET /v1/alias/{alias}` | Rend l'identifiant, **et rien d'autre**. Public — c'est l'emploi de l'alias, et son coût (`modele.md` §2.1). |
| `GET /v1/machines/{m}/services` | Les services, leurs candidats, leur état et la date de la dernière sonde. |
| `GET /v1/vu` | **D'où l'annuaire voit cette connexion**, sans rien annoncer ni prouver. Voir ci-dessous. |
| `GET /v1/version` | **La version de l'annuaire qui répond**, `{"version": "0.2.0"}`, sans rien prouver. Voir ci-dessous. |
| `GET /v1/utilisateurs/{u}` | **Confirme qu'un identifiant existe**, et rien d'autre : ni nom, ni machines, ni services. Sert à ce qu'une faute de frappe ne produise pas une autorisation muette. |
| `GET /v1/moi/appareils` | **Les appareils du compte de la machine qui demande**, révoqués compris — lecture seule, voie machine. Voir §3. |
| `GET /v1/utilisateurs/{u}/machines` | **Les machines de `u` que le demandeur a le droit de voir** — les siennes si `u` est lui, sinon celles que les autorisations de `u` envers lui couvrent (`modele.md` §2.5). Voir ci-dessous. Servi aussi sur la voie machine (§3). |
| `POST /v1/autorisations` | Accorde. Bénéficiaire `u-…`, portée, étiquette. Déclenche la notification. |
| `GET /v1/autorisations` | Les deux sens : ce que j'ai accordé, ce qu'on m'a accordé. |
| `DELETE /v1/autorisations/{g}` | Révoque. Effet immédiat. |
| `GET /v1/expositions` | **Ce qui est exposé de MOI**, relation par relation. Tout utilisateur, pas seulement l'administrateur. |
| `DELETE /v1/expositions/{relation}` | **Retire mes enregistrements** de cette exposition. Portée : tout mon compte, ou telle machine. |

### `GET /v1/vu` — d'où l'annuaire voit cette connexion

```jsonc
{"adresse": "2001:db8::1c2d", "port": 49152, "famille": 6}
```

**Elle n'exige rien**, et c'est la cinquième ressource dans ce cas (la sixième est `GET /v1/version`).
Elle ne parle QUE de la connexion qui la pose : rien d'un compte, d'une machine
ou d'un service, et rien qu'un serveur STUN public ne rendrait. Il n'y a pas
d'amplification à craindre — la poignée de main QUIC a déjà prouvé un aller-retour
vers cette adresse, et la réponse est plus courte que la requête.

**Pourquoi elle existe, alors que l'annonce rend déjà cette adresse.** La réponse
à `POST /v1/annonce` porte le candidat réflexif, mais il faut avoir annoncé pour
l'obtenir : avoir la capacité d'annonce, et un service à publier. Une machine de
lecture seule, ou un daemon dont le port n'est pas encore ouvert, n'ont donc aucun
moyen de savoir sous quelle adresse ils sortent — et c'est la première chose qu'on
veut regarder quand personne n'arrive à joindre un port.

Exiger une clé aurait exclu le cas le plus utile : la machine qu'on est en train
d'installer, qui veut savoir si elle atteint l'annuaire et comment il la voit,
avant même d'avoir un code d'enrôlement.

**`famille` est écrite alors qu'elle se déduit de l'adresse**, pour qu'aucune des
cinq liaisons n'ait à la déduire : chercher un `:` marche jusqu'au jour où
quelqu'un rencontre `::ffff:203.0.113.7`.

**Elle ne dit rien du NAT.** Le verdict de NAT se tranche en comparant cette
adresse à celles qu'un daemon ANNONCE, et un appelant qui n'a rien annoncé n'a
rien à comparer. Répondre ici serait affirmer ce qui n'a pas été mesuré.

### `GET /v1/version` — quelle version de l'annuaire répond

```jsonc
{"version": "0.2.0"}
```

**Elle n'exige rien, et c'est la sixième ressource dans ce cas.** Ceux qui ont
besoin de la lire sont précisément ceux qui n'ont pas encore de clé :
l'application qui va créer un compte et veut savoir si l'annuaire sert les
verbes qu'elle emploie, la machine qu'on installe, l'exploitant qui vérifie
qu'un banc sert bien ce qu'il croit. Et elle ne révèle rien qui ne soit déjà
public : ce logiciel est libre, et **chaque PR change sa version**
(`CLAUDE.md`), donc ce nombre nomme exactement un état du dépôt.

**La version, et rien d'autre.** Ni commit, ni posture d'attestation, ni
réglage : ce qu'un annuaire sait de lui-même au-delà de ce nombre est l'affaire
de son exploitant, qui le lit sur la machine avec `asl-server --version`.

**Ce qu'elle promet aux applications : un point de comparaison, pas une
négociation.** Une application qui lit `0.1.0` là où elle attend le verbe de
description (`0.2.0`) peut le dire à son utilisateur plutôt que de journaliser
un `404` ; elle ne demande pas à l'annuaire de parler autrement.

### Ce qu'un jeton de poussée exige, et ce qu'il ne promet pas

**Un appareil ne dépose que pour LUI-MÊME.** Le jeton vient du système du
téléphone qui le porte, et personne d'autre ne l'a ; déposer pour un autre
détournerait ses notifications, c'est-à-dire celles d'un compte vers le téléphone
de qui l'a volé. Viser l'appareil d'un autre rend **`404`**, comme un appareil qui
n'existe pas — le distinguer confirmerait l'existence de l'identifiant visé.

**Un corps mal formé rend `400`**, et non `404` : là, la faute est bien celle de
l'appelant, et il vise son propre appareil.

**Un seul jeton par appareil, et le neuf remplace l'ancien.** Apple et Google font
tourner les leurs ; en garder deux enverrait chaque notification en double, dont
une à un jeton mort — et un jeton mort répété finit par faire retirer le droit
d'en envoyer.

**Le jeton part avec l'appareil qu'on révoque**, dans la même écriture. L'appareil,
lui, reste marqué : l'écran d'après une perte doit montrer ce qu'on a retiré. Le
jeton n'a rien à montrer.

**L'annuaire ne lit pas le jeton.** Ni sa forme, ni sa longueur attendue : c'est
une chaîne opaque, et le seul juge de sa validité est le service qui l'a émis. Ce
qui est exigé ne porte pas sur le sens — de l'ASCII imprimable, non vide, et au
plus 255 octets, qui est ce qu'une longueur sur un octet permet. Un jeton vide
n'est pas un retrait déguisé ; **il n'y a pas de verbe de retrait**, et un
appareil qui n'en veut plus est un appareil qu'on révoque.

**Et l'ENVOI n'est pas écrit.** Ce verbe range le jeton ; rien ne s'en sert
encore. Le dire ici est plus honnête que de laisser croire qu'une notification
part parce que l'application a réussi son dépôt.

### Ce qu'une description d'appareil est, et ce qu'elle n'est pas

```jsonc
PUT /v1/appareils/{a}/description
{"plateforme": "macos", "modele": "MacBook Pro (2019)"}
```

**Une étiquette que l'appareil se pose lui-même, pas une preuve.** L'annuaire
ne vérifie rien de ce qu'elle dit ; ce qui identifie un appareil est son `a-…`
(`modele.md` §2.2). Elle existe pour un écran : celui qu'on regarde pour
vérifier qu'aucun appareil de trop n'est entré, et qui montrait le Mac comme
« Autre » parce qu'il ne savait rien d'autre de lui que `attestation: "aucune"`.

**Chaque appareil la pose juste après sa preuve**, et la repose quand elle
change. `GET /v1/appareils` rend les deux champs tels quels, et les OMET tant
qu'ils n'ont pas été posés — absents, jamais vides ni faux.

**Pour soi seulement, exactement comme le jeton** : viser l'appareil d'un autre
rend le `404` d'un appareil qui n'existe pas. La raison est moins grave —
décrire l'appareil d'un autre ne détourne rien — mais une seule règle pour les
deux verbes est plus simple à tenir qu'une exception, et c'est bien l'appareil
qui parle de lui, sur sa propre connexion. **Un corps mal formé rend `400`**,
et le corps ne connaît que ces deux champs : un `nom` est un champ inconnu.

**`plateforme` est une liste fermée** — `ios`, `android`, `macos`, les trois
applications de ce produit. **`modele` est du texte libre**, aux règles exactes
du nom d'une machine (`modele.md` §2.3) : 1 à 64 octets, tout l'UTF-8, sans
échappement, sans contrôle, sans forceur de sens d'écriture. C'est le nom du
MODÈLE — « iPhone 17 » —, et jamais le nom que l'utilisateur a donné à son
téléphone : « iPhone de Thierry » porte un prénom, et l'application ne l'envoie
pas.

**Elle reste quand l'appareil est révoqué**, à l'inverse du jeton : l'écran
d'après une perte doit montrer ce qu'on a retiré, et « iPhone 17, révoqué » le
dit mieux que « Autre, révoqué ». Elle ne donne aucun droit, donc rien ne presse
de l'effacer.

### Effacer mon compte — le dernier acte d'une clé

```
DELETE /v1/compte
        (sur la voie appareil, signé par un appareil vivant du compte ;
         sans corps)

        → 204, sans corps ; puis l'annuaire ferme la connexion
```

**Décidé le 2026-09-18** ; le fond — pourquoi c'est un geste du titulaire, ce
qui part, ce qui reste, la règle des orphelins — est dans `modele.md` §2.1.
Ce qui tient ici est ce qui se voit sur le fil.

**`/v1/compte`, au singulier, et non `/v1/moi` ni `/v1/comptes/{u}`.** La
grammaire de cette voie ne nomme jamais le compte : `/v1/alias` est *mon*
alias, `/v1/appareils` *mes* appareils, `/v1/machines` *mes* machines — la
connexion désigne le compte, et rien dans le chemin ne peut le contredire.
`/v1/compte` est *mon* compte, de la même façon. `/v1/comptes/{u}` aurait
obligé l'appelant à se nommer, et l'annuaire à répondre quelque chose quand
`{u}` n'est pas lui — un `404` de plus à justifier, pour un cas qui n'a aucune
raison d'exister. Et `/v1/moi` est déjà pris : c'est une ressource de la **voie
machine** (`Exigence::Machine`, §3), et **l'exigence est une propriété de la
ressource, pas du verbe** — une ressource qui exigerait une machine en `GET` et
un appareil en `DELETE` serait la première du genre, et une machine ne décide
pas du compte. Deux voies, deux ressources.

**Il ne porte pas de corps, et il n'y a rien à confirmer côté protocole.** La
confirmation est le geste biométrique qui débloque la clé — c'est ce que
« sous biométrie » veut dire ici (`modele.md` §5) —, et le texte qui dit ce qui
va partir est l'affaire de l'application, avant qu'elle signe. Un champ
`{"confirme": true}` serait un booléen que le client transporte, précisément
ce que C7 refuse de croire.

**Ce qu'il fait, dans UNE transaction, puis ce qu'il ferme.** L'entrepôt
révoque tous les appareils du compte — **celui qui demande compris** —, efface
leurs enregistrements, jetons et descriptions ; révoque les clés de toutes ses
machines, annule leurs codes d'enrôlement en cours, efface les machines et
leurs services ; efface les autorisations dans les deux sens ; retire la
réclamation d'alias ; marque le compte effacé, avec la date et la cause
`titulaire`. Puis, comme pour toute révocation (§2.1 quater), l'annuaire
**ferme les connexions** de tout ce qui vient d'être révoqué : les machines du
compte — leurs baux tombent par le chemin ordinaire d'un départ —, ses autres
appareils, et **la connexion qui a porté la demande**, au tour de boucle
suivant le `204`. L'application n'a rien à fermer elle-même ; elle lit `204`,
puis la connexion tombe, et c'est l'ordre attendu.

**Les réponses, et il n'y en a que deux.** `204` : c'est fait. `401` : la clé
qui signe n'est pas celle d'un appareil vivant — révoqué, ou d'un compte déjà
effacé. Il n'y a pas de `404` : la ressource est le compte de la connexion, et
une connexion authentifiée a toujours un compte. Un second `DELETE` après le
premier ne peut pas arriver sur la même connexion (elle est fermée), et sur
une nouvelle il rend `401`, puisque la clé est révoquée : **l'effacement est
idempotent par construction**, sans qu'il y ait à l'écrire.

**Ce que l'autre partie d'une autorisation voit : plus rien.** La ligne quitte
`GET /v1/autorisations` chez celui qui avait accordé comme chez celui qui avait
reçu ; ses machines `lecture` ne résolvent plus rien de ce compte, à la
seconde, sans qu'aucune connexion ait à être fermée chez lui (la résolution
relit l'entrepôt, §2.1 quater). `GET /v1/utilisateurs/{u}` sur l'identifiant
effacé rend `404` — le même `404` qu'un identifiant qui n'a jamais existé :
l'existence passée d'un compte n'est pas une information qu'on rend à qui
tient un `u-…` au hasard. **Aucune notification ne part** : « vous a retiré
l'accès » n'existe pas pour une révocation ordinaire, et n'existe pas
davantage ici.

**Et `GET /v1/alias/{alias}` rend le nouveau titulaire, ou `404`.** L'alias est
libéré dans la transaction ; s'il était réclamé en file par un autre compte,
c'est lui que la résolution rend désormais (`replication.md` §3.2).

**Sur la voie machine, rien.** Une machine ne décide pas du compte
(`modele.md` §2.3) ; `asl` n'a pas de verbe pour ça, et n'en aura pas. Ce
qu'une machine voit d'un effacement est le sien : sa connexion fermée, puis
`401` à la suivante — exactement ce qu'elle voit d'une révocation de clé, et
elle n'a pas à distinguer les deux.

**L'effacement automatique et le verbe d'exploitant passent par le même
chemin d'entrepôt** — la règle des orphelins (`--orphans`, `modele.md` §2.1)
et `asl-server --forget <u-…>` écrivent la même opération, avec leur cause,
et produisent les mêmes effets vivants. Il n'y a qu'une façon d'effacer un
compte ; ce qui change est qui l'a voulu, et c'est dit dans la cause.

### Émettre une invitation — le seul secret que l'exploitant tient

```
POST /v1/invitations
        (sans exigence préalable — c'est le corps qui prouve, comme
         POST /v1/attestation ; sur la connexion où GET /v1/defi a été tiré)

        corps = genre `o` ‖ signature (64)                          65 octets

        → 200, `{"code":"4K9M2-P7R1T","expire_a":1790000000000}`
          le code EN CLAIR, une seule fois, et jamais rendu ensuite
```

**Décidé le 2026-09-24.** La posture `invitation` était écrite depuis le
2026-09-16 (§2.1) — un code que l'exploitant émet, présenté sous la
plate-forme `3` — mais le geste d'émission restait en suspens, et sans lui la
posture n'était pas servable : la plate-forme `3` refusait « pas encore
servie ». Voici ce geste, et ce qu'il a coûté de trancher.

**Pourquoi un verbe, et pas un outil hors ligne.** `asl-server --forget` est
le précédent commode : un sous-verbe du binaire, sur la machine, qui ouvre
l'entrepôt et écrit. Mais l'entrepôt n'admet **qu'un seul écrivain** — c'est
un fichier redb, tenu par le processus qui sert —, et `--forget` exige pour
cette raison que le service soit **arrêté** (décision 24). Effacer un compte
dont la clé est perdue est un geste rare, et l'arrêt s'y paie une fois.
Émettre une invitation est le geste **ordinaire** d'une racine qui tourne en
`invitation` : c'est ainsi que ses utilisateurs entrent. Arrêter l'annuaire
pour laisser entrer quelqu'un ferait tomber toutes les annonces en cours
(§1.2 : la connexion EST le bail) à chaque nouvel arrivant. Un mécanisme dont
le coût croît avec le succès n'est pas un mécanisme.

**Pourquoi un code rangé, et pas un code qui se vérifie seul.** L'envie est
naturelle : un code qui porterait sa propre signature — de la clé d'identité
de la racine — se vérifierait sans que rien soit écrit à l'émission, donc sans
annuaire en marche. **La forme l'interdit, et ce n'est pas un détail de
place.** Le code fait dix symboles de Crockford, cinquante bits, dix octets
dans la case d'attestation ; une signature Ed25519 en fait soixante-quatre.
Un code auto-porteur serait un code qu'on ne recopie plus à la main, et l'on
perdrait ce qui fait qu'une invitation se transmet par un canal ordinaire —
un message, un appel, un bout de papier. Et l'usage unique y resterait
impossible : une signature se vérifie autant de fois qu'on veut. **Un secret
court et à usage unique impose un état ; la seule question est où il s'écrit,
et la réponse est : là où l'annuaire écrit déjà.**

**Pourquoi une clé d'exploitation, et pas un compte d'exploitation.**
Réserver le verbe à un compte privilégié aurait introduit dans le modèle une
chose qu'il n'a pas : un `u-…` qui vaut plus que les autres. Tout le produit
tient sur l'inverse — un compte est un jeu d'appareils enrôlés, et aucun ne
commande à l'annuaire. **La caution de l'exploitant n'est pas un compte,
c'est la machine** : il tient `/etc/asl-server/`, la clé d'identité de la
racine, l'unité de service. Une clé de plus dans ce même dossier, déclarée
par un réglage, dit exactement cela sans rien ajouter au modèle — et c'est
déjà la forme de `--peer-key` (`replication.md` §2.2), qui autorise l'autre
racine sans lui donner de compte non plus.

| Réglage | Ce qu'il fait |
|---|---|
| `--operator-key <fichier>` | La clé publique Ed25519 dont la signature ouvre `POST /v1/invitations`. **Sans elle, la ressource n'existe pas** : `404`, comme toute ressource inconnue — une racine qui n'invite pas n'expose pas de porte close. |
| `--invitation-ttl <durée>` | Ce que vit un code émis. **Vingt-quatre heures par défaut**, une semaine au plus. |

**`--attestation invitation` sans `--operator-key` refuse de démarrer**, et le
message le nomme : une racine qui exige une invitation sans pouvoir en émettre
est une racine où personne n'entre jamais. C'est la même règle que
`--attestation` sans valeur (README) — un service voué à échouer ne démarre
pas.

**Le genre `o`, et pourquoi il ne passe pas par `POST /v1/defi`.** La clé
d'exploitation se prouve comme les autres — une signature sur
`genre ‖ défi ‖ liaison` (§2.1 bis), le défi tiré par `GET /v1/defi` sur cette
connexion — mais **sans identifiant** : le corps de `POST /v1/defi` en exige
un de dix-sept octets, et il n'existe pas de `o-…`. Il n'y en a pas besoin, et
c'est déjà l'argument de l'exigence `Racine` : **il n'y a qu'une clé qui
satisfasse celle-ci, celle de `--operator-key`** — la nommer serait se
répéter, et inventer un identifiant pour une clé unique ferait entrer
l'exploitant dans le modèle par une porte dérobée. La preuve voyage donc dans
le corps du verbe lui-même, comme celle de `POST /v1/attestation`, et le défi
est dépensé qu'elle tienne ou non.

**Qui parle ce verbe.** `asl-server --invite --directory <hôte:port> --ca
<racine.crt> --operator-secret <fichier>`, et `asl-server --new-operator-key`
frappe la paire (2026-09-24). **Le même binaire, et non `asl`** : `asl` est
l'utilitaire d'une MACHINE — il s'enrôle, annonce, résout —, et émettre une
invitation n'est aucun de ces gestes ; lui donner ce verbe aurait fait entrer
l'exploitant dans la grammaire d'un daemon. Un binaire séparé, lui, aurait
redemandé la même pile QUIC, la même racine épinglée et le même conducteur
HTTP/3 que la voie entre racines porte déjà (`replication.md` §2.1) — deux
clients à maintenir, dont le second aurait vieilli. `asl-server` avait déjà
deux gestes qui ne servent pas (`--new-identity-key`, `--forget`) ; celui-ci
est le troisième, et le seul qui parle à un annuaire EN MARCHE. **Il n'a rien
à faire sur un banc** : c'est un exécutable autonome, qu'on copie là où vit la
moitié privée de la clé.

**Ce que cette clé ne donne pas.** Elle n'ouvre **que** cette ressource : elle
ne lit aucun compte, n'en révoque aucun, n'efface rien. Ce qu'un exploitant
peut faire de destructif, il le fait déjà hors ligne, service arrêté, et c'est
très bien ainsi. Une clé qui ouvre une porte ne doit pas ouvrir la maison —
et celle-ci, si elle fuit, ne coûte que des invitations, qu'on cesse d'honorer
en changeant le réglage.

**Vingt-quatre heures, et pourquoi pas dix minutes.** Un code d'enrôlement de
machine vaut dix minutes (`modele.md` §2.3) parce que l'humain qui le tape est
devant les deux écrans : il le lit sur son téléphone et le saisit sur sa
machine. Une invitation ne se consomme pas devant son émetteur — elle
s'envoie, et l'invité l'utilisera ce soir ou demain. Dix minutes en feraient
un rendez-vous ; une semaine au plus en borne la portée. **Ce que cela coûte
est écrit plus bas** : cinquante bits qui vivent un jour ne se défendent que
si l'annuaire limite le débit.

**Ce que l'annuaire garde, et ce qu'il ne garde pas.** L'empreinte du code
(SHA-256, domaine séparé), sa date d'expiration, l'estampille de son émission.
**Jamais le code.** C'est déjà la règle des codes d'enrôlement (C14) et elle
vaut pour la même raison : une base qui fuirait ne livrerait aucune entrée. Le
code en clair n'existe que dans la réponse au verbe, une fois — l'annuaire ne
sait pas le redire, et un exploitant qui le perd en émet un autre.

#### Ce que `POST /v1/comptes` fait d'une plate-forme `3`

L'ordre est celui de la plate-forme `2` (§2.1), et pour la même raison — rien
ne s'écrit avant que tout soit jugé :

1. la preuve de possession de la clé de l'appareil, comme toujours ;
2. l'empreinte du code présenté est cherchée ; absente, expirée ou déjà
   consommée, c'est **`403`** — le même refus pour les trois, et l'annuaire ne
   dit pas lequel, exactement comme `POST /v1/defi` ne dit pas pourquoi une
   preuve échoue. Distinguer « ce code n'existe pas » de « ce code a servi »
   dirait à qui essaie des codes lesquels ont existé ;
3. dans **une transaction** : le compte est créé, l'appareil enrôlé avec
   l'attestation `invitation`, et **l'empreinte du code supprimée**. Consommer,
   c'est supprimer — la règle des codes d'enrôlement, et la seule qui tienne
   l'usage unique sans horloge.

`400` si le corps est mal formé — plate-forme `3` sans les dix octets, ou avec
autre chose que dix. Sous une posture qui n'est **pas** `invitation`, une
plate-forme `3` reste refusée : une racine qui n'invite pas n'a pas de code à
reconnaître.

#### Cinquante bits qui vivent un jour, et la limite de débit

`modele.md` §2.3 le note déjà pour le code d'enrôlement : cinquante bits ne se
devinent pas, « cela ne dispense pas de limiter le débit, et cette limite-là
n'est pas encore écrite ». Sous la posture `invitation`, elle **doit** l'être,
et c'est ici la seule nouveauté de sécurité : c'est la première fois qu'un
secret court, seul, garde **l'entrée du service** — ailleurs il ne fait que
lier une clé à une machine déjà déclarée.

**La règle : cinq échecs de `POST /v1/comptes` sous plate-forme `3` par
minute et par adresse observée** (celle de §2.2, `GET /v1/vu`), puis `429`
avec `retry-after`. Le seuil est haut pour un humain qui se trompe en
recopiant, et dérisoire pour qui cherche : à cinq essais la minute, épuiser
cinquante bits demande plus de temps que l'univers n'en a. Les succès ne
comptent pas — un code qui marche ne se retente pas. Chaque refus est dit au
journal d'exploitation avec l'adresse, jamais avec le code ni son empreinte.

#### Deux racines, un seul code — la fenêtre, et ce qu'on n'en fait pas

Les invitations se répliquent, **comme les codes d'enrôlement et pour la même
raison** (`replication.md` §1) : l'alias donne une racine au hasard, et un code
qui ne vaudrait que chez celle qui l'a émis serait inconnu une fois sur deux.
C'est l'empreinte qui circule, jamais le code.

Il en découle la même fenêtre qu'en §3.2 : entre la consommation chez l'une et
son arrivée chez l'autre — moins d'une seconde en marche normale —, l'autre ne
peut pas refuser ce qu'elle ne sait pas. **Mais la conséquence diffère, et
c'est ce qui a demandé à trancher.** Un code d'enrôlement consommé deux fois
donne deux clés pour une machine, et il faut départager : le dépôt le fait (le
code le plus récemment émis, puis la première consommation). Une invitation
consommée deux fois donne **deux comptes** — et deux comptes ne se départagent
pas : ils ne se gênent pas, ne se disputent rien, et chacun porte l'appareil
de celui qui l'a ouvert.

**On ne les départage donc pas.** L'annuaire ne choisit pas un compte à
effacer : un effacement automatique déclenché par une course serait une arme,
et il n'existe aucune règle honnête pour désigner le perdant — le second
arrivé a fait exactement ce qu'on lui avait dit de faire. **Les deux vivent, et
le journal dit que le même code a été consommé deux fois**, avec les deux
`u-…`. L'exploitant tranche s'il veut trancher ; `asl-server --forget` est là
pour cela, hors ligne, sur décision d'un humain (décision 24).

Ce que cela coûte est borné et se dit en une phrase : **une invitation garantit
qu'on entre parce que l'exploitant l'a voulu, pas qu'on entre une fois et une
seule.** L'usage unique tient par racine et au-delà de la seconde qui sépare
les deux ; il ne tient pas dans cette seconde-là. Pour qu'il y ait deux
comptes, il faut que le même code soit présenté deux fois dans cet intervalle
— une faute, ou un code intercepté ; et dans ce second cas, celui qui l'a
intercepté aurait de toute façon obtenu un compte en arrivant le premier.

### Attester un appareil qui rejoint — la preuve et la chaîne, d'un même défi

```
POST /v1/attestation
        (sans aucune authentification préalable — c'est elle, la preuve ;
         sur la connexion où GET /v1/defi a été tiré AVANT de générer la clé)

        corps = genre `a` ‖ a-… (17) ‖ signature (64) ‖ plate-forme (1)
                ‖ attestation (0…8 Kio)

        → 204, sans corps ; la connexion est désormais celle de cet appareil
```

**Décidé le 2026-09-21.** Le premier appareil d'un compte entre attesté
(`POST /v1/comptes`, §2.1) ; **le second n'avait aucun moyen de l'être**, et
c'est un trou que l'essai réel du 2026-09-17 a montré : le Fairphone 5 a
ouvert un compte neuf sous l'attestation `android`, puis a rejoint le compte
du Mac — et y est entré `aucune`. `POST /v1/appareils` ne porte que la clé
(33 octets, §2.1 bis) : pas de place pour une chaîne. Et l'y mettre n'aurait
rien résolu, pour une raison qui tient à ce qu'est une attestation de clé.

**Pourquoi ce n'est pas l'ancien appareil qui apporte la chaîne.** Une chaîne
du Keystore est liée à un défi **posé à la génération de la clé**
(`setAttestationChallenge`, §2.1) ; ce défi est tiré sur une connexion et lié
à elle par la liaison de canal. La connexion qui a tiré le défi est celle du
NOUVEL appareil — c'est lui qui a généré la clé —, et l'ancien n'en sait rien :
lui apporter la chaîne, c'est lui faire porter une preuve qui parle d'un canal
qui n'est pas le sien, et que l'annuaire ne pourrait rapprocher de rien. La
règle de §2.1 ter tient donc telle quelle, et se complète d'une phrase :
**celui qui PRÉSENTE une clé signe qu'il la détient ; celui pour qui un tiers
l'apporte ne signe pas — et c'est quand il signe enfin, sur sa propre
connexion, que sa chaîne a un sens.** L'attestation s'attache à la preuve du
nouveau, pas à l'apport de l'ancien.

**L'ordre, côté nouvel appareil, et il ne se négocie pas.** Se connecter nu ;
tirer le défi (`GET /v1/defi`) ; composer
`asl_cle::message_d_attestation_de_cle(défi, liaison)` ; **GÉNÉRER la clé**
avec son condensat pour défi d'attestation — exactement l'ordre de
`POST /v1/comptes`, et pour la même raison : le défi doit exister avant la
clé ; **montrer la clé** à l'ancien appareil (`modele.md` §2.2) ; attendre
qu'il l'ait présentée (`POST /v1/appareils`, sur SA connexion) et lui ait
rendu `u-…` et `a-…` ; puis, **sur la connexion tenue depuis le début**,
`POST /v1/attestation` : la signature ordinaire du genre `a` — `genre ‖
identifiant ‖ défi ‖ liaison`, celle de `POST /v1/defi` —, suivie de la
plate-forme et de la chaîne. Un seul défi, tiré une fois, dépensé une fois :
il couvre la preuve ET l'attestation, comme il le fait à la création d'un
compte. Ce que l'annuaire vérifie est ce qu'il vérifie déjà en §2.1 —
`asl-keystore`, contre `--android-roots`, le défi égal à
`SHA-256(message_d_attestation_de_cle)`, la clé de la feuille égale à la clé
rangée pour `a-…`, notre paquet sous notre empreinte — plus une chose : que
la clé rangée pour `a-…` soit bien celle qui signe. Deux vérifications, une
transaction : l'attestation ne se pose que si la preuve tient, et la preuve
n'est retenue que si l'attestation est jugée — jugée, non acceptée : en
posture facultative, une chaîne refusée laisse l'appareil `aucune` et la
connexion authentifiée quand même (voir la table).

**Pourquoi un verbe à part, et non `POST /v1/defi` allongé.** `POST /v1/defi`
sert trois genres — machine, appareil, racine — et fait 81 octets pour les
trois ; lui donner une queue variable pour le seul genre `a` ferait d'un corps
à longueur fixe un corps qui l'est parfois. `POST /v1/comptes` est le
précédent : la preuve d'une clé et sa chaîne, dans un verbe à elles.
`/v1/attestation`, au singulier, comme `/v1/compte` et `/v1/alias` : *mon*
attestation, celle de la clé qui signe, et rien dans le chemin ne nomme
l'appareil deux fois. Pas `PUT /v1/appareils/{a}/attestation` : une
attestation ne se remplace pas — une clé est attestée à sa génération, une
fois, et la chaîne ne vaut que sur la connexion qui a tiré son défi.

**Le défi vit ce que vit la connexion, et c'est la seule durée.** Il n'y a
pas de délai à part : un défi est tenu par la connexion qui l'a tiré, un seul
à la fois, remplacé par le suivant, consommé par la preuve — qu'elle tienne
ou non. La connexion, elle, est tenue par l'application (keepalive à 10 s,
§1.2), le temps que l'humain passe d'un écran à une caméra et revienne. Ce
que cela impose à l'application est dit en clair : **si la connexion tombe
entre le code montré et la preuve, la clé générée ne s'attestera plus
jamais** — son défi est mort avec le canal. L'application recommence alors du
début : nouvelle connexion, nouveau défi, **nouvelle clé**, nouveau code à
montrer ; l'ancien appareil représente la nouvelle clé, et le premier `a-…`
reste dans le compte — `aucune` ou `attendue`, jamais prouvé — jusqu'à ce que
son titulaire le révoque depuis l'écran Appareils. C'est le prix de lier la
chaîne au canal, et il est accepté : un défi qui survivrait à sa connexion
serait un état à garder, à expirer et à répliquer, pour éviter une révocation
à la main dans un cas qui ne se produit qu'à la coupure.

**Ce que la posture change, et la valeur `attendue`.** L'attestation qualifie
l'entrée d'un appareil (C19), et **un appareil qui rejoint entre quand il
prouve**, pas quand on l'apporte :

| Posture | `POST /v1/appareils` écrit | `POST /v1/defi` (genre `a`, sans chaîne) | `POST /v1/attestation` |
|---|---|---|---|
| `optional` | `aucune` — l'annuaire admet des appareils sans preuve, et c'est une entrée légitime, comme aujourd'hui | Sert ; l'appareil reste `aucune` | Chaîne acceptée : `aucune` → `android` \| `apple`, `204`. Chaîne refusée : **`204` quand même**, l'appareil reste `aucune`, le refus est journalisé — c'est ce que la posture promet, et ce que l'application 0.5.0 obtenait déjà à la création en retentant sans chaîne |
| `required` | **`attendue`** — une clé apportée, que personne n'a encore prouvée ni attestée ; rien d'unattesté n'est vivant sous cette posture | **`401`** tant que l'appareil est `attendue` — la même réponse qu'une clé révoquée : il n'est pas vivant | Chaîne acceptée : `attendue` → `android` \| `apple`, `204`, l'appareil est vivant. Chaîne refusée : **`403`**, l'appareil reste `attendue`, la connexion n'est pas authentifiée ; le journal dit pourquoi |
| `invitation` | `aucune` — l'invitation vaut pour ouvrir un compte ; un appareil qui rejoint est voulu par un appareil du compte, et c'est la seule caution que cette posture connaît | Sert ; `aucune` | Comme `optional` — une racine sans fabricant dans sa boucle n'a pas de racine à opposer à la chaîne, et ne la juge pas |

`attendue` est une **cinquième valeur d'`attestation`** (`modele.md` §2.2),
et non un drapeau à part : c'est bien « sous quoi l'appareil est entré » —
il n'est pas entré. Elle se voit dans `GET /v1/appareils` et
`GET /v1/moi/appareils` comme les autres, et l'écran la dit (« en attente
d'attestation ») ; un appareil `attendue` se révoque comme un autre, et compte
comme vivant pour la règle des orphelins tant qu'il ne l'est pas — un compte
dont le seul appareil non révoqué est `attendue` n'est pas orphelin, il est
en train de rejoindre. **Elle ne s'expire pas** : un enregistrement qui
partirait de lui-même serait la troisième exception à « marqué, jamais
effacé » (`replication.md` §5.2), pour un cas que l'écran Appareils montre et
qu'un geste règle. Un appareil `aucune` d'aujourd'hui, sur une racine passée
en `required`, reste servi : la posture qualifie l'entrée, jamais ce qui est
déjà entré (C19).

**Ce qu'`attendue` ne fait pas.** Il ne s'agit pas d'exiger une chaîne en
posture facultative : `aucune` y reste une entrée entière, et une application
d'aujourd'hui (Android 0.6.0, iOS 0.7.0) rejoint une racine `optional` ou
`invitation` exactement comme hier — `POST /v1/appareils`, puis
`POST /v1/defi`. Sur une racine `required`, elle obtient `201` à l'apport et
`401` à la preuve, là où elle obtenait `403` à l'apport ; l'ancien appareil
verra un appareil « en attente » et pourra le révoquer. Ce n'est pas mieux
que le refus franc, et ce n'est pas pire : aucune racine ne tourne en
`required` aujourd'hui, et aucune ne le fera avant que les applications
présentent leur chaîne.

**Les réponses.** `204` : la preuve tient, la connexion est celle de `a-…`,
et l'attestation est ce que la table dit. `401` : la signature ne vérifie pas
contre la clé rangée pour `a-…`, ou il n'y a pas de défi sur cette connexion,
ou l'appareil est révoqué, ou son compte effacé — **le même `401` pour les
quatre**, comme `POST /v1/defi`, et pour la même raison : distinguer dirait à
qui essaie des identifiants lesquels existent. `403` : la preuve tient, la
chaîne ne prouve rien, et la posture l'exige — la connexion n'est pas
authentifiée, le défi est dépensé, et cette clé ne s'attestera plus : c'est
le cas de la coupure, et la sortie est la même — nouvelle clé, nouveau code,
l'appareil `attendue` à révoquer. `400` : le corps est mal
formé — genre autre que `a`, plate-forme inconnue, plate-forme `0` avec une
chaîne derrière ou `1`/`2` sans. `409` : l'appareil est déjà attesté — il
n'existe pas : une clé attestée est une clé prouvée sur la connexion de son
défi, et ce défi est dépensé ; un second `POST /v1/attestation` sur la même
connexion rend `401` (pas de défi), sur une autre aussi (la chaîne ne
correspond à aucun défi de celle-ci). Il n'y a donc rien à écrire pour
l'idempotence, et c'est l'argument de « Effacer mon compte » à nouveau.

**Sur la voie machine, rien**, et sur la réplication, une opération :
`appareil-atteste` (identifiant ‖ attestation), qui ne va que dans un sens —
d'`aucune` ou `attendue` vers une valeur prouvée — et s'applique toujours,
révoqué ou non (`replication.md` §3.2, §5.2, décision 25). Une racine passe
un appareil d'`attendue` à vivant en appliquant l'opération de l'autre, et
c'est ce qui rend le geste possible quand les deux téléphones parlent à deux
racines : l'ancien apporte la clé chez `nitrogen`, le nouveau prouve chez
`argon` — l'opération `appareil` a traversé en moins d'une seconde, et la
chaîne remonte dans l'autre sens.

**App Attest y passe aussi**, sous la plate-forme `1`, avec le message qui
contient la clé (`asl_cle::message_d_attestation`) : l'enclave génère la clé
quand elle veut, et App Attest atteste une clé à lui sur un défi qui nomme la
nôtre — l'ordre « défi avant clé » n'est une contrainte que du Keystore. Rien
n'est éprouvé côté Apple, comme pour la création : le même iPhone manque.

### Ce qu'un `PATCH` change, et ce qu'il ferme

**Ce qui est absent ne change pas, et le tableau vide RETIRE.** `{"capacites":
[]}` laisse une machine déclarée qui ne peut plus rien — un état légitime —,
tandis que l'absence du champ laisse les capacités telles quelles. Il n'y a pas de
troisième forme : un `null` serait un sens de plus, à mi-chemin entre « laisse »
et « aucune », qu'il faudrait ensuite trancher partout.

**`{}` rend `400`, alors que c'est du JSON valide.** Personne ne l'envoie
exprès : ce qui le produit est un champ mal orthographié ou une variable vide
côté appelant. Rendre `204` à une requête qui n'a rien changé laisserait l'humain
regarder un nom inchangé en cherchant sa faute partout sauf là où elle est.

**Retirer la capacité d'annonce ferme les connexions de cette machine**, et fait
donc tomber ses baux — le même effet immédiat que `DELETE
/v1/machines/{m}/cle`, et pour la même raison : une capacité retirée qui
laisserait courir les baux déjà posés ne retirerait rien, et l'annuaire
continuerait de publier les adresses d'une machine à qui l'on vient d'interdire
d'annoncer.

**Retirer la LECTURE ne ferme rien.** Une machine qui ne peut plus interroger
l'annuaire n'a rien laissé derrière elle : sa prochaine requête sera refusée, et
il n'y a pas d'état à défaire. Renommer ne ferme rien non plus — un nom ne
retire aucun droit.

### Ce qu'une liste rend, et ce qu'elle ne dit pas

**Une liste vide est un `200` et un tableau vide, jamais un `404`.** « Je n'ai
rien à te montrer » et « cette ressource n'existe pas » ne se corrigent pas au
même endroit, et un client qui lirait `404` là où il devait lire `[]` croirait son
appel fautif.

**Une liste OMET ce qu'on n'a pas le droit de voir, et l'omission ne dit rien de
ce qu'elle omet.** C'est le pendant du `404` de `GET /v1/ou/{m}/{s}`, qui ne
distingue pas « absent » de « interdit » : ici, il n'y a rien à distinguer,
puisque rien ne paraît. Personne ne peut compter ce qui manque.

**`GET /v1/ou?service=` et `GET /v1/machines/{m}/services` rendent les mêmes
objets que la forme par machine**, répétés dans un tableau. Une forme propre aux
listes aurait demandé un second décodeur, écrit cinq fois dans les cinq liaisons.

**Une liste porte au plus soixante-quatre éléments, et au-delà c'est `500`.**
Jamais une liste tronquée : elle mentirait par omission, et le demandeur croirait
avoir tout vu. `500` est le mot juste — le demandeur n'a rien fait de mal, c'est
l'annuaire qui a plus à dire que ce protocole ne sait exprimer, et la réponse est
une **pagination à concevoir**, pas un réessai.

**`GET /v1/machines/{m}/services` ne regarde aucune autorisation.** C'est l'écran
qui montre MES machines ; les chemins inter-comptes sont `GET /v1/ou` pour les
services et `GET /v1/utilisateurs/{u}/machines` pour les machines — chacun
calculé depuis les arêtes du demandeur, jamais depuis ce qu'il désigne (C10).

### Les machines d'un utilisateur — ce qu'une autorisation donne à voir

```jsonc
GET /v1/utilisateurs/{u}/machines
[{"machine": "m-…", "nom": "grenier"}, {"machine": "m-…", "nom": "nas"}]
```

**Une autorisation de portée « tout le compte » donne la liste entière des
machines de celui qui l'a accordée** — identifiant et nom, rien d'autre : ni
capacités, ni clé, ni code, qui n'appartiennent qu'au propriétaire. Une portée
« une machine » ne rend que celle-là ; « un service », celle qui le porte.
`u` égal au demandeur rend ses propres machines, comme `GET /v1/machines` mais
sous la même forme. **Sans aucune arête entre `u` et le demandeur, la liste est
vide** — vide, pas `403` ni `404` : un tiers qui interroge un compte qui ne lui
a rien accordé n'apprend rien, et n'apprend pas non plus qu'il n'a rien, après
le même délai (C9). Il sait déjà que `u` existe, par le booléen ; il ne saura
rien de plus.

C'est une décision de produit qui tranche contre une prudence antérieure, et
`modele.md` §2.5 en porte la raison : un `m-…` est public par construction,
et un bénéficiaire à qui l'on a dit « tout » n'a pas à deviner. **Ce qu'elle
coûte est dit à celui qui accorde**, au moment d'accorder : « tout le compte »
livre aussi la liste de ses machines.

**`GET /v1/autorisations` rend un seul tableau pour les deux sens**, et y laisse
les révoquées, marquées. `par` et `a` disent de quel côté chacune est, et un
lecteur qui connaît son identifiant sait lequel il est ; deux tableaux auraient
obligé l'application à savoir dans lequel chercher. Taire les révoquées ferait
douter d'avoir cliqué — même raison qu'un appareil révoqué, qui est marqué et non
effacé.

**Les deux verbes d'exposition rendent `501`, et c'est exact.** Ils supposent ce
qui n'est pas écrit : la table des relations avec les pairs, et la trace de ce qui
a été répliqué vers chacun. `annuaires.md` est le moins avancé des quatre
documents, et ces deux verbes en dépendent entièrement — les écrire aujourd'hui
demanderait d'inventer un modèle de relation que la fédération devrait ensuite
défaire. Rendre un tableau vide serait pire que `501` : il dirait « rien de vous
n'est exposé » là où la vérité est « l'annuaire ne sait pas encore le dire ».

Les verbes d'administration d'une exposition — ce que l'annuaire expose à un pair,
et ce qu'il en prend — sont réservés à l'administrateur de l'annuaire et ne
figurent pas ici : ils relèvent de son exploitation, pas de l'application mobile.
**Les deux verbes ci-dessus, si.** Ils sont ce qui rend le retrait effectif, et un
droit de retrait sans écran est une mention dans un document.

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

```
GET /v1/moi
{"machine": "m-…", "proprietaire": "u-…"}
```

**Une machine peut demander qui elle est et à qui elle appartient**, sur sa
connexion authentifiée, sans rien d'autre. Les deux identifiants sont publics ;
ce que la réponse prouve est que l'annuaire tient bien cette clé pour cette
machine de ce compte. C'est ce qu'`asl diagnose` affiche, et ce qui remplit
le fichier d'identité d'une machine enrôlée avant que l'enrôlement ne rende le
propriétaire (§2.0).

**La voie machine sert aussi `GET /v1/ou?service=` — toutes les instances d'un
nom que le propriétaire a le droit de voir — et `GET /v1/utilisateurs/{u}/machines`**
(§2.2), avec la même règle : calculé depuis les arêtes du propriétaire de la
machine qui demande. C'est ce qui permet à un programme de B de partir d'un
`u-…` que A lui a donné et d'arriver à un port, sans qu'un humain ait à
recopier des `m-…`.

```
GET /v1/moi/appareils
[{"appareil": "a-…", "attestation": "aucune", "revoque": false,
  "plateforme": "macos", "modele": "MacBookPro15,2"}]
```

**Une machine peut voir les appareils du compte qui la possède** — la même
liste que `GET /v1/appareils` rend à un appareil, révoqués compris et marqués,
avec la description quand elle a été posée — **et rien faire dessus.** C'est
une décision de produit, et elle abaisse à dessein la frontière entre les deux
rôles : l'administrateur d'une machine, dans un terminal, doit pouvoir répondre
à « quels appareils administrent ce compte ? » sans sortir un téléphone — c'est
`asl enrolled`. Ce qu'elle coûte est dit : une clé de machine compromise, qui
signe sans témoin, apprend désormais *qui* administre le compte — les `a-…`,
les modèles. Ce qu'elle ne peut toujours pas : enrôler, révoquer, décrire —
tout ce qui change le compte reste sur la voie appareil, sous biométrie. Une
machine compromise ne donne pas le compte ; elle le voit.

**Pour soi seulement, comme `/v1/moi`** : la liste est celle du propriétaire
de la clé qui demande, jamais d'un compte désigné. Une machine dont la clé est
révoquée n'a plus de propriétaire à qui poser la question — `401`, comme tout
le reste de la voie.

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
- **Le parc d'un compte ne se liste que sur autorisation de ce compte** :
  `GET /v1/utilisateurs/{u}/machines` rend ce qu'une arête accorde, et une liste
  vide à qui n'en a aucune (§2.2). Ce n'est pas une énumération : c'est ce que
  « tout mon compte » veut dire quand on l'accorde.
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

## 3 bis. La voie entre racines — servie, pas encore tirée

Le quatrième public : **l'autre racine.** Elle n'est ni un daemon, ni une
application, ni une machine qui cherche un port — elle est la même autorité,
sur une autre machine, et ce qu'elle veut est TOUT ce que celle-ci a écrit.
[`replication.md`](replication.md) porte le fond : le périmètre, la règle de
conflit, l'horloge, le rattrapage, la sécurité. Ce qui tient ici est ce qui se
voit sur le fil.

**Depuis 0.6.0, le côté SERVI est écrit** : les deux preuves, les deux flux,
et l'exigence qui les garde. **Depuis 0.7.0, le côté qui TIRE l'est aussi** :
la connexion sortante vers `--peer`, les deux preuves prouvées dans l'autre
sens, le curseur qui avance dans la transaction qui applique, et l'application
des opérations avec la règle de conflit de [`replication.md`](replication.md)
§3.2. Une racine qui a `--peer` tire chez l'autre sans fin, et reprend depuis
son curseur à chaque rupture (§1.5). **Depuis 0.8.0, la voie est exploitable
sur les bancs** : `GET /v1/replication` rend son état, l'instantané et le
rattrapage passent par parts au-delà de la fenêtre d'un flux, et une base
reprise sans identité est ré-estampillée sous l'identité réelle
([`replication.md`](replication.md) §11.4).

**Le même port, le même transport.** La voie est une ressource de plus sous
`/v1`, avec une exigence que seule une clé d'identité de racine satisfait ; il
n'y a pas de second serveur.

```
GET  /v1/defi                                   la racine qui tire prend un défi
POST /v1/defi        genre `n` ‖ n-… (17) ‖ signature (64)
                                                … et prouve sa clé d'identité, comme une machine
POST /v1/pair/preuve défi (32)  →  n-… (17) ‖ signature (64)
                                                la racine tirée prouve la sienne en retour
GET  /v1/pair/operations?apres=<compteur>       tout ce qu'elle a écrit après, puis la suite — SANS FIN
GET  /v1/pair/instantane                        l'état entier, puis le compteur de coupe — fini
GET  /v1/replication                            l'état de la voie, sur la voie machine (`Exigence::Machine`)
```

**`GET /v1/replication` rend un JSON dont `voie` prend trois valeurs** : avec un
pair, `{"pair":"n-…","voie":"ouverte"|"coupée","compteur":…,"applique":…}` —
`compteur` est notre horloge (§4), `applique` le curseur qu'on tient pour le
pair (§5.3). Sans pair, `{"voie":"seule","compteur":…}`, **ni `pair` ni
`applique`** : rien à appliquer de personne. La ressource est **sur la voie
machine** (`Exigence::Machine`), et non sans exigence : elle ne se rend pas à un
inconnu, à qui elle dirait l'heure où une unicité se gagne sur une racine isolée
([`replication.md`](replication.md) §8).

**Chaque racine OUVRE vers l'autre, et y LIT.** Deux connexions, une par sens,
et le même code des deux côtés : c'est le lecteur qui tient son curseur, parce
que c'est lui qui sait ce qu'il a appliqué. Elles se tiennent comme la voie du
daemon — keepalive et inactivité de `modele.md` §4.1, reprise de §1.5.

**`GET /v1/pair/operations` ne se termine jamais**, exactement comme
`GET /v1/poussees` (§1.4) : pas de `content-length`, des cadres qui se suivent
sans enveloppe, et le premier octet est la première opération. Une opération
est un cadre à champs fixes — `genre (1) ‖ compteur (8) ‖ racine (17) ‖
charge` —, dont la charge est l'enregistrement **dans le format de l'entrepôt**
(`asl-registre`). Le genre fixe la taille de la charge ; aucune longueur ne
vient du réseau (§2.1 bis), et il n'y a pas de second décodeur.

**`410` sur `operations` veut dire « mon journal ne remonte plus jusque-là »**,
et la réponse du tireur est `instantane`, puis `operations` à partir du compteur
de coupe. Un instantané est une suite d'opérations, pas un autre format : **son
cadre de fin a la forme d'une opération sans charge**, `15 ‖ compteur (8) ‖
racine (17)`, où l'étiquette `15` suit les quatorze genres et n'en est pas un
— ce qui applique ne le prend jamais pour un fait (`asl_registre::Cadre`).

**Un flux porte une PART, puis se ferme, et le tireur en rouvre un.** La pile
QUIC annonce une fenêtre par flux — seize kibioctets — et ne la relève jamais :
un instantané ou un rattrapage plus grands ne tiennent pas dans un seul flux.
La racine tirée coupe donc chaque flux quand il a porté sa part (douze
kibioctets, **toujours à une frontière d'opération** — jamais au milieu d'un
cadre), et le tireur rouvre : `operations?apres=<curseur>` reprend depuis son
curseur, `instantane` continue le reste de la MÊME lecture, que la connexion
tient jusqu'au cadre de fin. La fin d'un flux n'est donc pas une rupture ; seule
la connexion qui tombe en est une, et c'est la reprise (§1.5) qui joue alors.
Le flux d'`operations` ne se termine, lui, jamais de son propre chef — une
part pleine le coupe, une part vide le tient ouvert.

**Un flux par connexion.** Une connexion qui tient déjà `operations` ou
`instantane` reçoit `409` au second : ce qui est poussé sur une connexion va à
SON flux, et deux curseurs y liraient la même chose.

**`POST /v1/pair/preuve` signe sous un domaine propre**,
`asl_cle::DOMAINE_PREUVE_DE_RACINE`, le message `domaine ‖ n ‖ identifiant
(16) ‖ défi (32) ‖ liaison (32)` — la liaison de canal de LA connexion sur
laquelle la preuve est rendue, dérivée des deux côtés. Un domaine propre,
parce qu'un serveur qui signerait sous celui de `/v1/defi` ce qu'un client lui
présente serait un oracle pour la preuve d'authentification.

**Un genre `n` sur `POST /v1/defi`, et rien d'autre ne change à ce verbe.**
L'identifiant présenté est celui que la clé d'identité de l'autre racine donne
(`replication.md` §2.2), et la signature se vérifie contre la clé lue de
`--peer-key`, pas contre l'entrepôt. Un `n-…` qui n'est pas celui du pair
configuré rend le refus d'une clé inconnue.

**Une opération illisible ferme la connexion ; elle ne se saute pas.** Sauter,
c'est diverger en silence. Le curseur n'avance pas, l'exploitant le lit dans son
journal, et la reprise réessaie la même opération — qui échouera pareil, et se
verra pareil, jusqu'à ce qu'un humain regarde.

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
