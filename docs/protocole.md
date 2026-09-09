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

#### Et aujourd'hui, la vérification n'est pas écrite — d'où un réglage sans défaut

App Attest et Play Integrity demandent les racines d'Apple et de Google, du CBOR,
et une chaîne à valider. **Exiger l'attestation aujourd'hui, c'est donc refuser
TOUS les enrôlements.**

Les deux postures sont défendables et **aucune ne peut être le défaut** : exiger
livrerait un annuaire qui ne crée aucun compte, dispenser livrerait en silence la
posture faible. `asl-server` n'a donc **pas de valeur par défaut** — il refuse de
démarrer tant qu'on ne lui a pas dit laquelle il tient :

```
asl-server --attestation exigee       # la posture de ce document, et rien ne passe
asl-server --attestation facultative  # n'importe qui crée un compte, et c'est dit
                                      # au démarrage, dans le journal d'exploitation
```

Le jour où la vérification s'écrira, elle se branchera à un seul endroit :
`asl_auth::decider_attestation` prend déjà `atteste` en paramètre, aujourd'hui
toujours faux.

### 2.1 bis Ce que porte chaque corps, et pourquoi ce n'est pas toujours du JSON

**Les corps qui portent des CLÉS et des SIGNATURES sont des octets bruts**, à
champs de longueur fixe :

| Verbe | Corps | Taille |
|---|---|---|
| `POST /v1/defi` | genre ‖ identifiant (17) ‖ signature (64) | 81 |
| `POST /v1/comptes` | clé publique (32) ‖ preuve (64) | 96 |
| `POST /v1/appareils` | clé publique (32) | 32 |
| `POST /v1/enrolement` | code (10) ‖ clé publique (32) ‖ preuve (64) | 106 |

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
| `POST /v1/appareils` | Enrôle un appareil de plus. **Signé par un appareil déjà enrôlé.** |
| `PUT /v1/appareils/{a}/poussee` | Dépose ou renouvelle le jeton APNs / FCM. |
| `DELETE /v1/appareils/{a}` | Révoque. Un appareil ne peut pas se révoquer lui-même — sinon un téléphone volé et déverrouillé révoque les autres et confisque le compte. **Il est marqué, non effacé** : l'écran qu'on regarde après avoir perdu un téléphone doit montrer ce qu'on a retiré. |
| `POST /v1/machines` | Déclare une machine, avec son **nom** et ses **capacités** (`annonce`, `lecture`). **Rend un code d'enrôlement** — dix symboles, à usage unique, valable dix minutes. La machine n'a **pas encore de clé**. |
| `PATCH /v1/machines/{m}` | Change le nom ou les capacités. **Ce qui est absent ne change pas** ; voir ci-dessous. |
| `POST /v1/machines/{m}/enrolement` | Émet un nouveau code, pour ré-enrôler une machine dont la clé a été révoquée ou perdue. **Le code précédent meurt à l'émission du suivant.** |
| `DELETE /v1/machines/{m}/cle` | Révoque la clé. **Effet immédiat : connexions fermées, baux tombés** (voir ci-dessous). La machine reste — son nom, ses capacités, ses services ; elle perd le moyen de prouver qu'elle est elle. |
| `PUT /v1/alias` | Enregistre ou change l'alias public. **La seule donnée que l'utilisateur nous confie.** Un alias déjà pris rend `409`, et non `403` : la demande est légitime, c'est l'état du monde qui s'y oppose. |
| `DELETE /v1/alias` | Le retire. |
| `GET /v1/alias/{alias}` | Rend l'identifiant, **et rien d'autre**. Public — c'est l'emploi de l'alias, et son coût (`modele.md` §2.1). |
| `GET /v1/machines/{m}/services` | Les services, leurs candidats, leur état et la date de la dernière sonde. |
| `GET /v1/utilisateurs/{u}` | **Confirme qu'un identifiant existe**, et rien d'autre : ni nom, ni machines, ni services. Sert à ce qu'une faute de frappe ne produise pas une autorisation muette. |
| `POST /v1/autorisations` | Accorde. Bénéficiaire `u-…`, portée, étiquette. Déclenche la notification. |
| `GET /v1/autorisations` | Les deux sens : ce que j'ai accordé, ce qu'on m'a accordé. |
| `DELETE /v1/autorisations/{g}` | Révoque. Effet immédiat. |
| `GET /v1/expositions` | **Ce qui est exposé de MOI**, relation par relation. Tout utilisateur, pas seulement l'administrateur. |
| `DELETE /v1/expositions/{relation}` | **Retire mes enregistrements** de cette exposition. Portée : tout mon compte, ou telle machine. |

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
qui montre MES machines ; le chemin inter-comptes est `GET /v1/ou`. Les confondre
donnerait à une autorisation de lecture — accordée pour joindre un service — le
droit d'énumérer le parc de celui qui l'a accordée. Ce n'est pas ce qu'il a
accordé.

**`GET /v1/autorisations` rend un seul tableau pour les deux sens**, et y laisse
les révoquées, marquées. `par` et `a` disent de quel côté chacune est, et un
lecteur qui connaît son identifiant sait lequel il est ; deux tableaux auraient
obligé l'application à savoir dans lequel chercher. Taire les révoquées ferait
douter d'avoir cliqué — même raison qu'un appareil révoqué, qui est marqué et non
effacé.

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
