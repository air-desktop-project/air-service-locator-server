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

**Une exception, et une seule : l'écho** (décision 106, §3 quater, « Quand la
box ne perce pas son pare-feu IPv6 »). `asl echo` tient son bail **en IPv4
alors que l'IPv6 marche**, quand la box ne lui ouvre pas de trou IPv6 mais lui
accorde une redirection IPv4 vers une adresse externe publique : l'annuaire
ne sonde que l'adresse qu'il a vue, et ce n'est qu'en IPv4 qu'il verra une
adresse où la box laisse entrer. Ce n'est pas un repli sur échec — le bail
IPv6 tenait —, c'est le choix de la seule famille où l'écho est joignable du
dehors. Toute autre connexion, `asl announce` compris, garde la règle.
**La visite IPv4 d'un annuaire local n'en est pas une seconde** (décision
107, §3 quater) : une connexion courte, à côté de sa voie qui reste en IPv6,
qui ne porte rien — elle ne sert qu'à ce que les racines **voient**
l'adresse IPv4 de la box du membre.

### Qui l'on croit : une identité, pas un nom

**Décidé le 2026-09-27 (Thierry) — C20, `annuaires.md` §2 quater, décisions 53
à 58.** Joindre un annuaire, c'est viser un **locateur** (une adresse, ou un nom
DNS si l'on en a un) en attendant une **identité** (`n-…`). La poignée de main
TLS 1.3 juge l'identité, jamais le locateur.

- **Côté annuaire** (racine ou local) : un certificat X.509 **auto-signé par
  sa clé d'identité Ed25519**, d'un seul maillon, présenté par
  `ams_tls::quic_server_config` comme aujourd'hui. Le produire ne demande
  aucune dépendance de plus (C4) : un gabarit DER fixe, une clé, une signature
  (décision 55 : `<clé>.crt` à `--new-identity-key`, `--identity-certificate
  <clé>` pour l'imprimer, et le démarrage le frappe en mémoire — 0.29.0).
- **Côté client** (daemon, application, racine qui tire, annuaire local qui
  fédère) : un vérificateur propre à ASL, branché par
  `with_custom_certificate_verifier` sur la `ClientConfig` qu'ASL construit
  déjà. Il **accepte** si et seulement si : le certificat de tête porte une clé
  Ed25519 ; cette clé se déduit en le `n-…` attendu (`modele.md` §2.7) ; la
  signature de la poignée de main est bonne sous cette clé. Il **ignore** le
  nom (SNI, `subjectAltName`), l'émetteur, la chaîne et les dates (décision 54).
- **Le nom de serveur** que `ams_quic_tls::Connection::connect` exige reste
  requis par `rustls` : le client passe le locateur (une IP, ou le nom s'il en
  a un) ; il ne décide de rien.
- **Les réglages** : là où l'on donnait une autorité PEM, on donne une
  identité attendue — `--peer-key` pour le pair (déjà), le `n-…` de chaque
  racine pour `--federation` (décision 58 : `--federation
  <locateur>=<n-…>`, ou un locateur de la liste embarquée — 0.29.0), et une
  liste embarquée pour `asl` et les applications.
  **La transition est close côté serveur (0.34.0, décision 63)** : un
  annuaire ne présente plus que son certificat d'identité, à tous, et
  `--certificate`/`--key`, `--peer-ca`, `--federation-ca` et `--ca` sont
  refusés avec ce qu'il faut faire à la place. `--roots` (côté `asl`) suit
  dans le dépôt client.
- **Un locateur peut rester un nom** (C20) : `--peer`, `--federation`,
  `--directory` acceptent un nom DNS comme une adresse, parce qu'il ne dit que
  **où** aller. La confiance ne vient jamais de lui : ni SNI jugé, ni nom
  vérifié, et le client vise toujours l'adresse résolue.

**Ce que la preuve HTTP garde.** Les défis de genre `n` (`POST /v1/defi`,
`POST /v1/pair/preuve`) restent : liés au canal (§2.1 bis), ils prouvent
l'identité au-dessus de TLS, et jugent seuls un premier contact où le client ne
sait pas encore qui il attend.

**Ce qui ne change pas.** Les machines et les appareils prouvent déjà leurs
clés par défi HTTP (§2.0, §2.1) ; ils ne présentent pas de certificat, et rien
ne change pour eux. Un TLS direct entre machines, authentifié par leurs clés
`m-…`, est une suite nommée, hors de ce périmètre.

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

**Le `service` rendu est DÉRIVÉ** (0.37.0 ; `modele.md` §2.4, décisions 66 et
72) : `SHA-256("asl/service/1" ‖ m (16 octets) ‖ nom)` tronqué à seize octets.
La première annonce d'un nom crée le service sous cet identifiant ; toute
annonce suivante — au même annuaire, à l'autre membre de la paire, à une racine
après un changement d'hébergeur — rend **le même**. Le message et la réponse ne
changent pas de forme : seul le choix de la valeur change, et un client qui la
calculerait de son côté tomberait juste. Jusqu'à la 0.36.0, c'était un aléa de
l'annuaire qui recevait l'annonce ; un daemon ré-annoncé après la mise à jour
lit donc, une fois, un `s-…` nouveau.

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
l'exploitant comme `--peer-key` l'est pour la réplication.

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
l'app. Et **les notifications** (§2.6 de `modele.md`) n'appellent plus ni
Apple ni Google : un point de poussée UnifiedPush choisi par l'utilisateur sur
Android, la connexion tenue sur le Mac, et sur un iPhone la relecture à
l'ouverture — tranché le 2026-09-25, §2.2, « Les notifications ».

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
| Supprimer son **dernier** domaine (`modele.md` §2.11, 2026-09-26) | `409` — un compte a toujours au moins un domaine |

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
| `PUT /v1/appareils/{a}/poussee` | Dépose ou renouvelle le **point de poussée** de cet appareil : une URL UnifiedPush, que l'annuaire réveillera d'un message VIDE. **Pour soi seulement** ; voir ci-dessous. |
| `GET /v1/nouvelles` | **Le flux des nouvelles de MON compte**, sur la connexion tenue d'un appareil : une ligne par événement, sans rien de plus. Ce qu'un Mac résident reçoit sans aucun serveur de poussée. Voir ci-dessous. |
| `PUT /v1/appareils/{a}/description` | Dit ce que cet appareil est : `{"plateforme": "macos", "modele": "MacBook Pro (2019)"}`, la plate-forme parmi `ios`, `android`, `macos`. **Pour soi seulement**, même règle que la poussée ; voir ci-dessous. |
| `DELETE /v1/appareils/{a}` | Révoque. Un appareil ne peut pas se révoquer lui-même — sinon un téléphone volé et déverrouillé révoque les autres et confisque le compte. **Il est marqué, non effacé** : l'écran qu'on regarde après avoir perdu un téléphone doit montrer ce qu'on a retiré. La révocation du **dernier** appareil vivant ouvre le délai des orphelins (`modele.md` §2.1). |
| `DELETE /v1/compte` | **Efface MON compte** — celui de la clé qui signe. Tout part dans une transaction : appareils, machines et services, autorisations dans les deux sens, alias libéré ; reste l'identifiant marqué effacé. `204`, puis l'annuaire ferme la connexion : la clé qui a demandé est révoquée. Voir ci-dessous. |
| `POST /v1/invitations` | **Émet un code d'invitation**, sous la clé déclarée par `--operator-key`. Rend le code EN CLAIR, une fois — l'annuaire n'en garde que l'empreinte. N'existe que sous la posture `invitation` ; ailleurs, `404`. Voir ci-dessous. |
| `POST /v1/machines` | Déclare une machine, avec son **nom** et ses **capacités** (`annonce`, `lecture`). **Le nom est un nom d'hôte** depuis 0.26.0 — étiquette RFC 1123, rangée en minuscules (`modele.md` §2.3) — sinon `400`. **Rend un code d'enrôlement** — dix symboles, à usage unique, valable dix minutes. La machine n'a **pas encore de clé**. |
| `GET /v1/machines` | Les machines de MON compte : l'écran « Machines ». Chacune rend `machine`, `nom`, `capacites`, et `cle` (`enrolee` ou `attendue`). |
| `PATCH /v1/machines/{m}` | Change le nom ou les capacités. **Ce qui est absent ne change pas** ; voir ci-dessous. Un nouveau nom suit la règle du nom d'hôte. |
| `POST /v1/machines/{m}/enrolement` | Émet un nouveau code, pour ré-enrôler une machine dont la clé a été révoquée ou perdue. **Le code précédent meurt à l'émission du suivant.** |
| `DELETE /v1/machines/{m}/cle` | Révoque la clé. **Effet immédiat : connexions fermées, baux tombés** (voir ci-dessous). La machine reste — son nom, ses capacités, ses services ; elle perd le moyen de prouver qu'elle est elle. |
| `PUT /v1/alias` | Enregistre ou change l'alias public : `{"alias":"Thierry"}`. **La seule donnée que l'utilisateur nous confie.** UTF-8, **sensible à la casse**, rangé en NFC, trois à trente-deux octets rangés, pas de tiret en deuxième caractère (`modele.md` §2.1, 0.26.0) — sinon `400`. Un alias déjà pris rend `409`, et non `403` : la demande est légitime, c'est l'état du monde qui s'y oppose. |
| `DELETE /v1/alias` | Le retire. |
| `GET /v1/alias/{alias}` | Rend l'identifiant, **et rien d'autre**. Public — c'est l'emploi de l'alias, et son coût (`modele.md` §2.1). Le chemin porte un alias ASCII — lettres des deux casses, chiffres, `-`, `_`, `.` —, la forme des applications d'avant 0.26.0. |
| `GET /v1/alias?alias=…` | **La même résolution pour un alias UTF-8** (0.26.0) : pourcent-encodé comme `GET /v1/domaines?alias=…`, rangé en NFC avant d'être cherché, **la casse comptant**. Public, comme la forme du chemin. `400` pour un alias qu'on n'aurait pas pu poser. |
| `GET /v1/machines/{m}/services` | Les services, leurs candidats, leur état et la date de la dernière sonde. **Le propriétaire de la machine, et lui seul** ; pour tout autre, `[]`. Servi aussi sur la voie machine (0.39.0, §3), à une machine qui porte `lecture`, pour son propriétaire. |
| `GET /v1/vu` | **D'où l'annuaire voit cette connexion**, sans rien annoncer ni prouver. Voir ci-dessous. |
| `GET /v1/version` | **La version de l'annuaire qui répond, et sa posture d'attestation**, `{"version": "0.2.0", "posture": "optional"}`, sans rien prouver. Voir ci-dessous. |
| `GET /v1/racines` | **Les racines, leur identité et leurs locateurs** (décision 56, 0.30.0), sans rien prouver : `[{"annuaire":"n-…","cle":"<64 chiffres hexadécimaux>","locateurs":["[IPv6]:port","IPv4:port","nom:port"]},…]` — la liste embarquée dans le binaire. **Aucune signature à part** : la connexion, vérifiée par la clé de la racine jointe (§0), est la signature. Le client vérifie que chaque clé se déduit en le `n-…` écrit à côté, et refuse la liste entière sinon ; puis met à jour ses locateurs. **Au moins une racine écoute sur 6630** — celle que la liste embarquée garantit ; les autres peuvent écouter ailleurs, et c'est par cette liste, **relue et gardée en cache**, que le client l'apprend (décision 76 ; pas d'`asl-directory` pour les racines). **Elle ne change que les locateurs des racines déjà embarquées**, par leur `n-…` : elle n'en ajoute ni n'en retire aucune — une racine nouvelle exige une nouvelle version du client —, et le client essaie d'abord les locateurs appris, puis les embarqués (décision 85). Le client d'aujourd'hui ne la lit que pour `asl roots` : à coder (`annuaires.md` §2 quinquies). |
| `GET /v1/utilisateurs/{u}` | **Confirme qu'un identifiant existe**, et rien d'autre : ni nom, ni machines, ni services. Sert à ce qu'une faute de frappe ne produise pas une autorisation muette. |
| `GET /v1/moi/appareils` | **Les appareils du compte de la machine qui demande**, révoqués compris — lecture seule, voie machine. Voir §3. |
| `GET /v1/utilisateurs/{u}/machines` | **Les machines de `u` que le demandeur a le droit de voir** — les siennes si `u` est lui, sinon celles que les autorisations de `u` envers lui couvrent (`modele.md` §2.5). Voir ci-dessous. Servi aussi sur la voie machine (§3). |
| `POST /v1/autorisations` | Accorde. Bénéficiaire `u-…`, portée, étiquette. **Réveille les appareils du bénéficiaire** — voir « Les notifications ». **Depuis le 2026-09-26, un verbe de compatibilité** : il écrit un droit `voir` + `localiser` au groupe personnel du bénéficiaire (voir « Les autorisations d'hier »). |
| `GET /v1/autorisations` | Les deux sens : ce que j'ai accordé, ce qu'on m'a accordé. **Compatibilité** : une vue des droits, sous la forme d'hier. |
| `DELETE /v1/autorisations/{g}` | Révoque. Effet immédiat. **Compatibilité** : retire le droit `g-…`. |
| `GET /v1/expositions` | **Ce qui est exposé de MOI**, relation par relation. Tout utilisateur, pas seulement l'administrateur. |
| `DELETE /v1/expositions/{relation}` | **Retire mes enregistrements** de cette exposition. Portée : tout mon compte, ou telle machine. |
| `POST /v1/domaines` | **Crée un domaine** à MON compte (2026-09-26, `modele.md` §2.11), alias facultatif : `{"alias":"Maison"}`. `201`, `{"domaine":"d-…"}`. Le premier est créé par `POST /v1/comptes`, dans sa transaction. |
| `GET /v1/domaines` | **Les domaines que je possède et ceux où l'un de mes groupes tient un droit** (0.25.0 ; le propriétaire tient les quatre, le groupe d'administrateurs `["administrer","rattacher","voir"]`, ~~le domaine racine `["administrer"]` à ses administrateurs~~ **le domaine racine les quatre à ses administrateurs** — 0.39.0, décision 88) : `[{"domaine":"d-…","proprietaire":"u-…","alias":"Maison","heberge_par":"racines"\|"n-…","droits":["administrer","voir",…]}]` — `droits` est l'union de ce que je peux sur ce domaine (`modele.md` §2.13). Le domaine racine n'y figure que pour ses administrateurs, **et son objet seul porte, en dernier, `"sorte":"racine"`** (0.39.0) : une chaîne, absente pour tout autre domaine — ni `null`, ni booléen, qu'un décodeur déployé pourrait refuser. Elle dit aux applications ce que le domaine racine n'accepte pas : un hébergeur, une suppression. Elle ne se confond pas avec la `sorte` d'un groupe (`administrateurs`, `domaine`, `personnel`) : un autre objet, et d'autres valeurs. **Servi aussi sur la voie machine** (0.39.0, §3). |
| `GET /v1/domaines?alias=…` | **La recherche par alias** : correspondance exacte après NFC, **sensible à la casse** (0.26.0) ; `[{"domaine":"d-…","autorite":"racines"\|"n-…"}]`, **tous** ceux qui portent l'alias, et `[]` si aucun. Ni propriétaire, ni machine. Servie sur la voie appareil **et** sur la voie machine — tout compte authentifié —, jamais sans preuve. Voir ci-dessous. |
| `GET /v1/domaines/{d}` | Le domaine, ses groupes, et les machines qui y sont rattachées — `m-…` et propriétaire ; le nom, pour mes machines **et** pour qui a `voir` sur le domaine. Qui tient un droit sur le domaine ; les autres, `404`. Les champs de `GET /v1/domaines` suivis de `"groupes":[{"groupe","domaine","etiquette"?,"sorte"}]` — **pour qui l'administre**, vide sinon — et `"machines":[…]` — **pour qui le voit** (`voir`, `localiser` ou `administrer`), vide sinon. Une machine n'y figure que si son propriétaire peut encore y ranger — il l'administre, ou tient `rattacher` (`modele.md` §2.11). Un domaine supprimé rend `404`. **Le domaine racine** (0.39.0, décision 88) : à ses administrateurs, `"sorte":"racine"` après `droits`, son groupe d'administrateurs, et les machines qu'ils y ont rangées ; aux autres, `404`. **Servi aussi sur la voie machine** (§3). |
| `PUT /v1/domaines/{d}/alias` | Pose ou change l'alias : `{"alias":"Maison"}`. `administrer`. **Jamais `409`** : l'alias de domaine n'est pas unique. `400` s'il n'est pas de l'UTF-8 admis (`modele.md` §2.11). |
| `DELETE /v1/domaines/{d}/alias` | Le retire. |
| ~~`PUT`/`DELETE /v1/domaines/{d}/delegues/{u}`~~ | **Retirés le 2026-09-26** : déléguer, c'est ajouter au groupe d'administrateurs (`POST /v1/groupes/{e}/membres`). |
| `PUT /v1/machines/{m}/domaine` | **Rattache** MA machine : `{"domaine":"d-…"}` — un domaine où je tiens `rattacher` — reçu, ou emporté par `administrer` : propriétaire, groupe d'administrateurs, ou droit reçu. Une machine déjà rattachée est **déplacée**. `403` sans le droit ; `404` si la machine n'est pas à moi, ou si le domaine n'existe pas ou plus. **Le domaine racine** (0.39.0, décision 88) : ses administrateurs y rangent leurs machines, par ce verbe, comme ailleurs ; pour tout autre compte, `403` — il existe toujours, calculé, et n'est jamais « absent ». |
| `DELETE /v1/machines/{m}/domaine` | La détache : elle n'a plus de domaine. |
| `PUT /v1/machines/{m}/alias` | **Pose l'alias** de MA machine (0.26.0) : `{"alias":"Le Grenier — NAS.maison"}` — UTF-8, sensible à la casse, rangé en NFC, 1 à 253 octets (`modele.md` §2.3). `204` ; `400` pour un alias qu'on ne peut pas ranger ; `404` si la machine n'est pas à moi. **Le propriétaire seul** : ranger une machine dans un domaine confie à ses administrateurs le droit de la partager (décision 40), pas de la renommer. |
| `DELETE /v1/machines/{m}/alias` | Le retire. |
| `DELETE /v1/domaines/{d}` | Supprime un domaine : ses machines détachées, son alias, ses groupes et les droits qui le visent retirés. **`409` si c'est mon dernier.** Propriétaire seulement ; le domaine racine ne se supprime pas. |
| `POST /v1/annuaires` | **Déclare MON annuaire local** : `{"adresse":"hôte:port"}` — ASCII imprimable, sans `"` ni `\`, un port de 1 à 65 535 ; `201` `{"code":"XXXXX-XXXXX","expire_a":<ms>}`, un code d'inscription — dix symboles, à usage unique, comme un code d'enrôlement, **valable vingt-quatre heures** (0.27.0). L'annuaire le présente aux racines avec sa clé d'identité (`POST /v1/annuaires/inscription`) ; l'inscription est alors **en attente**. |
| `GET /v1/annuaires` | Mes annuaires locaux et l'état de leur inscription : `attendue` (un code déclaré, pas encore présenté ni expiré — `adresse`, `expire_a`), `en attente`, `acceptée`, `refusée`, `retirée` (`membre`, `annuaire` — son titulaire —, `adresse`, et `locateurs` s'il en a publié : décision 57, 0.30.0). **Et `paire`** (0.36.0, décision 70) : `seul`, `reglee`, `sans-peer` ou `peer-inconnu`, ce que ce membre conclut de sa paire — absent tant qu'il ne l'a pas dit à cette racine. **Et `voie`** (décidé le 2026-09-29, décision 86 ; fait en 0.38.0) : `ouverte` si la voie de fédération de ce membre vers **cette** racine tient (trente secondes au plus, la règle des services), `tombee` si elle a tenu depuis que la racine tourne et s'est tue — une chaîne, comme `paire` ; absent tant que ce membre ne lui a pas parlé depuis son démarrage. C'est ce que la tuile de l'annuaire affiche : les applications ne lisent pas `asl-directory`. |
| `DELETE /v1/annuaires/{n}` | Retire l'inscription de mon annuaire local — son second avec lui ; ses domaines reviennent aux racines. **Un administrateur des racines le peut aussi** : c'est révoquer une inscription acceptée (0.27.0). |
| `POST /v1/annuaires/{n}/membres` | **Déclare le second membre** de mon annuaire local accepté — sa paire de secours (2026-09-27, décision 49) : `{"adresse":"hôte:port"}` ; `201`, un code d'inscription, que la seconde machine présente avec **sa** clé. `409` si l'annuaire a déjà deux membres ; `404` s'il n'est pas à moi ou pas accepté. |
| `DELETE /v1/annuaires/{n}/membres/{n2}` | Retire le second membre. Nommer ici le titulaire, c'est retirer l'annuaire entier, comme `DELETE /v1/annuaires/{n}`. `404` pour un membre d'un autre annuaire. |
| `PUT /v1/domaines/{d}/hebergeur` | **Confie** mon domaine à mon annuaire local accepté : `{"annuaire":"n-…"}` ; `DELETE` le rend aux racines. Propriétaire seulement, et **vers un annuaire de son propre compte** : `404` pour l'annuaire d'un autre, même si j'administre le domaine (décision 48). **Le domaine racine ne se confie pas** : `404`, pour ses administrateurs comme pour les autres (décision 88). |
| `GET /v1/inscriptions` | **Les inscriptions en attente**, pour un administrateur des racines (`modele.md` §2.12) : `membre`, `annuaire`, `proprietaire`, `etat`, `adresse` — et `paire`, comme `GET /v1/annuaires` (décision 70). **Pas `voie`** (décision 86, précisée le 2026-09-29 ; retiré en 0.38.1) : elle n'est dite que d'un membre accepté, et cette vue ne rend que ce qui attend. Aux autres, `404`. |
| `POST /v1/inscriptions/{n}/decision` | **Accepte ou refuse** : `{"accepte":true}`. Un administrateur suffit ; **le refus l'emporte**, même arrivé après une acceptation, même d'une autre racine (`replication.md` décision 51). Accepter une inscription retirée ou refusée, `409` ; redemander, c'est une inscription neuve. |
| `POST /v1/annuaires/inscription` | **L'annuaire local présente son code** (0.27.0), **sans session** : corps binaire `code (10) ‖ clé d'identité (32) ‖ preuve de possession (64)`, la forme d'un enrôlement, la preuve signant le défi de la connexion (`POST /v1/defi` d'abord). `200` et l'inscription (`membre` — `asl_cle::identifiant_de_racine` de la clé —, `annuaire`, `etat`, `adresse`) ; la même clé qui représente le même code, `200` encore ; une autre clé, ou une clé déjà membre d'un annuaire, `409` ; un code inconnu, `404` ; expiré, `403` ; une preuve fausse ou sans défi, `401` ; trop d'échecs d'une adresse, `429` — le frein des invitations. |
| `POST /v1/annuaires/etat` | **L'annuaire local relit son état** (0.27.0), sans session : `clé (32) ‖ preuve (64)` ; `200` et l'inscription, `404` pour une clé membre de rien. |
| `POST /v1/administrateurs` | **Nomme** un administrateur des racines, **sous la clé d'exploitant** : corps `o ‖ signature ‖ u-…` — le genre, la signature du défi de la connexion comme pour `POST /v1/invitations`, puis le compte en dix-sept octets (sa lettre, ses seize octets), quatre-vingt-deux en tout. `DELETE /v1/administrateurs/{u}` le retire, corps `o ‖ signature`. `204` ; `401` si la signature ne tient pas ; `409` pour nommer qui l'est déjà ; `404` sans `--operator-key`, pour un compte inconnu, ou pour retirer qui ne l'est pas ; `400` pour un corps mal formé. Le défi est dépensé dans tous les cas. **Depuis le 2026-09-26, c'est un membre du groupe d'administrateurs du domaine racine** : ces deux verbes, et eux seuls, changent ce groupe-là — `POST` et `DELETE /v1/groupes/{e}/membres…` y rendent `403`. Le premier nommé encore administrateur est propriétaire du domaine racine — calculé, jamais écrit (décidé ; 0.24.0, décision 43). L'outil de l'exploitant : `asl-server --add-admin <u-…>` / `--remove-admin <u-…>`, avec `--directory`, `--ca`, `--operator-secret`. |
| `GET /v1/groupes` | **Mes groupes** — ceux dont je suis membre, mon groupe personnel compris, et ceux des domaines que j'administre : `[{"groupe":"e-…","domaine":"d-…"\|null,"etiquette":"Famille","sorte":"administrateurs"\|"domaine"\|"personnel","membre":true}]`. (2026-09-26, `modele.md` §2.12.) |
| `POST /v1/domaines/{d}/groupes` | **Crée un groupe** dans le domaine : `{"etiquette":"Famille"}` ; `201`, `{"groupe":"e-…"}`. `administrer`. |
| `GET /v1/groupes/{e}` | Le groupe et ses membres (`u-…`) : `{"groupe","domaine"\|null,"etiquette"?,"sorte","membres":["u-…",…]}` — le propriétaire du domaine y figure dans son groupe d'administrateurs, d'office. Ses membres et les administrateurs de son domaine ; les autres, `404`. Un groupe personnel ne rend que son titulaire, à lui seul. |
| `PATCH /v1/groupes/{e}` | Change l'étiquette : `{"etiquette":"…"}`, aux règles d'un nom de machine. `administrer` sur son domaine. `204` ; `409` pour un groupe d'administrateurs ou un groupe personnel, qui n'en portent pas. |
| `POST /v1/groupes/{e}/membres` | **Ajoute un compte** : `{"compte":"u-…"}` ; `204` ; `404` si le compte n'existe pas, `409` s'il est déjà membre. `administrer` sur le domaine du groupe. **Réveille le compte ajouté si le groupe porte des droits** (`modele.md` §2.13). `403` sur un groupe personnel, et sur celui du domaine racine. |
| `DELETE /v1/groupes/{e}/membres/{u}` | **Retire un membre**. Effet immédiat. `administrer`, ou le membre lui-même qui s'en va. `409` pour le propriétaire dans son groupe d'administrateurs. Retirer `rattacher` à quelqu'un détache ses machines du domaine. |
| `DELETE /v1/groupes/{e}` | Supprime un groupe — ses membres et les droits qu'il reçoit partent avec. `administrer`. `409` pour un groupe d'administrateurs ou un groupe personnel. |
| `POST /v1/droits` | **Accorde** : `{"groupe":"e-…","element":"d-…"\|"m-…"\|"s-…","droits":["localiser"],"etiquette":"…"}` ; `201`, `{"droit":"g-…"}`. `administrer` sur le domaine de l'élément, ou propriétaire de la machine visée. `400` pour un droit sans sens sur cet élément (`rattacher` sur une machine) ; `404` pour un groupe inconnu ou supprimé, et pour un élément que je ne vois pas ; `403` pour un élément que je vois sans pouvoir y accorder. **Réveille les membres du groupe**, moi excepté (0.25.0). |
| `GET /v1/droits` | **Les droits que j'ai accordés, ceux que mes groupes ont reçus, et ceux qui visent ce que je possède ou que j'administre** — un domaine, une machine, ses services —, pour voir et retirer ce qu'un administrateur a partagé de ma machine ; chacun une fois : `[{"droit":"g-…","groupe":"e-…","element":"…","droits":[…],"etiquette":"…","par":"u-…","retire":false}]`. Les retirés y restent, marqués. |
| `DELETE /v1/droits/{g}` | **Retire** un droit. Effet immédiat. Celui qui l'a accordé, ou qui a aujourd'hui le pouvoir d'accorder sur l'élément. `204`, déjà retiré compris — le retrait garde sa première estampille ; `403` pour un membre du groupe qui l'a reçu ; `404` pour les autres. |

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

### `GET /v1/version` — quelle version répond, et ce qu'elle exige

```jsonc
{"version": "0.2.0", "posture": "optional"}   // required | optional | invitation
{"version": "0.36.0", "posture": "optional", "paire": "sans-peer"}   // un membre d'annuaire local
```

**Et `paire`, chez un membre d'annuaire local** (0.36.0, décision 70) : ce
qu'il conclut de sa paire — `seul`, `reglee`, `sans-peer`, `peer-inconnu`
(§3 ter). Absent chez une racine, et tant que le membre n'a pas entendu les
racines. Une chaîne, comme `posture` : les lecteurs d'hier la sautent.

**Elle n'exige rien, et c'est la sixième ressource dans ce cas.** Ceux qui ont
besoin de la lire sont précisément ceux qui n'ont pas encore de clé :
l'application qui va créer un compte et veut savoir si l'annuaire sert les
verbes qu'elle emploie, la machine qu'on installe, l'exploitant qui vérifie
qu'un banc sert bien ce qu'il croit. Et elle ne révèle rien qui ne soit déjà
public : ce logiciel est libre, et **chaque PR change sa version**
(`CLAUDE.md`), donc ce nombre nomme exactement un état du dépôt.

**La version et la posture, et rien d'autre.** Ni commit, ni réglage : ce
qu'un annuaire sait de lui-même au-delà de ces deux mots est l'affaire de son
exploitant, qui le lit sur la machine avec `asl-server --version`.

**La posture s'est ajoutée le 2026-09-24, et ce paragraphe disait le
contraire.** Il tenait que la posture était « l'affaire de son exploitant »,
au même titre que le reste du réglage. L'argument ne tient pas à l'examen :
**une posture n'est pas un secret, elle est déjà observable**. Une racine en
`invitation` refuse toute création de compte qui ne porte pas de code ; une
racine en `required` refuse celles qui n'attestent pas. Qui veut la connaître
l'apprend en une requête, et la taire ne l'a jamais cachée — cela obligeait
seulement les applications à deviner, ou à essuyer un refus pour comprendre
ensuite. La posture `invitation` (§2.2) a rendu ce coût visible : une
application doit savoir s'il lui faut demander un code **avant** d'ouvrir un
compte, faute de quoi elle montre à tous un champ qui ne sert qu'à quelques-uns,
ou ne le montre à personne.

**Où passe la ligne, alors.** Elle passe entre ce qui est déductible du dehors
et ce qui ne l'est pas. La posture est déductible : elle se lit dans les refus.
Le reste du réglage ne l'est pas, et **reste tu** — les racines de fabricant
épinglées, le paquet et le signataire Android attendus, l'existence d'une
`--operator-key`, les durées et les seuils. Rien de tout cela ne se devine en
essayant, et rien de tout cela n'aide une application honnête : ce sont des
renseignements pour qui cherche une prise.

**Ce qu'elle promet aux applications : un point de comparaison, pas une
négociation.** Une application qui lit `0.1.0` là où elle attend le verbe de
description (`0.2.0`) peut le dire à son utilisateur plutôt que de journaliser
un `404` ; elle ne demande pas à l'annuaire de parler autrement. La posture
s'y lit de la même façon : une application qui voit `invitation` demande un
code avant d'ouvrir un compte, et ne le demande pas ailleurs — elle ne
négocie pas davantage, et un annuaire qui répondrait un mot qu'elle ne
connaît pas se traite comme une version trop récente, non comme une panne.

### Le point de poussée — ce qu'un appareil dépose, et ce qu'il ne promet pas

```jsonc
PUT /v1/appareils/{a}/poussee
{"plateforme": "unifiedpush", "point": "https://ntfy.example.org/upAb3kZq9…"}
```

**Un appareil ne dépose que pour LUI-MÊME.** Le point vient du distributeur
installé sur le téléphone qui le porte, et personne d'autre ne l'a ; déposer
pour un autre détournerait ses notifications, c'est-à-dire celles d'un compte
vers le téléphone de qui l'a volé. Viser l'appareil d'un autre rend **`404`**,
comme un appareil qui n'existe pas — le distinguer confirmerait l'existence de
l'identifiant visé. **Un corps mal formé rend `400`** : là, la faute est celle
de l'appelant, et il vise son propre appareil.

**Un seul point par appareil, et le neuf remplace l'ancien.** Le distributeur
en donne un nouveau quand l'utilisateur en change ; en garder deux réveillerait
deux fois, dont une fois un point mort. **Le point part avec l'appareil qu'on
révoque**, dans la même écriture. **Il n'y a pas de verbe de retrait** : un
utilisateur qui coupe les notifications se désinscrit auprès de son
distributeur, le point meurt, et l'annuaire l'apprend au premier envoi (voir
« Échec »). Un appareil dont on ne veut plus est un appareil qu'on révoque.

**Ce qui est exigé du point porte sur sa FORME, et c'est déjà une défense**
(voir « La sécurité ») : `https://` et rien d'autre ; un **nom DNS**, jamais une
adresse littérale — le certificat se vérifie contre un nom, et une adresse
littérale est la forme la plus directe d'une requête détournée ; le port **443**,
implicite ou écrit ; ni identifiants (`user@`), ni fragment ; de l'ASCII
imprimable, au plus **1024 octets**. Deux champs facultatifs, `"cle"` (la clé
publique P-256 du récepteur, 65 octets en base64url) et `"secret"` (16 octets
en base64url), sont acceptés et rangés sans servir : ce sont ceux de RFC 8291,
gardés pour le repli dit plus bas, afin qu'il ne coûte pas un format de plus.

**`apns` et `fcm` sont refusés, `400`.** Le verbe les acceptait depuis le début
et rien ne s'en servait — « l'envoi n'est pas écrit », disait cette section, et
c'était la vérité. Ni l'app Android ni l'app iOS ne les déposent (vérifié le
2026-09-25 dans les deux dépôts) : les refuser ne casse personne, et accepter
un jeton qu'aucun code n'emploiera est une promesse qu'on sait ne pas tenir.

**Le rangement.** Une table à elle, à taille fixe (provenance, estampille,
longueur, point, et les deux champs facultatifs) : **une table qui s'ajoute ne
change aucun format**, comme celle des invitations. L'ancienne rangée du jeton
(`JetonPoussee`, 255 octets au plus — trop court pour une URL) n'est plus
écrite ; elle se lit encore, et partira avec l'opération qui la porte.

### Les notifications — sans Apple ni Google, et ce que cela coûte

**Décidé le 2026-09-25.** B doit apprendre qu'A l'a autorisé sans avoir à ouvrir
son application au bon moment (`modele.md` §2.6), et aucun service d'Apple ou de
Google ne doit être appelé pour cela (C19). Les deux exigences ne se concilient
pas partout, et cette section dit, plate-forme par plate-forme, ce qui a été
choisi et ce que cela coûte.

**Ce qui déclenche : un seul événement.** Une autorisation accordée à B
(`POST /v1/autorisations`) réveille tous les appareils vivants de B. Rien
d'autre ne notifie. **Depuis le 2026-09-26, l'événement a deux formes, et c'est
le même** (`modele.md` §2.13) : **un droit accordé** à un groupe réveille ses
membres, et **l'ajout d'un compte** à un groupe qui porte des droits réveille
ce compte — dans les deux cas, quelqu'un vient de recevoir de quoi voir ou
joindre. Retirer ne réveille personne. **Elle part de la racine qui a écrit l'autorisation**, jamais
de celle qui l'applique (`replication.md`, décision 9) : un utilisateur ne doit
pas être réveillé deux fois. **Et elle part hors de la boucle** : une tâche à
part, après la validation de l'écriture ; la réponse à `POST /v1/autorisations`
ne l'attend pas, et la boucle QUIC — une tâche qui sert toutes les connexions —
ne s'arrête pas le temps d'un appel sortant (la leçon de la 0.18.0).

**Ce qu'elle porte : RIEN.** Le message est **vide**. L'application réveillée
affiche une notification locale générique — « Du nouveau dans Service
Locator » — et c'est à l'ouverture qu'elle relit et montre qui a accordé quoi.
Trois raisons, et la première décide :

- **Un téléphone réveillé ne peut pas lire.** La clé d'un appareil ne s'emploie
  qu'après un geste biométrique (`modele.md` §2.2), et il n'y a personne devant
  l'écran pour le faire : l'application réveillée en arrière-plan ne peut pas se
  connecter. Un contenu détaillé devrait donc voyager DANS le message.
- **Ce message traverse un serveur de poussée.** Choisi par l'utilisateur, le
  sien peut-être — mais un serveur. Vide, il ne lui apprend que l'heure.
- **Un écran verrouillé n'affiche alors rien qui désigne quelqu'un** — mieux
  que ce que `modele.md` §2.6 promettait, qui y mettait l'identifiant d'A.

*Écarté* : le contenu pauvre de §2.6, chiffré de bout en bout (RFC 8291). Le
serveur de poussée ne le lirait pas, mais il faudrait écrire et éprouver un
chiffrement de plus pour afficher un `u-…` que l'utilisateur ne reconnaît pas
sans ouvrir l'app — où il le verra de toute façon, avec son contexte.

**Android : UnifiedPush.** L'utilisateur installe un *distributeur* — ntfy,
auto-hébergeable, ou un autre de son choix. L'application obtient de lui, par le
connecteur UnifiedPush, un **point de terminaison** (une URL), et le dépose ici.
Pour réveiller l'appareil, l'annuaire envoie à cette URL un message Web Push
vide (RFC 8030). **Est-ce « sans tiers » au sens de C19 ?** C19 interdit que le
service DÉPENDE d'un tiers que le produit impose. Ici, le service marche sans
poussée (la relecture, plus bas), et le serveur de poussée est désigné par
l'utilisateur, jamais par le produit — comme une adresse de courrier qu'on
donne à un service. L'annuaire l'appelle, et il faut le dire : c'est le seul
appel sortant d'une racine en dehors de son pair, et c'est pourquoi la section
« La sécurité » existe. *Écartés* : FCM (Google, imposé) ; un distributeur
intégré à l'app (une socket tenue en permanence par application, ce que les
distributeurs mutualisent justement).

**iOS : pas de poussée.** Un iPhone ne réveille une application en
arrière-plan que par APNs, et c'est la limite dure. Trois voies ont été pesées :

- **(a) aucune poussée** — la relecture à l'ouverture, seule ;
- **(b) APNs, choix de l'exploitant, désactivé par défaut** — comme C19 traite
  l'attestation. Il faudrait la clé du compte développeur Apple posée sur les
  racines, un client HTTP/2 vers les serveurs d'Apple, un jeton signé (ES256),
  et l'autorisation `aps-environment` dans l'app ;
- **(c) le rafraîchissement en arrière-plan** d'iOS — l'app tourne parfois,
  quand le système le décide ; mais elle ne peut pas se connecter sans geste
  biométrique, donc elle n'apprendrait rien. Écarté.

**Choisi : (a).** Ce que cela coûte, sans détour : **un utilisateur d'iPhone
apprend une autorisation reçue quand il ouvre l'application, pas avant.** Le
service n'y perd rien — la notification est une commodité, la liste fait foi
(§2.6) ; l'utilisateur y perd l'immédiateté. (b) reste la porte si un exploitant
la veut : nommée ici, non écrite ; elle appellerait Apple, ce que C19 ne tolère
que comme un choix de l'exploitant, et elle demanderait sa propre spécification.

**macOS : la connexion tenue, et aucun serveur de poussée.** L'app du Mac est
résidente et tient sa connexion. Elle ouvre **`GET /v1/nouvelles`** (ci-dessous)
et reçoit une ligne par événement ; elle relit alors, et affiche une
notification **locale** — le système la montre sans passer par Apple. La
limite : la connexion tenue est celle que l'utilisateur a ouverte d'un Touch
ID ; si la veille ou un changement de réseau la rompt, la reconnexion redemande
le geste, et rien n'arrive jusque-là. Le même flux sert les apps Android et iOS
tant qu'elles sont au premier plan.

**Le repli, partout : la relecture à l'ouverture.** C'est ce qui marche quand
tout le reste échoue — poussée perdue, distributeur absent, iPhone. À
l'ouverture, et à chaque ligne de `GET /v1/nouvelles`, l'application relit
`GET /v1/autorisations` et montre **la différence** avec l'ensemble des `g-…`
reçus qu'elle a déjà montrés, qu'elle garde localement. Ni compteur ni date à
ajouter à l'annuaire : la liste est la vérité, la différence est locale.

### La sécurité : l'annuaire appelle une URL qu'un appareil lui a donnée

C'est la première fois qu'une racine se connecte à une adresse qu'elle n'a pas
choisie, et c'est une porte à trois abus : **la requête détournée** (SSRF — viser
un service interne, joignable du réseau de la racine et pas d'Internet),
**l'amplification** (faire envoyer la racine vers une victime), **le sondage**
(apprendre, aux erreurs et aux délais, ce qui répond derrière). Défenses :

1. **À la dépose, la forme** — dite plus haut : `https`, un nom DNS, le port 443,
   ni identifiants ni fragment, 1024 octets au plus.
2. **À l'envoi, l'adresse.** Le nom est résolu **à chaque envoi**, et si **une
   seule** des adresses rendues n'est pas une adresse unicast globale,
   l'envoi est refusé — le nom est tenu pour hostile, on ne se rabat pas sur
   une autre. Sont refusées : bouclage, non spécifiée, privées (RFC 1918,
   `fc00::/7`), lien local (`169.254.0.0/16`, `fe80::/10`), partage
   (`100.64.0.0/10`), multidiffusion, documentation, réservées, et toute
   adresse IPv4 enfouie dans une IPv6 (`::ffff:0:0/96`, `64:ff9b::/96`,
   `2002::/16`, Teredo) jugée comme l'IPv4 qu'elle porte. **La connexion se fait
   à l'adresse vérifiée**, sans nouvelle résolution — c'est ce qui défait le
   rebinding DNS, où la seconde résolution n'est plus la première ; le nom sert
   au SNI et à la vérification du certificat.
3. **Rien à suivre, rien à lire.** Une redirection est un échec, jamais un
   chemin ; de la réponse, seule la ligne de statut compte, le corps n'est pas
   lu ; **cinq secondes** pour tout — TCP, TLS, requête, statut.
4. **Rien à choisir pour l'attaquant**, sauf l'URL : la méthode (`POST`), les
   en-têtes et le corps (vide) sont fixes.
5. **Le débit, borné en mémoire** : un appareil est réveillé **une fois par
   minute** au plus par racine — dix autorisations dans la minute font un seul
   réveil ; un même hôte reçoit **soixante envois par minute** au plus ; **huit**
   envois au plus sont en vol. Rien de cela n'est rangé ni répliqué : ce sont
   des freins, pas des faits.

**Ce qui reste, et se dit.** Qui tient les appareils de B peut faire envoyer la
racine vers un hôte PUBLIC de son choix, un `POST` vide par minute et par
appareil ; sous une posture `optional`, les comptes sont libres, et c'est la
limite par hôte qui borne alors l'envoi vers une même victime — par racine :
deux racines, cent vingt par minute. Une limite qu'on ne peut pas tenir : un
distributeur à une adresse publique qui relaierait vers un réseau interne ; la
racine n'en sait rien, et c'est la responsabilité de qui l'exploite.

### Échec — une tentative, et pas de file

**Une tentative, jamais davantage, et rien ne se range pour plus tard** : c'est
une commodité, et une file persistante ferait d'un envoi raté une dette. Un
`2xx` est un succès. **`404` ou `410` : l'abonnement est mort** — l'utilisateur
a changé de distributeur ou s'est désinscrit ; la racine le retient **en
mémoire** et n'y envoie plus rien tant que l'appareil n'a pas déposé un point
neuf. Ce n'est ni rangé ni répliqué : chaque racine l'apprend à son premier
essai, et répliquer une mort ferait croire à une racine ce que l'autre a vu de
son réseau. **`429`, `5xx`, délai dépassé** : l'envoi est abandonné ; le prochain
événement réessaiera. Le journal d'exploitation dit les points morts
(l'appareil et le statut) et **chaque refus des règles d'adresse** (l'appareil,
l'hôte, la règle) — c'est ce qu'un exploitant doit voir en premier.

### Le client sortant — ce que la pile a déjà, et ce qu'elle n'a pas

Envoyer à un serveur Web Push demande un client **HTTPS sur TCP** ; ce dépôt ne
parle que HTTP/3 sur QUIC. La pile d'`air-mail-server` a ce qu'il faut pour le
TLS : `ams-tls` fournit un client TLS 1.3 en Rust pur (`rustls` avec
`rustls-rustcrypto`, pas une ligne de C), celui du relais de courrier sortant,
avec une vérification des certificats par `webpki` contre un magasin qu'on lui
donne. **Les racines viennent d'un fichier** que l'exploitant désigne,
`--push-roots <fichier PEM>` — typiquement le paquet de certificats de la
distribution —, épinglées comme `--android-roots` (C19) ; **sans ce réglage,
rien ne part**, le journal le dit au démarrage, et `GET /v1/nouvelles` reste
servi. La résolution passe par celle du système, comme le tireur la fait déjà
pour `--peer`. **HTTP/1.1, et le strict nécessaire** : `POST`, `Host`,
`TTL: 86400`, `Topic: nouvelles` (RFC 8030 §5.4 : un message neuf remplace chez
le serveur de poussée un message du même sujet encore en attente — la
coalescence se fait là aussi), `Urgency: normal`, `Content-Length: 0`,
`Connection: close` ; puis la ligne de statut. Pas de HTTP/2 : une requête
minuscule, une fois par minute au plus, n'en demande pas. **Et TLS 1.3
seulement** : un distributeur qui ne parle que TLS 1.2 n'est pas servi.

**Le repli, s'il le faut.** Un corps vide est un message Web Push valide
(RFC 8030) et le plus sûr à faire traverser un serveur de poussée. Si
l'épreuve sur un vrai téléphone montrait qu'un distributeur ou le connecteur ne
délivre pas un message vide, le repli est de chiffrer (RFC 8291) une
**constante** avec la clé et le secret que le connecteur fournit — d'où les
deux champs facultatifs du point, rangés dès maintenant : le message ne dirait
toujours rien, et seule la PR de code aurait à l'écrire. Pas de VAPID
(RFC 8292) en première version : ntfy ne l'exige pas ; si un distributeur
l'exige, ce sera une clé d'exploitant de plus, `--vapid-key`, nommée ici.

### `GET /v1/nouvelles` — les nouvelles, sur une connexion tenue

```
GET /v1/nouvelles
        (dans la connexion d'un appareil, prouvée)
{"quoi": "autorisation"}
{"quoi": "autorisation"}
…
```

**Exige un appareil**, et ne dit que son propre compte. **La réponse ne se
termine jamais**, comme `GET /v1/poussees` (§1.4) : `200`, sans
`content-length`, un objet par ligne, sans enveloppe. **Une ligne dit qu'il y a
du neuf, et de quel genre — rien d'autre** : l'application relit la liste qui
fait foi. La connexion est authentifiée, et le genre pourrait en dire plus sans
risque ; il ne le fait pas pour que les deux voies, poussée et flux, déclenchent
la même relecture. Un seul genre aujourd'hui, `autorisation` ; un lecteur saute
ceux qu'il ne connaît pas. **Ouvert à la demande, un par connexion**, et fermé
avec elle. Un second `GET /v1/nouvelles` sur la même connexion rend
**`409`** ; un appareil révoqué depuis sa preuve, **`401`**. **Une ligne ne
s'écrit que sur la racine qui a écrit l'autorisation** (décision 9, comme la
poussée) : un Mac dont la connexion tient l'autre racine l'apprend à la
relecture — la règle est la même que pour les deux voies, et l'écart est de ceux
que le repli couvre.

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

### Les domaines — ce qu'une recherche par alias rend, et ce qu'elle tait

**Décidé le 2026-09-26 (Thierry)** ; le modèle est dans `modele.md` §2.11 à
§2.13, l'autorité dans `annuaires.md` §2 bis. **Les verbes de la table sont
décidés dans leur forme** — chemins, corps, codes —, ceux des groupes et des
droits compris ; la PR de code peut encore les ajuster, et le dira.

```
GET /v1/domaines?alias=Maison
        (voie appareil ou voie machine — tout compte authentifié)

[{"domaine": "d-7Q2H…", "autorite": "racines"},
 {"domaine": "d-4K9M…", "autorite": "n-3P8X…"}]
```

**L'alias voyage pourcent-encodé** (PR du socle, 0.23.0) : c'est de l'UTF-8
libre, et une URL ne porte que de l'ASCII — `?alias=Maison%20%C3%A9t%C3%A9`.
Chaque octet est `%HH` (l'une ou l'autre casse) ou un caractère ASCII
graphique autre que `%`, `&`, `+`, `=` et `#` ; **`+` n'est pas une espace**
— ce n'est pas un formulaire. C'est la seule chaîne de requête de l'API qui
décode un pourcent — avec `GET /v1/alias?alias=…` depuis 0.26.0 : le chemin,
lui, les refuse tous. Deux écritures du même alias cherchent la même chose,
parce que ce qui est décodé est ensuite normalisé en NFC ; **la casse, elle,
compte** (décision 45). Un alias qu'on n'aurait pas pu poser rend `400`, et
`?alias=` seul aussi.

**Une liste, toujours.** L'alias de domaine n'est pas unique : deux domaines
« Maison » sont deux réponses, et aucune n'est la bonne — c'est celui qui
cherche qui reconnaît la sienne. `autorite` dit **qui fait autorité** sur ce
domaine : `racines`, ou l'annuaire local qui l'héberge.

**Ce qu'elle tait** : le propriétaire, les machines, les services. Savoir
qu'un domaine « Maison » existe n'ouvre rien — la résolution reste gardée par
les droits (§3, C10).

**Ce qui la borne, et pourquoi c'est assez.** Correspondance **exacte**, après
NFC, sensible à la casse (`modele.md` §2.11) : pas de préfixe, pas de
joker, pas de liste de tous les alias. Et **jamais sans preuve** : la
recherche exige une connexion authentifiée, appareil ou machine, contrairement
à `GET /v1/alias/{alias}` qui est public. **L'alias de domaine devient ainsi la
deuxième surface énumérable de l'annuaire** (§3, « Ce qui rend l'annuaire non
énumérable ») : on peut essayer des chaînes et apprendre lesquelles existent.
Elle rend moins que l'alias de compte — un `d-…` dont on ne peut rien faire —
et elle demande un compte pour être interrogée.

### Les autorisations d'hier — servies comme une vue des droits

**Décidé le 2026-09-26 (Thierry) que les autorisations deviennent des droits,
et que leurs verbes restent servis pendant la transition** (`modele.md` §2.13,
`replication.md` décisions 41 et 44 ; codé en 0.25.0). Les applications déployées —
Android 0.11, iOS/macOS 0.13 — accordent, listent et retirent par
`/v1/autorisations`. Les casser le jour de la mise à jour des racines serait
couper le partage à tous ceux qui ne mettent pas leur application à jour. Les
trois verbes restent donc, **comme une vue** :

| Verbe | Ce qu'il fait désormais |
|---|---|
| `POST /v1/autorisations` `{"a":"u-…","portee":…,"etiquette":…}` | Écrit un droit `voir` + `localiser` **au groupe personnel** de `u-…`, sur l'élément que nomme la portée — le service, la machine, ou **le compte** pour « tout mon compte ». Rend `{"autorisation":"g-…"}`, l'identifiant du droit. Réveille, comme avant. |
| `GET /v1/autorisations` | Rend, **sous la forme d'hier**, les droits qui s'y laissent dire : accordés par moi à un groupe personnel (`a` = son titulaire), et reçus par un de mes groupes (`a` = moi). **Octet pour octet la forme d'hier** — aucun champ nouveau : un droit converti se rend exactement comme l'autorisation qu'il était (décision 44). Un droit sans `localiser`, ou sur un domaine, n'y figure pas : ce n'était pas une autorisation. |
| `DELETE /v1/autorisations/{g}` | Retire le droit `g-…`. |

**La ligne du flux des nouvelles garde son genre**, `{"quoi":"autorisation"}` :
c'est sur elle que les applications déployées relisent, et un droit accordé à
un de mes groupes, ou mon ajout à un groupe qui porte des droits, est
exactement ce qu'elles doivent relire.

**La fin de la transition** : quand les applications appelleront
`/v1/groupes` et `/v1/droits`, les trois verbes pourront être retirés — une
rupture de protocole, donc un cran majeur, annoncée par `GET /v1/version`.
Jusque-là, ils coûtent une traduction, et rien d'autre : il n'y a qu'un
modèle, les droits, et deux façons d'en parler.

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

**Qui parle ce verbe.** `asl-server --invite --directory
<hôte:port>[=<n-…>] --operator-secret <fichier>` (l'identité attendue au
bout : la liste embarquée des racines, ou le `=<n-…>` ; `--ca` jusqu'à 0.34.0), et `asl-server --new-operator-key`
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

**`GET /v1/machines/{m}/services` ne regarde aucune autorisation de compte ni
de machine.** C'est l'écran qui montre MES machines ; les chemins inter-comptes
sont `GET /v1/ou` pour les services et `GET /v1/utilisateurs/{u}/machines` pour
les machines — chacun calculé depuis les arêtes du demandeur, jamais depuis ce
qu'il désigne (C10). **Depuis la 0.40.0, un droit sur le DOMAINE où `m` est
rangée l'ouvre** : `voir` sans adresse, `localiser` en entier (décision 104,
§3 « Les services d'une machine d'un AUTRE compte »).

**Une machine d'un domaine confié : ses services viennent de l'état fédéré**
(décision 60, 0.32.0). Elle s'annonce chez l'annuaire local, et rien n'en est
rangé chez les racines (C13) ; `GET /v1/machines/{m}/services` y ajoute donc ce
que les membres de l'annuaire local rapportent, **sous la même règle que la
résolution** : vivant si un membre le dit, `parti` (`volontaire: null`) si tous
ceux qui en parlent encore le disent parti, **absent** si plus personne ne le
confirme depuis l'expiration (30 s). **Un nom dont la racine tient la
ligne** — un service né aux racines avant que son domaine soit confié — **ne
se rend qu'une fois, et son état vient lui aussi de l'état fédéré** : la ligne
ne donne que l'identité (`service`), le rapport l'état et la réponse ; rien de
rapporté, `parti` (`volontaire: null`). La même règle vaut pour `GET /v1/ou`
(décision 99, 0.39.2). Ces objets portent deux champs de plus, que ne portent
pas les services tenus ici :

```jsonc
{"service":"s-…","nom":"depot","etat":"annonce","annonce":{…},
 "sonde_par":"n-…",      // le membre dont le rapport est retenu : c'est LUI qui a sondé
 "sonde_locale":true}    // le daemon est venu de l'une de SES adresses : il s'est sondé de l'intérieur
```

**`sonde_locale` est là parce que la joignabilité d'un service fédéré est
celle que l'annuaire local a constatée.** Quand il tourne sur la machine même
(speedy, 27/09), il se sonde de l'intérieur : « joignable » ne dit alors rien
de ce qu'un client verra dehors — l'essai réel l'a montré, un pare-feu bloquait
le port en IPv6 que la sonde disait joignable. La règle : le daemon est venu
(`vu_depuis`) d'une adresse **littérale** où l'on joint le membre (ses
locateurs publiés, sinon son adresse déclarée) ; une IPv4 habillée en IPv6
(`::ffff:…`) est déshabillée ; un nom ne fait rien conclure (C20). Un lecteur
d'hier, qui lit par clés, ignore les deux champs.

### Les machines d'un utilisateur — ce qu'une autorisation donne à voir

```jsonc
GET /v1/utilisateurs/{u}/machines
[{"machine": "m-…", "nom": "grenier"}, {"machine": "m-…", "nom": "nas"}]
```

**Depuis le 2026-09-26, ce sont les droits `voir` (et `localiser`, qui
l'emporte) qui décident de cette liste** (`modele.md` §2.13) ; ce qui suit le
dit dans les mots d'hier, qui restent exacts pour une autorisation convertie.

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

**Depuis la 0.39.0, la voie machine LIT aussi les domaines** — pour
`asl domain <d-…|alias>`, qui liste ce qui est rangé dans un domaine :

| Route | Sur la voie machine | Ce qui décide |
|---|---|---|
| `GET /v1/domaines?alias=…` | Déjà (0.24.0) — toute machine qui a prouvé sa clé | `[{"domaine","autorite"}]`, rien de plus. |
| `GET /v1/domaines` | **0.39.0**, une machine qui porte `lecture` | Les domaines du propriétaire de la machine, et ceux où l'un de ses groupes tient un droit — la même liste que sur la voie appareil. Sans `lecture` : `[]`. |
| `GET /v1/domaines/{d}` | **0.39.0**, une machine qui porte `lecture` | Le même objet que sur la voie appareil : `machines` pour qui a `voir` (ou `localiser`, ou `administrer`) sur le domaine, `groupes` pour qui l'administre ; `404` pour qui n'y tient rien, et pour une machine sans `lecture` (C10). |
| `GET /v1/machines/{m}/services` | **0.39.0**, une machine qui porte `lecture` | Le propriétaire de `m` : tout ; **depuis la 0.40.0** (décision 104), qui tient `localiser` sur le domaine où `m` est rangée : tout ; qui n'y tient que `voir` (ou `administrer`) : les services **sans adresse** ; `[]` sinon (`asl_auth::decider_services_de_machine`). |
| `GET /v1/ou/{m}/{s}`, `GET /v1/ou?service=…` | Déjà | `localiser` (§3 ci-dessus). |
| `POST /v1/echo/jetons` | **0.42.0** (décision 91, §3 quater), une machine qui porte `lecture` ; aux racines seulement — un annuaire local rend `421` | `localiser` sur `asl-echo` de la machine visée — la décision de `GET /v1/ou/{m}/asl-echo` ; `404` sinon (C9). |

**Seules ces lectures s'ouvrent** : créer, supprimer, nommer, confier un
domaine, y ranger une machine, ses groupes, ses droits restent à un appareil
(`401` sur la voie machine) — la raison de l'exigence d'un appareil ne change
pas. La capacité `lecture` se juge à l'étage 3, comme pour
`GET /v1/utilisateurs/{u}/machines`.

**Les services d'une machine d'un AUTRE compte, rangée dans un domaine où le
demandeur tient un droit** — tranché (Thierry, 2026-09-29 ; décisions 103 et
104, 0.40.0), **pour tout domaine, le domaine racine compris** :

- **`voir`** sur le domaine (ou `administrer`, qui l'emporte) :
  `GET /v1/machines/{m}/services` rend la liste — identifiants, noms, état —
  **sans adresse**. Un service vivant y porte un objet d'annonce **vide** :

  ```jsonc
  [{"service":"s-…","nom":"depot","etat":"annonce","annonce":{}},
   {"service":"s-…","nom":"nas","etat":"parti","volontaire":null}]
  ```

  `sonde_par` et `sonde_locale` y restent pour un service fédéré (un `n-…` et
  un booléen, pas une adresse). Un parti est le même objet que pour le
  propriétaire.
- **`localiser`** sur le domaine : la liste entière, **objet d'annonce
  compris** — bail, adresse observée, candidats —, celle du propriétaire ;
  et `GET /v1/ou/{m}/{s}`, `GET /v1/ou?service=…` rendent ses services
  (décision 103).
- **Rien** : `[]`, comme pour une machine sans service (C9).

**Pourquoi cette route, et pas `GET /v1/domaines/{d}`.** Le détail d'un
domaine est UN objet, borné à 4 Kio (`MESSAGE_MAX`) : y mettre les services de
chaque machine le ferait déborder dès quelques machines. La liste des services
est une liste, bornée à soixante-quatre éléments de 4 Kio chacun. Et la forme
passe les décodeurs déployés : `asl` 0.22 lit un objet d'annonce vide comme un
service annoncé (il n'exige qu'un objet) ; les applications Android et iOS le
lisent vivant, sans point ni diagnostic. Un mot d'état nouveau (« vivant »)
aurait été lu « parti » par les deux applications.

**Ranger sa machine dans le domaine d'un autre, c'est accepter les droits de
ce domaine sur elle** : qui y tient `voir` voit ses services, qui y tient
`localiser` les localise. Le rangement reste un geste de son propriétaire, et
de lui seul (`PUT /v1/machines/{m}/domaine`, avec `rattacher` sur le domaine) ;
il le défait quand il veut (`DELETE`).

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
  **Depuis le 2026-09-26, l'alias de domaine en est une seconde** — exacte,
  réservée aux comptes authentifiés, et qui ne rend que des `d-…` (§2.2,
  « Les domaines »).
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

### Un service d'un domaine hébergé se résout aux racines

**Décidé le 2026-09-26** (`annuaires.md` §5.4). Quand la machine visée est
rattachée à un domaine qu'un annuaire local héberge, `GET /v1/ou` répond **aux
racines**, avec ce que l'annuaire local leur a transmis — l'adresse, le port,
vivant ou non —, **et sous la même règle** : seulement si le demandeur tient
`localiser` sur ce service, par l'un de ses groupes (C10, `modele.md` §2.13), et la même réponse, après le même délai, pour un
service hors de portée et pour un service inexistant (C9). Le client ne sait
pas, et n'a pas à savoir, que le service vit derrière un annuaire local.

### Résoudre un annuaire local : `asl-directory`

**Décidé le 2026-09-28 (Thierry ; décisions 73 à 85, `annuaires.md` §2
quinquies), précisé le 2026-09-29 (décisions 86 et 87) ; fait en 0.38.0.** Un
annuaire local accepté se résout comme un service, **sous le `n-…` de son
titulaire** :

```
GET /v1/ou/{n-…}/asl-directory
200  avec `localiser` : {"service":"s-…","annuaire":"n-…","adresses":["hôte:port",…],"identites":"n-… n-…"}
200  avec `voir` seul : {"service":"s-…","annuaire":"n-…"}
404  aucun membre vivant, hors du cercle, ou aucun annuaire sous ce `n-…` —
     la même réponse, après le même délai (C9)
```

**Le corps est celui du `421`** (§3 ter), plus `service` : pour chaque membre
**vivant** — sa voie tient vers cette racine —, ses locateurs publiés, sinon
son adresse déclarée (décision 81), et au même rang de `identites` le `n-…`
qu'on doit trouver au bout. **Ce n'est pas une réponse d'annonce** : celle-ci ne
tolère aucun champ inconnu (§1.1, `asl-proto`), et un champ de plus y casserait
les clients ; le chemin par `n-…` est nouveau, et le lecteur de renvoi
d'aujourd'hui lit ce corps, dont il saute `service`. **`voir` sans `localiser`**
reçoit le même `200` sans `adresses` ni `identites` — absents, pas vides : on
omet ce qui n'est pas accordé, comme une liste (§2.2), et C9 garde ses deux
seules réponses (décision 80). **`administrer` n'emporte pas `localiser`**
(décision 87) : un administrateur d'un domaine hébergé reçoit ce corps réduit,
et s'accorde `localiser` s'il veut les adresses. **Personne ne l'annonce** : les racines le
synthétisent, et une annonce du nom `asl-directory` est refusée (`403`, et une
ligne au journal), aux racines — avant le `421` — comme chez un annuaire
local. **Le `service`** est `asl_registre::asl_directory_derive(n)` :
`SHA-256("asl/annuaire/1" ‖ n (16 octets) ‖ "asl-directory")[0..16]` ; pour
speedy, `n-7MSV5RPCXBZH25PQM4ZPE5X87P` → `s-294B4BA9XHXFZ5DQ8Q7T35M7PY`. **Un
autre nom sous un `n-…`** reste la faute d'identifiant d'hier (`400`) ; **le
`n-…` du second membre** ne nomme pas l'annuaire, et rend `404`. **Chez un
annuaire local**, ce chemin est renvoyé aux racines (`421`, décision 62),
comme toute résolution.
**Vivant** veut dire qu'une voie tient, pas que la maison est joignable du
dehors — aucune sonde en v1 (décision 83). **Le cercle est étroit** (décision
79) : le propriétaire, les administrateurs des racines, qui tient un droit sur
un domaine hébergé ; **le `421`, lui, reste servi à toute machine rattachée**,
quel que soit son compte. **Servi sur la voie machine seulement** (décision
86) : c'est le moyen des machines — daemons, `asl`. **Les applications ne le
lisent pas** : la tuile de l'annuaire tient son état du champ `voie` de
`GET /v1/annuaires` (§2.2), et la voie appareil n'a pas ce chemin.
`GET /v1/ou?service=` ne rend aucun annuaire. **Les racines n'en ont pas** : `GET /v1/racines`
(§2.2).

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

## 3 ter. La voie de l'annuaire local

**Décidé le 2026-09-26 (Thierry) : qu'elle existe, ce qu'elle porte, et sa
forme sur le fil** (`annuaires.md` §2 bis, §5.4, `replication.md` décision 36),
qui reprend la voie entre racines (§3 bis) partout où elle convient.

Le cinquième public : **un annuaire local inscrit**. Il n'est pas une racine —
il ne fait autorité sur aucun compte —, et il n'est pas un daemon — il parle
pour toutes les machines de ses domaines.

**Il OUVRE, vers chaque racine.** Contrairement à la voie entre racines, où
c'est le lecteur qui ouvre, ici c'est toujours l'annuaire local : il est à la
maison, derrière un NAT que les racines ne traverseraient pas, et une connexion
sortante passe. Il en tient **une par racine**, pour que chacune reçoive
l'état de ses services directement — rien d'observé ne passe par la voie entre
racines (`replication.md` §1).

```
GET  /v1/defi
POST /v1/defi              genre `n` ‖ n-… (17) ‖ signature (64)
                                        prouve sa clé d'identité, comme une racine
POST /v1/annuaires/inscription   code ‖ clé ‖ preuve   la première fois : lie la clé
                                  au code que l'application a obtenu (§2.2) — 0.27.0
GET  /v1/federation/machines     SANS FIN — les machines rattachées à ses domaines :
                                  m-…, clé, capacités, puis leurs changements et
                                  leurs révocations
POST /v1/federation/etat         SANS FIN, dans l'autre sens — ses services :
                                  s-…, machine, nom, adresse, port, vivant ou non,
                                  et chaque changement
```

**Ce que la 0.27.0 sert de cette esquisse** (`replication.md` décision 51) :
la présentation et la relecture de l'état, **sans** le `POST /v1/defi` de
genre `n` — le corps porte la clé et sa preuve de possession, comme un
enrôlement, et l'on n'a pas eu à ouvrir une seconde manière de prouver une
clé.

**Ce que la 0.28.0 sert : la voie** (`replication.md` décision 52), avec un
écart. **Pas de flux sans fin** : la pile QUIC ne relève jamais la fenêtre
d'un flux, et un flux montant que le client écrirait sans fin s'y tairait.
Deux verbes courts, que l'annuaire local répète à sa cadence et dès que ce
qu'il sert change :

```
POST /v1/defi                    genre `n` ‖ n-… ‖ signature — sa clé, comme une racine
GET  /v1/federation/machines?apres=<rang>
        200  des MachineFederee à la suite : n-… (17) ‖ enregistrement Machine
             de l'entrepôt — taille fixe, rangées par identifiant, une part au
             plus ; pleine, on redemande depuis le rang suivant
POST /v1/federation/etat         des EntreeDEtat à la suite, huit kibioctets au plus :
             s-… (17) ‖ m-… (17) ‖ longueur du nom (1) ‖ nom ‖ vivant (1)
             [‖ longueur (2, gros-boutiste) ‖ réponse d'annonce, 4 096 au plus
              [‖ port (2) ‖ via (1)          — drapeau 2, un écho (0.44.0)
               [‖ adresse externe (4)]]]     — drapeau 3, un écho (0.45.0,
                                               décision 107)
        204  rangé ; 403 une entrée hors de ses domaines (C11), rien n'est rangé ;
        404  l'inscription n'est plus acceptée
PUT  /v1/federation/locateurs    {"locateurs":["[IPv6]:port","IPv4:port",…]} — de
             zéro à quatre, chacun de la forme d'une adresse déclarée (0.30.0)
        204  publiés — une publication identique n'écrit rien ; vide, un
             retrait : l'adresse déclarée sert de nouveau ;
        400  un locateur de travers, ou plus de quatre ;
        404  l'inscription n'est plus acceptée
PUT  /v1/federation/paire        {"pair":"n-…"} — le n-… de la clé de son --peer-key —,
             ou {"pair":null} sans --peer (0.36.0, décision 70)
        200  {"annuaire":"n-titulaire","membres":["n-titulaire","n-second"]} :
             son annuaire et ses membres ACCEPTÉS, lui compris ;
        400  un corps de travers ; 404  l'inscription n'est plus acceptée
```

**La paire, jugée par le membre** (0.36.0, décision 70). À chaque tour — dix
secondes —, le membre dit son `--peer` et apprend les membres acceptés de son
annuaire ; **c'est lui qui juge**, et il n'en refuse pas de servir :

| Mot | Quand |
|---|---|
| `seul` | aucun autre membre accepté, pas de `--peer` |
| `reglee` | `--peer` désigne l'autre membre accepté |
| `sans-peer` | un autre membre est accepté, et ce membre tourne sans `--peer` — **le titulaire comme le second** : chacun l'apprend des racines |
| `peer-inconnu` | `--peer` désigne une clé qui n'est celle d'aucun autre membre accepté |

Les deux derniers se disent **au journal** dès qu'on les apprend, puis toutes
les dix minutes tant qu'ils durent — `asl-server : PAIRE MAL RÉGLÉE (sans-peer) :
les racines disent que cet annuaire local (n-…) a un autre membre accepté, n-…,
et ce membre tourne SANS --peer — …` —, et **`GET /v1/version`** du membre porte
`"paire":"<mot>"`. Les racines jugent de même, des mêmes données, et
**`GET /v1/annuaires`** (et `GET /v1/inscriptions`) rend `"paire":"<mot>"` pour
chaque membre qui le leur a dit depuis qu'elles tournent — c'est ce que l'écran
de l'annuaire affiche. Une racine d'avant la 0.36.0 répond `404` : le membre le
dit une fois par session, et continue.

**Le `s-…` d'une `EntreeDEtat` est celui du membre qui rapporte** (constaté le 2026-09-28) : chaque membre d'une paire frappe le sien pour le même `(machine, nom)`, la racine les range par membre, et `GET /v1/ou` rend celui du rapport retenu. Une paire qui se réplique (`--peer`) converge vers un seul au premier rattrapage ; une paire qui ne se parle pas en garde deux, et le `s-…` rendu change à chaque bascule. Défaut, pistes et questions : `annuaires.md` §2 ter, « L'identifiant d'un service dans une paire ». **Décidé (2026-09-28, Thierry ; décisions 65 et 66)** : un seul `s-…` par service, dérivé de la machine et du nom — **fait en 0.37.0** ; le format de l'entrée ne change pas. Un membre en 0.37.0 rapporte le dérivé ; un membre encore en 0.36.0 rapporte son aléa, que la racine rend tel quel (c'est lui qui tient le daemon) **et qu'elle signale** : la ligne « fédération : n-… rapporte N service(s) … » de son journal ajoute « K sous un identifiant qui n'est pas le dérivé : ce membre n'est pas encore en 0.37.0 ». Une fois les deux membres à jour, les deux rapports portent le même `s-…`, et la racine ne rend plus qu'un identifiant.

**Où le joindre, dit par lui** (décision 57, 0.30.0) : l'annuaire local publie
ses locateurs à **chaque ouverture** de sa voie — `--locator <hôte:port>`,
répétable, quatre au plus ; aucun, c'est un retrait. L'opération répliquée
`inscription-locateurs` les porte d'une racine à l'autre (le plus récent gagne,
par membre) ; le `421` et `GET /v1/annuaires` les rendent. **Le localisateur
se détecte** (décision 64, 0.35.0) : `--locator auto[:<interface>]` publie
l'adresse IPv6 globale stable de la machine, la relit à la cadence de la
fédération, et la republie **dans la session** quand elle change — un
`PUT /v1/federation/locateurs` de plus sur la voie ouverte, que la racine
prend pour le même membre. Sans adresse candidate, rien n'est publié, et la
racine garde la dernière (`annuaires.md` §2 quater).

La réponse d'annonce est **l'objet que `GET /v1/ou` rend**, encodé par
l'annuaire local : les racines le rendent tel quel à qui peut le localiser.
Et une racine qui reçoit l'annonce d'une machine d'un domaine confié répond
**`421`** avec `{"annuaire":"n-…","adresses":["hôte:port",…],"identites":"n-… n-…"}` :
pour chaque membre accepté, les locateurs qu'il a publiés, ou son adresse
déclarée s'il n'en a publié aucun (décision 57) — huit au plus pour une paire.
**`identites` dit, rang par rang, l'identité du membre au bout de chaque
adresse** (décision 59, 0.31.0) : le second d'une paire a SA clé, et c'est
elle qu'un client doit attendre en le joignant, pas celle du titulaire que
porte `annuaire`. C'est une **chaîne**, des `n-…` séparés d'une espace, et non
une liste d'objets : le lecteur d'hier (client 0.16/0.17) ne saute une clé
inconnue que si sa valeur est une chaîne — il ignore donc `identites` et suit
les mêmes adresses. Un annuaire d'avant 0.31.0 ne l'écrit pas : le client
attend alors `annuaire` au bout de chaque adresse, comme hier.

**Le `421` reste tel quel** (décision 78) ; sa forme sert aussi de corps à
`GET /v1/ou/{n-…}/asl-directory` (§3, « Résoudre un annuaire local »), qui
rend, sans attendre une annonce mal adressée, les seuls membres vivants.
**Leurs cercles diffèrent, et c'est voulu** (décision 79) : le `421` va à
toute machine rattachée à un domaine confié, quel que soit son propriétaire —
sans lui, elle ne pourrait plus annoncer —, l'`asl-directory` aux seuls comptes
qui tiennent un droit sur un domaine hébergé.

**L'exigence est nouvelle** : une clé d'identité `n-…` **inscrite et
acceptée**, pas celle de `--peer-key`. Une racine qui reçoit un `POST /v1/defi`
de genre `n` cherche donc la clé dans deux endroits — son pair, et les
inscriptions acceptées — et ce qu'elle accorde n'est pas la même chose : la
voie entre racines d'un côté, celle-ci de l'autre. Une inscription retirée
ferme la connexion, comme une clé de machine révoquée.

**Ce que la racine vérifie de chaque cadre reçu** (C11) : que la machine est
rattachée à un domaine que CET annuaire héberge. Sinon, refus et journal — et
le flux se ferme, comme sur une opération illisible entre racines
(`replication.md` §5.2).

**Une paire** (`annuaires.md` §2 ter) : chaque membre ouvre sa propre voie,
prouve sa propre clé, et reporte ce que lui voit ; les racines savent que les
deux parlent pour le même annuaire, et tiennent l'état par membre. Entre eux,
les deux membres se répliquent comme deux racines (§3 bis, `--peer`).

**Côté annuaire local** : un `asl-server` qui reçoit `--federation
<hôte:port>` — **une fois par racine** (0.28.0 : chacune sa voie, puisque
l'état ne se réplique pas entre elles) — avec le `n-…` de chaque racine,
attendu dans la poignée de main (`<hôte:port>=<n-…>`, ou la liste embarquée ;
§0, « Qui l'on croit » — `--federation-ca` a servi jusqu'à 0.34.0), et
sa clé d'identité (`--identity-key`) ; il publie aussi **ses propres
locateurs** (décision 57 : `PUT /v1/federation/locateurs`), pour
qu'un préfixe IPv6 qui change chez un particulier ne demande rien à personne ; il
authentifie les annonces des daemons de ses domaines avec les clés que
`GET /v1/federation/machines` lui transmet, et reporte leur état. Il n'a
**aucun compte** : ses domaines appartiennent à des comptes qui vivent aux
racines.

**Et il le fait respecter** (`replication.md` décision 62, 0.33.0) : il ne
sert lui-même que `/v1/defi` (pour une machine de ses domaines), `/v1/annonce`
et `/v1/poussees`, `/v1/vu`, `/v1/version`, `/v1/racines`, et la voie de sa
paire (`/v1/pair/*`, `/v1/replication`). Tout autre verbe reçoit **`421`**, dont
le corps est la liste des racines (la forme de `GET /v1/racines`) : c'est là
qu'on crée un compte, qu'on administre un domaine, qu'on accorde un droit et
qu'on résout un service.

**La visite IPv4** (décision 107, 0.45.0 ; §3 quater, « Chez un annuaire
local ») : à côté de la voie, **à chaque ouverture puis tous les quarts
d'heure**, le membre ouvre une connexion courte vers l'adresse IPv4
littérale de chaque racine (la liste embarquée), y prouve sa clé
(`POST /v1/defi`, genre `n`), lit `GET /v1/vu`, et ferme. La racine retient,
par membre et en mémoire, l'adresse IPv4 observée sur toute connexion où un
membre accepté a prouvé sa clé — trente minutes. Sans adresse IPv4 de la
racine, ou sans IPv4 sortante, pas de visite : c'est dit au journal, et les
racines ne sondent pas en IPv4.

## 3 quater. L'écho — `asl-echo` et `asl ping`

**Décidé (2026-09-29, Thierry ; décision 89)** — et c'est tout ce qui l'est :

1. **Un service `asl-echo` sur chaque machine enrôlée, sur un port
   aléatoire** — **tiré dans la plage réservée UDP 6631–6639** depuis la
   décision 105 (ci-dessous). `asl echo` — une sous-commande d'`asl`, pas un
   nouveau binaire — écoute sur un port choisi au hasard dans cette plage et
   **le publie par son annonce** `asl-echo`, dont le bail est tenu par la
   connexion comme celui d'`asl announce`. On le retrouve par l'annuaire
   (`asl where <m-…> asl-echo`). **Aucun port fixe** : l'aléa demeure, à
   l'intérieur de la plage.

**Décidé (2026-09-29, Thierry ; décision 105) : l'écho tire son port au hasard
dans une plage réservée, UDP 6631–6639.** L'essai réel l'a montré : un port
tiré dans tout l'espace éphémère se heurte au pare-feu **de la machine** —
nitrogen et argon ont une table nft `inet asl` en politique `drop`, helium et
speedy ont ufw —, et UPnP n'ouvre que la box, jamais ce pare-feu-là. Chaque
exploitant ouvre donc **une fois pour toutes** cette plage dans le pare-feu de
la machine :

```sh
# nft, dans la table de la machine (ici `inet asl`, chaîne d'entrée `entree`)
nft add rule inet asl entree udp dport 6631-6639 accept

# ufw
sudo ufw allow proto udp from any to any port 6631:6639 comment 'asl-echo'
```

**Neuf ports, et c'est assez** : un écho par machine, et le tirage n'a qu'à
éviter un port déjà pris sur la même machine — un redémarrage en tire un
autre. La plage suit celle de l'annuaire (6630, `--listen`), et ne la
recouvre pas. **Côté serveur, rien ne change** : la sonde va au port observé
(ou accordé par la box), quel qu'il soit, et l'annuaire n'exige pas la
plage — une machine qui l'aurait ouverte autrement n'est pas refusée. Le
client la code de son côté (`asl echo`).
2. **Deux sondes, et deux seulement, sont autorisées** : celle de
   **l'annuaire**, qui constate la joignabilité, et **`asl ping <m-…|alias>`**,
   lancé par un compte qui en a le droit.

**Le but** : un « ping applicatif » qui prouve qu'une machine est joignable
**et que c'est bien elle** — la preuve est une signature de sa clé —, depuis
l'annuaire ou depuis n'importe où. Il comble trois trous que la sonde
d'aujourd'hui laisse (`modele.md` §4.3) :

- **l'UDP n'est jamais sondé** : aucun écho générique, donc `non_sonde`
  (`crates/asl-loop-tokio/src/sonde.rs:86-91`, `RaisonNonSonde::ProtocoleNonSondable`) ;
- **un port TCP ouvert ne prouve pas l'identité** : la sonde d'aujourd'hui est
  un trois-temps ouvert puis refermé vers le seul candidat réflexif
  (`sonde.rs:104-110`, `tokio::net::TcpStream::connect` sous trois secondes),
  et derrière un NAT partagé ou sur une adresse réattribuée, c'est peut-être
  quelqu'un d'autre qui a répondu ;
- **rien ne se vérifie à la demande** : la sonde part à l'annonce et au
  changement de candidat (`asl-loop-tokio/src/h3.rs:2820-2860`,
  `lancer_les_sondes`), jamais quand quelqu'un se demande « est-ce que je la
  joins, d'ici, maintenant ? ».

**La forme a été proposée par la spécification, puis tranchée** : Thierry a
retenu chacune des recommandations des questions E1 à E14 (« d'accord pour
tout », 2026-09-29), inscrites comme **décisions 90 à 93** — 90 : le
transport, la socket, la signature, le nom (E1, E2, E3, E13) ; 91 : qui
l'écho croit, le jeton, les droits (E4, E5, E6, E7) ; 92 : les sondes des
annuaires (E8, E9) ; 93 : l'installation, `asl ping`, l'activation (E10,
E11, E12, E14). **Décision 94** : l'écho parle UPnP derrière une passerelle
résidentielle ; sa forme a été proposée par les questions E15 à E23, et
Thierry en a retenu chaque recommandation de même (« d'accord pour tout »,
2026-09-29) — **décisions 95 à 98** : 95 : la passerelle active par défaut,
sa durée, quand on cherche la box (E15, E18, E23) ; 96 : notre client UPnP,
puis PCP et NAT-PMP (E16, E17) ; 97 : ce que l'annuaire en apprend — double
NAT, trou IPv6, `passerelle` et `echo_via` (E19, E20, E21) ; 98 : le Mac et
l'attestation (E22). **Décision 106** (2026-09-29, Thierry, « option
(b) ») : quand la box refuse le trou IPv6 mais redirige en IPv4, l'écho tient
son bail en IPv4 (« Quand la box ne perce pas son pare-feu IPv6 », plus bas).
**Décision 107** (2026-09-29, Thierry, « option (i) ») : quand ce bail va à
un annuaire local, les racines voient l'adresse IPv4 de la box du membre, et
l'écho la confirme (« Chez un annuaire local », plus bas).
**Décision 108** (2026-09-30, Thierry) : la socket de l'écho se lie à
l'adresse IPv6 **stable** de la machine, pour qu'une règle posée à la main
dans une box qui refuse UPnP ne meure pas avec une adresse temporaire — le
revers, la traçabilité de la machine, est assumé (« L'écho se lie à l'adresse
IPv6 STABLE », plus bas).
**Aucune question ne reste ouverte dans cette section.**

### Ce que l'écho est, et ce qu'il n'est pas

**Un service comme un autre, annoncé comme un autre** — `asl echo` ouvre sa
propre connexion, prouve la clé de la machine, annonce `asl-echo` avec **un
seul point `udp:<port>`**, et tient. Un redémarrage tire un autre port et
réannonce ; la règle ordinaire (`modele.md` §2.4) remplace l'ancien.

**Il ne répond qu'à une sonde autorisée, et à personne d'autre** : aux autres,
le silence. Il ne sert rien, ne relaie rien, ne tient aucun état par sondeur
au-delà d'une mémoire courte des défis vus (l'anti-rejeu, ci-dessous).

**Ce qu'il prouve** : qu'**un datagramme parti d'ici** a atteint **un
processus qui détient la clé privée de cette machine**, à cette adresse, sur
ce port, et qu'une réponse est revenue. **Ce qu'il ne prouve pas** : que les
AUTRES services de la machine sont joignables — chacun a son port, son
pare-feu, son daemon. L'écho mesure la machine et son chemin, pas ses
services ; la sonde TCP des services reste ce qu'elle est.

**Le nom est réservé à cette forme** (décision 90 ; E13) : une annonce
`asl-echo` porte exactement un point, en UDP, sinon `400`. Qui annonce ce nom
n'a pas à être `asl echo` — la clé est par machine (`modele.md` §2.3), tout
processus qui la lit peut s'annoncer sous n'importe quel nom —, et ce n'est
pas une faille : la preuve est la signature, pas le programme qui la fait.

### Le transport : des datagrammes UDP bruts, et pourquoi pas QUIC

**Des datagrammes UDP, un aller et un retour, dans un format binaire à
nous, versionné** (décision 90 ; E1).

| | UDP brut, un défi signé | QUIC (poignée de main, puis une requête) |
|---|---|---|
| Allers-retours | **Un.** | Deux au moins (poignée de main, puis la requête). |
| État chez l'écho avant d'avoir vérifié quoi que ce soit | **Aucun** : il lit, vérifie, répond ou se tait. | Une connexion par sondeur — la nôtre pèse **cent trente-six kibioctets** (`air-service-locator-client`, `crates/asl-client-tokio/src/lib.rs:167-178`). Un inconnu qui en ouvre mille, c'est cent trente-six mégaoctets. |
| Amplification | **Nulle, par construction** : la réponse est plus petite que la requête (ci-dessous). | Bornée à trois fois (RFC 9000 §8.1) : un Initial de 1 200 octets peut faire répondre 3 600. |
| Ce qu'il faut pour prouver l'identité | Une signature Ed25519 sur un défi — ce que la machine sait déjà faire (`asl-cle`). | Un certificat pour la clé `m-…`, et un vérificateur de plus : le « TLS direct entre machines » que §0 nomme et repousse. |
| Silence envers un inconnu | Naturel : on ne répond pas. | La poignée de main répond avant de savoir à qui. |

**QUIC resterait le bon choix pour PARLER** ; ici, on ne parle pas, on
**prouve** en un aller-retour. Et C15 n'est pas touchée : l'écho n'écrit pas
une seconde pile QUIC, il n'en a pas besoin.

**Le codec est un codec** (C1) : une crate d'étage 1, sans entrée-sortie,
couverte à 100 % (C2), fuzzée (C3), sans une ligne de C (C4) — sous le
nom `asl-echo`, dans ce dépôt, tirée par le client comme `asl-proto` l'est
(`Cargo.toml` du client, `rev` épinglée).

**Fait en 0.41.0.** `crates/asl-echo` lit et écrit les trois datagrammes et
le jeton (`SondeAnnuaire`, `SondeJeton`, `Reponse`, `Jeton`, ce dernier aussi
en 386 chiffres hexadécimaux), et décide hors ligne : `asl_echo::accepter`
prend un datagramme reçu et rend la sonde acceptée — défi, sondeur — ou la
raison du silence ; `SondeAcceptee::repondre` signe la réponse pour la source
observée ; `Reponse::verifier` dit au sondeur si la preuve tient, et sinon
pourquoi (autre défi, autre sondeur, autre machine, autre clé) ;
`Jeton::verifier` est la vérification du jeton par l'écho. Les clés crues —
l'annuaire du bail, les racines embarquées — sont passées par l'appelant, qui
tient aussi le débit et la mémoire des défis vus. Les quatre séparateurs sont
dans `asl-cle` (`DomaineEcho`, `CleSecrete::signer_echo`,
`ClePublique::verifie_echo`). Des vecteurs figés
(`crates/asl-echo/tests/vecteurs.rs`) sont calculés hors du code, par
`tests/fixtures/vecteurs.py` sur une autre bibliothèque Ed25519 ; quatre
cibles de fuzz, une par décodeur (`fuzz_asl_echo_*`). **Deux précisions**
que le format impliquait sans les écrire : une adresse au **port nul** est
refusée à la lecture ; l'écho refuse un jeton dont la validité n'est pas
comprise entre zéro (exclu) et soixante secondes — une racine n'en délivre
pas d'autre.

**TCP** : pas en v1 (décision 90 ; E1). Si un réseau de sondeur bloque l'UDP
sortant, le même format voyagerait sur TCP, préfixé de sa longueur — une
extension, pas un second protocole. Rien aujourd'hui ne dit qu'il le faut.

### La socket : celle du bail, et c'est ce qui rend l'UDP joignable derrière un NAT

**Décidé (décision 90 ; E2) : `asl echo` tient son bail SUR la socket où il
écoute.** Une seule socket UDP, liée à un port de la plage 6631–6639
(décision 105) ; la connexion QUIC
vers l'annuaire en part, et les datagrammes de l'écho y arrivent.

C'est ce que `modele.md` §3 disait déjà du seul candidat réflexif UDP utile —
« si le daemon envoie son annonce **depuis la socket sur laquelle il
écoute**, le NAT crée un mapping pour cette socket-là » — et ce que
`protocole.md` §4.1 repoussait faute de canal. L'écho le réalise **pour lui
seul**, sans rien demander au daemon d'un autre :

- **le candidat réflexif porte le port OBSERVÉ**, et non le port annoncé — pour
  `asl-echo` seulement. La règle d'aujourd'hui
  (`crates/asl-annuaire/src/lib.rs:515-519` : « l'adresse OBSERVÉE et le port
  ANNONCÉ — jamais le port observé ») reste vraie pour tout autre service, dont
  la socket QUIC n'est pas celle du service ; pour l'écho, elle l'est ;
- **le mapping reste ouvert** par le keepalive du bail, dix secondes
  (`modele.md` §4.1), sans rien de plus ;
- **le point annoncé garde le port local** : c'est lui que les candidats
  `annoncé` portent, pour qui sonde depuis le même réseau.

**Ce que cela demande au client** : aujourd'hui la socket est **connectée** à
l'annuaire (`crates/asl-client-tokio/src/lib.rs:255-262`,
`UdpSocket::bind` puis `socket.connect(annuaire)`), et le noyau jette tout
datagramme d'une autre source. L'écho la veut non connectée, et **trie à
l'arrivée** : un paquet QUIC v1 a toujours le bit `0x40` du premier octet
posé (RFC 9000 §17 ; RFC 9443 §2) ; l'écho commence par un octet de `0x04` à
`0x0F`, une plage que ni QUIC, ni STUN, ni DTLS, ni RTP n'emploient
(RFC 7983 §7, RFC 9443). Un seul octet décide, sans ambiguïté.

**Ce que cela ne donne pas, et il faut le dire.** Un NAT à filtrage dépendant
de l'adresse laisse entrer **tout port de l'annuaire** — puisqu'on lui a
parlé — et rien d'autre : la sonde de l'annuaire, même partie d'un autre port
(ci-dessous), aboutira, et un `asl ping` d'ailleurs non. C'est exact, et c'est
précisément la question que `asl ping` sert à poser : **l'annuaire dit
« joignable depuis l'annuaire », `asl ping` dit « joignable d'ici »**, et les
deux peuvent différer.

**L'alternative écartée** (E2, b) : une socket d'écho distincte de celle du bail. Plus
simple côté client — rien ne change dans `asl-client-tokio` —, mais derrière
un NAT IPv4 le candidat réflexif n'y vaut que si l'on a redirigé le port à la
main, et le mapping n'est tenu par rien.

**IPv6 d'abord, IPv4 en repli.** La socket est liée à **l'adresse IPv6 stable
et globale de l'interface qui sert le bail** (décision 108, plus bas), et à
`[::]:<port de la plage>` en double pile (`IPV6_V6ONLY` à zéro) quand il n'y en
a pas — ou que le système ne dit pas laquelle l'est ; `0.0.0.0:<port>` si la
machine n'a pas d'IPv6 ; le bail
part en IPv6 d'abord (§0). L'annonce porte, dans `adresses_locales`, **toutes**
les adresses non locales de la machine — IPv6 globales d'abord, puis IPv4 —,
au plus `ADRESSES_MAX`, et non plus la seule qui a servi à joindre l'annuaire
(`asl announce` d'aujourd'hui : `crates/asl-cli/src/commandes.rs:469-478` du client) : un
sondeur du même réseau essaie les annoncées, un sondeur du dehors la
réflexive. **L'adresse IPv6 annoncée est celle à laquelle la socket est
liée** (décision 108) : une socket liée ne reçoit rien d'autre, et le verdict
de NAT se prend sur cette comparaison. **Le candidat réflexif est d'une seule famille**, celle du bail :
une machine joignable en IPv6 et en IPv4 ne le verra dit que dans la
première. Tenir deux baux pour avoir les deux est écarté en v1. **Sauf
quand la box ne laisse entrer qu'en IPv4** : le bail passe alors en IPv4,
sur la même socket (décision 106, « Quand la box ne perce pas son pare-feu
IPv6 », plus bas) — c'est pourquoi la double pile est posée
explicitement, et non laissée au réglage du système.

#### L'écho se lie à l'adresse IPv6 STABLE de la machine

**Décidé (2026-09-30, Thierry ; décision 108).** La socket de l'écho est liée
à **l'adresse IPv6 stable et globale** de l'interface qui sert le bail, quand
la machine en a une — et non plus à `[::]`, qui laisse le système choisir
l'adresse SOURCE, c'est-à-dire, là où les adresses temporaires tournent
(macOS par défaut, Linux souvent), **une adresse qui aura disparu demain**.

**Pourquoi — le constat d'oxygen (30/09).** La Livebox ne laisse ouvrir son
pare-feu IPv6 que vers un équipement **choisi dans une liste fermée**, et
l'adresse qu'elle propose pour un équipement donné est une **ancienne adresse
temporaire, déjà dépréciée**. Une règle posée à la main dans l'interface de la
box meurt donc avec l'adresse qu'elle nomme : le lendemain, l'écho écoute
ailleurs. Le trou UPnP y échappe — l'écho le redemande à chaque tour, pour
l'adresse du moment (`AddPinhole`, « IPv6 : un trou dans le pare-feu ») —
**mais une règle manuelle n'a personne pour la redemander.** Liée à l'adresse
stable, l'écho ne bouge plus, et une règle manuelle devient tenable. Oxygen
porte huit adresses sur `en5` ; la stable est
`2a01:cb19:d27:2f00:144b:b441:5901:6706`, la temporaire du moment
`2a01:cb19:d27:2f00:157e:db0b:296a:f355`.

**Le revers, et il est assumé.** Une adresse IPv6 stable **suit la machine sur
l'Internet** : elle est la même pour tout correspondant, et permet de
reconnaître cette machine d'un site à l'autre — c'est précisément ce que les
adresses temporaires de RFC 8981 servent à empêcher. **Thierry l'a tranché en
connaissance de ce revers** (2026-09-30) : la joignabilité durable de l'écho
passe devant. **Et la portée est bornée** : c'est la socket de `asl echo` —
donc le bail de l'écho et ses réponses de sonde — qui est liée ainsi, **rien
d'autre sur la machine** ; `asl announce`, un navigateur, un courrielleur
gardent le choix du système et ses adresses temporaires. L'écho, de toute
façon, publie déjà une adresse : c'est son métier que d'être joignable.

##### Ce qui compte comme stable

Une adresse candidate est **globale et stable** :

- **globale** : ni lien-local (`fe80::/10`), ni boucle, ni multicast, ni
  indéterminée, ni IPv4 enfouie (`::ffff:a.b.c.d`) ;
- **et pas une ULA** (`fc00::/7`) : une ULA est stable, mais **elle ne sort
  pas de la maison** — l'annuaire ne la verrait pas, aucune sonde du dehors
  ne l'atteindrait, et le pare-feu de la box n'a rien à y ouvrir. Ce qu'on
  cherche ici est une adresse **que le dehors peut joindre** ;
- **ni temporaire** (RFC 8981 ; sous Linux, `IFA_F_TEMPORARY`) : c'est celle
  qui tourne, et c'est tout le problème ;
- **ni dépréciée** (`IFA_F_DEPRECATED`) : elle ne sert plus qu'aux
  connexions en cours, et disparaîtra ;
- **ni provisoire** (`IFA_F_TENTATIVE`), **ni en échec de DAD**
  (`IFA_F_DADFAILED`) : on ne se lie pas à une adresse dont le réseau n'a pas
  encore dit qu'elle est à nous.

Une adresse stabilisée par RFC 7217 (« autoconf secured ») et une adresse
posée à la main entrent toutes deux dans cette définition : ce qui est demandé
est qu'elle ne tourne pas, non la façon dont elle a été formée.

**L'interface est celle qui sert le bail**, et elle se connaît sans rien
appeler de nouveau : le système dit déjà quelle adresse source il prendrait
pour joindre l'annuaire (c'est ce que l'écho lit pour `adresses_locales`) ;
l'interface de CETTE adresse est celle qu'on retient, et l'on choisit parmi
ses adresses. Se lier à l'adresse stable d'une autre interface serait se
lier là où la route ne passe pas.

**Si plusieurs restent, le choix est déterministe** : **la plus petite dans
l'ordre de ses seize octets**. Un redémarrage reprend donc la même, tant que
le préfixe tient — et deux exploitants qui regardent la même machine y
trouvent la même réponse. (Ni « la première rendue par le système », qui ne
promet aucun ordre, ni « la plus récente », qui rendrait l'adresse mouvante
que l'on fuit.)

##### Quand il n'y en a pas, ou plus

- **Aucune adresse stable** sur l'interface du bail — une machine qui n'a que
  des adresses temporaires, ou dont la seule globale est dépréciée : **l'écho
  garde le choix du système** (`[::]`, comme avant), et **le dit une fois** :
  « pas d'adresse IPv6 stable sur l'interface du bail : le système choisit —
  une règle posée à la main dans la box ne tiendra pas ».
- **Le système ne dit pas les drapeaux** (§ suivant : macOS) : même repli,
  même ligne, et la raison est dite.
- **La stable disparaît en service** (le préfixe change, l'opérateur
  renumérote) : le bail tombe avec elle, et l'écho le rouvre — il relit alors
  les adresses et se lie à celle du moment. Rien de particulier n'est prévu :
  un préfixe qui change est déjà ce qui fait tomber un bail.
- **Elle devient dépréciée** sans disparaître : on ne s'y relie pas au tour
  suivant ; le bail en cours, lui, n'est pas coupé pour cela — une adresse
  dépréciée fonctionne encore.

##### Comment on la connaît, sans une ligne de C (C4)

- **Linux** : `/proc/net/if_inet6`, que le client lit déjà pour les index
  d'interface (« La passerelle », le M-SEARCH). Chaque ligne y porte
  l'adresse en hexadécimal, l'index de l'interface, la longueur du préfixe, la
  portée, **les drapeaux** et le nom du périphérique ; `IFA_F_TEMPORARY` vaut
  `0x01`, `IFA_F_DEPRECATED` `0x20`, `IFA_F_TENTATIVE` `0x40`,
  `IFA_F_DADFAILED` `0x08`.
- **macOS : il n'y a pas de moyen sans C, et on ne l'invente pas.** Les
  drapeaux d'une adresse IPv6 s'y lisent par `getifaddrs` puis l'ioctl
  `SIOCGIFAFLAG_IN6` (`IN6_IFF_TEMPORARY`, `IN6_IFF_DEPRECATED`) — du C, donc
  de l'`unsafe`, que C4 refuse et qu'aucune crate du graphe n'enveloppe.
  Lire la sortie d'`ifconfig` serait un programme tiers dont on analyserait le
  texte : la même voie que celle qui a déjà été écartée pour la table de
  routage. **Donc : sous macOS, l'écho garde le choix du système**, et le dit
  (la ligne ci-dessus). Le jour où une crate sans C expose ces drapeaux, ou
  qu'une frontière `unsafe` existe pour cela dans ce dépôt, la règle
  s'appliquera là aussi sans rien changer d'autre.

##### Ce que cela change à l'annonce, et à la bascule en IPv4

**L'annonce doit porter l'adresse liée** — et c'est la seule chose qui change
ailleurs. Une socket liée à une adresse précise **ne reçoit que ce qui est
destiné à cette adresse**, et n'en émet pas d'autre : si l'annonce portait
l'adresse temporaire que le système aurait choisie, un sondeur du même réseau
parlerait à une adresse où l'écho n'écoute pas, et surtout **le verdict de NAT
dirait « oui »** — l'annuaire compare l'adresse observée aux adresses
annoncées (`modele.md` §4.3), et `echo_via` dirait `nat` là où il doit dire
`direct`. L'adresse à laquelle la socket est liée est donc celle que
`adresses_locales` annonce pour l'IPv6.

**La bascule en IPv4 rouvre la socket** (décision 106). Une socket liée à une
adresse IPv6 ne peut pas parler IPv4 : la double pile n'est possible que liée
à `[::]`. Quand la passerelle demande le passage en IPv4, l'écho **ferme sa
socket et la relie au MÊME port**, en `[::]` double pile (ou `0.0.0.0`), puis
rouvre le bail ; au retour en IPv6, il se relie à l'adresse stable. **Le port
ne change jamais** : c'est lui que la box redirige, et lui que le pare-feu de
la machine laisse entrer (décision 105). Le mapping NAT de l'ancienne socket
tombe avec elle, ce qui est sans effet : une bascule rouvre de toute façon le
bail, et l'annuaire réobserve tout (« La bascule », plus haut).

##### Côté serveur, rien ne change — vérifié

L'annuaire voit une adresse globale, comme avant ; elle ne tourne plus, voilà
tout. Le candidat réflexif, la sonde par l'écho, le verdict de NAT, l'état
`echo*`, le rapport d'un membre aux racines, la sonde du dehors : aucun ne
regarde **comment** une adresse a été formée, ni si elle est temporaire —
`asl_annuaire::adresse_globale` juge la portée, et une adresse stable globale
la passe comme n'importe quelle autre. **C'est une décision du client seul**,
comme la 106. Un bénéfice s'ensuit toutefois, et il vaut d'être dit : une
adresse qui ne tourne plus rend `sonder_du_dehors` moins bavard (la cible ne
change plus à chaque renouvellement d'adresse) et « constaté à » plus
comparable d'un quart d'heure à l'autre.

### La passerelle : UPnP, pour mettre toutes les chances de son côté

**Décidé (2026-09-29, Thierry ; décision 94) : « pour mettre toutes les
chances de son côté, `asl echo` doit aussi parler UPnP quand il est derrière
une passerelle résidentielle ; normalement toutes les box le proposent. »**
C'est la première route de `modele.md` §6.3 — « le daemon demande lui-même
une redirection à sa box » —, prise **pour l'écho seul**. La forme qui suit
a été proposée par les questions E15 à E23, puis **tranchée** (2026-09-29,
Thierry ; décisions 95, 96 et 97).

**Ce que la passerelle ajoute à la socket partagée (décision 90).** Le bail
tient déjà un mapping NAT ouvert, mais il ne laisse entrer que ce que le NAT
veut bien laisser entrer : un NAT à filtrage dépendant de l'adresse ne laisse
passer que l'annuaire. **Une redirection demandée à la box laisse entrer
tout le monde** sur ce port-là — c'est ce qui rend l'écho joignable d'un
`asl ping` lancé d'ailleurs.

#### IPv4 : une redirection du port de l'écho, et de lui seul

- **La découverte** : SSDP, **sur le réseau local seulement** — un `M-SEARCH`
  vers `239.255.255.250:1900` (IPv4) et `[ff02::c]:1900` (IPv6, lien local),
  `ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2` puis `:1`, portée
  d'un saut. **Aucun tiers n'est appelé** (C19) : ni serveur STUN, ni service
  « quelle est mon adresse ». **Aucun DNS** (C20) : la réponse donne une URL
  `LOCATION` ; elle n'est suivie que si son hôte est **une adresse littérale
  égale à celle qui a répondu**, privée ou de lien local — un nom est ignoré.
- **La description** (`GET` de `LOCATION`, HTTP/1.1 en clair, sur le réseau
  local) donne l'URL de contrôle du service `WANIPConnection:2`, sinon `:1`
  (ou `WANPPPConnection:1`).
- **La redirection** : IGD v2 — `AddAnyPortMapping`, qui laisse la box
  choisir le port externe et le rend ; IGD v1 — `AddPortMapping`, en
  demandant d'abord **le même port externe que le port local**, puis, sur
  `718 ConflictInMappingEntry`, trois ports tirés au hasard. Toujours
  `NewProtocol = UDP`, `NewInternalPort` = **le port de l'écho**,
  `NewInternalClient` = **l'adresse locale d'où l'on a parlé à la box**,
  `NewRemoteHost` vide, `NewPortMappingDescription = "asl-echo"`.
- **L'adresse externe** : `GetExternalIPAddress`, comparée à `vu_depuis` que
  l'annuaire a rendu à l'annonce. **Égales** : la box est bien le dernier
  NAT, et la redirection vaut depuis l'Internet. **Différentes** — une adresse
  `100.64.0.0/10`, une autre privée, une autre publique — : il y a **un
  second NAT** au-dessus (celui de l'opérateur, ou une box derrière une box),
  la redirection ne sert à rien depuis l'Internet, et `asl echo` le dit
  (« double NAT : la box n'est pas la dernière — la redirection ne suffira
  pas ») sans rien annoncer de plus (**décidé**, décision 97 ; E19).

#### IPv6 : un trou dans le pare-feu, si la box le propose — et c'est rare

En IPv6, il n'y a rien à traduire : l'adresse de la machine est globale. Ce
qui bloque est **le pare-feu à état de la box** — la mesure de `modele.md`
§4.1 l'a montré, la borne est la même qu'en IPv4. IGD v2 définit pour cela
`WANIPv6FirewallControl:1` : `GetFirewallStatus` (le pare-feu est-il actif,
et les trous permis ?), puis `AddPinhole` — `RemoteHost` et `RemotePort`
libres, `InternalClient` = l'adresse IPv6 globale d'où le bail part,
`InternalPort` = le port de l'écho, `Protocol = 17` (UDP), `LeaseTime` — qui
rend un `UniqueID`, renouvelé par `UpdatePinhole` et retiré par
`DeletePinhole`.

**Il faut le dire honnêtement : c'est rare.** Beaucoup de box n'annoncent pas
ce service ; quand elles l'annoncent, `GetFirewallStatus` rend souvent
`InboundPinholeAllowed = 0`, et l'on n'a alors le droit de rien. Rien n'en a
été mesuré ici : le banc `bancs/nat` devra relever, box par box, ce qu'elles
proposent. **Ne pas l'obtenir n'est pas une panne** : `asl echo` tente, et se
tait si le service est absent (il le dit en mode bavard) — **décidé**,
décision 97 ; E20. **Mais ce n'est plus un cul-de-sac** quand la même box
redirige en IPv4 : voir la sous-section suivante (décision 106).

#### Quand la box ne perce pas son pare-feu IPv6 : le bail passe en IPv4

**Décidé (2026-09-29, Thierry ; décision 106, « option (b) »).** Constaté
derrière une Livebox, sur trois machines (speedy, helium, oxygen) : la box
refuse le trou (`AddPinhole` → `606 Action not authorized`), accorde la
redirection (`udp 66xx → box 193.250.159.198:66xx`), et le bail, parti en
IPv6, ne peut pas l'annoncer — l'annuaire ne sonde que l'adresse qu'il a vue
(ci-dessous), et il a vu l'IPv6, que le pare-feu de la box ferme. L'écho
n'est alors joignable que de l'intérieur, **alors que la box a précisément
ouvert de quoi le joindre du dehors**. La décision : **l'écho tient son bail
en IPv4**, pour que l'annuaire voie l'adresse externe de la box et sonde la
redirection.

**Les conditions — toutes les trois**, lues à un tour de la passerelle :

1. **aucun trou IPv6 obtenu** : `AddPinhole` refusé (`606`, toute autre
   faute), `InboundPinholeAllowed = 0`, ou pas de service
   `WANIPv6FirewallControl` du tout. **Un pare-feu IPv6 inactif**
   (`FirewallEnabled = 0`) **n'en est pas une** : la box laisse alors tout
   entrer en IPv6, et le bail y reste ;
2. **une redirection IPv4 accordée** pour le port de l'écho (IGD v1 ou v2,
   bail d'une heure ou permanente) ;
3. **une adresse externe publique** : `GetExternalIPAddress` rend une
   adresse, et elle n'est ni privée (RFC 1918), ni partagée
   (`100.64.0.0/10`, RFC 6598), ni de lien local, de bouclage ou nulle. Une
   adresse externe non publique, c'est un double NAT **déjà visible** — la
   box n'est pas la dernière —, et le bail reste en IPv6 sans rien tenter.

Il faut encore, côté machine, **que la socket de l'écho sache l'IPv4** — une
double pile, ou une socket IPv4 seule, auquel cas le bail y était déjà — et
**qu'un annuaire ait une adresse IPv4** dans la liste. À défaut, l'écho le
dit et reste en IPv6. **Chez un annuaire local** — le bail va au membre, sur
le réseau de la maison, et aucun annuaire n'a d'adresse IPv4 qui verrait la
box —, c'est la décision 107 qui prend le relais (« Chez un annuaire local »,
plus bas) : le bail reste en IPv6, et l'écho confirme l'adresse externe.

**La bascule.** L'écho ferme le bail IPv6 — la connexion, donc l'annonce —,
puis rouvre **sur la même socket** (ou sur une socket reliée au même port,
quand elle était liée à l'adresse IPv6 stable : décision 108, « Ce que cela
change à l'annonce, et à la bascule en IPv4 »), vers les seules adresses IPv4
des annuaires (racines, ou l'annuaire local d'un renvoi), et réannonce : sans
`passerelle` d'abord, pour apprendre `vu_depuis`, puis avec, comme partout
(« Comment l'annuaire l'apprend »). **La même socket** : le port local ne
change pas, la redirection que la box tient vise toujours le bon port, et le
mapping NAT que le keepalive tient est celui de cette socket (décision 90).
Fermer avant de rouvrir : il n'y a jamais deux baux de l'écho à la fois. Un
annuaire qui ne répond pas en IPv4 dans la patience d'`asl announce` fait
revenir en IPv6, et la bascule n'est pas retentée avant le tour suivant de la
passerelle (trente minutes).

**La vérification, après la bascule.** Le premier `vu_depuis` du bail IPv4
est comparé à l'adresse externe que la box a dite :

- **égales** : la box est bien le dernier NAT. L'annonce part avec
  `"passerelle": {"port": <port externe redirigé>, "via": "upnp"}` — le port
  que la box a accordé, qui n'est pas forcément celui de l'écho —,
  l'annuaire sonde `vu_depuis:<port externe>` en tête, et l'état dit
  `echo_via: upnp` quand la preuve arrive par là ;
- **différentes** : un double NAT que l'adresse externe ne montrait pas (la
  box a une adresse publique, mais on sort par ailleurs — un second
  routeur, un VPN, une route par défaut qui ne passe pas par elle).
  L'écho le dit (« double NAT : la box dit A, l'annuaire nous voit depuis
  B — le bail revient en IPv6 »), **revient en IPv6**, et ne rebascule pas
  tant que la box dit la même adresse externe.

**L'hystérésis : on ne rebascule pas à chaque tour.** La passerelle
recommence toutes les trente minutes (« La durée ») ; ce qui a décidé la
bascule n'est pas réexaminé à chaque fois. **Le bail reste en IPv4 tant que
la redirection tient** et que `vu_depuis` reste l'adresse externe de la box.
Il **revient en IPv6** dans trois cas seulement :

- **un trou IPv6 devient possible** — la passerelle continue de le demander
  en IPv4, et l'obtient (une box reconfigurée, une mise à jour) : le bail
  revient là où l'écho est joignable sans traduction, et annonce le trou ;
- **la redirection est perdue** — refusée au renouvellement, la box ne
  répond plus, ou plus de box : en IPv4, sans elle, l'écho n'a que le
  mapping du bail, et l'IPv6 vaut au moins autant ;
- **le double NAT se révèle** (ci-dessus) : `vu_depuis` et l'adresse
  externe de la box divergent.

Un bail IPv4 perdu pour une autre raison — l'annuaire redémarre, le réseau
tombe — se rouvre **en IPv4** : la bascule tient d'un bail à l'autre, et
seuls les trois cas ci-dessus la défont. Un arrêt de l'écho l'oublie : au
démarrage suivant, le bail part en IPv6, et le premier tour de la passerelle
décide de nouveau.

**Ce que dit le journal** — une ligne à chaque changement, pas à chaque
tour : « le bail passe en IPv4 : la box ne perce pas son pare-feu IPv6, mais
redirige udp N » à la bascule ; « le bail revient en IPv6 : » suivi de la
raison (trou obtenu, redirection perdue, double NAT, annuaire muet en IPv4)
au retour.

**Côté serveur, rien ne change.** Un bail IPv4 d'`asl-echo` est un bail
comme un autre : son candidat réflexif est `vu_depuis` — ici l'adresse
externe de la box — au port observé, la passerelle place en tête
`vu_depuis` au port accordé (`asl-annuaire`, `Session::candidats`), et
`echo_via` dit `upnp` quand c'est la passerelle qui a prouvé — y compris
quand la box a redirigé le même port externe que celui du mapping, et que les
deux candidats n'en font qu'un (`asl-loop-tokio`, `SondeDEcho::du_bail`). La
bascule elle-même est une fermeture de bail suivie d'une annonce : le service
passe `parti` le temps de la reconnexion, puis `annonce`. Le décodeur
d'annonce, la sonde, le rapport d'un membre d'annuaire local aux racines
n'ont rien à apprendre. **C'est une décision du client seul.**

#### Chez un annuaire local : les racines voient l'adresse de la box, l'écho la confirme

**Décidé (2026-09-29, Thierry ; décision 107, « option (i) »).** La décision
106 ne sert pas une machine d'un domaine **hébergé** : son bail va au membre
de l'annuaire local, sur le réseau de la maison, et aucun annuaire n'a
d'adresse IPv4 qui verrait celle de la box — le membre voit l'IPv6 globale de
la machine, ou son adresse privée. Constaté sur speedy, helium et oxygen,
dans air-dictator-house, dont l'annuaire local est la paire speedy + helium :
la Livebox refuse le trou (`606`), accorde la redirection, et **personne
dehors ne connaît son adresse IPv4 publique**. Les racines sondent alors
l'IPv6 que le membre a vue (décision 92), que le pare-feu de la box ferme :
`injoignable`, alors que la box a ouvert de quoi joindre l'écho.

**Le principe** : **l'annuaire local fait OBSERVER l'adresse IPv4 publique de
sa box par les racines**, en leur parlant en IPv4 ; l'écho dit l'adresse
externe que la box lui a donnée, **à titre de confirmation seulement** ; et
une racine ne sonde `adresse:port` du dehors que si **l'adresse que l'écho
confirme est celle qu'elle a elle-même observée** chez ce membre. L'adresse
sondée est toujours une adresse **qui a parlé à la racine** ; elle n'est
jamais choisie par un client (E21, décision 97, la règle de `modele.md` §4.3).

##### 1. La visite IPv4 — comment les racines voient la box du membre

**Une connexion courte, en IPv4, vers chaque racine, à côté de la voie** —
et non une seconde voie, ni la voie passée en IPv4 :

```
(IPv4, vers l'adresse IPv4 de la racine, la même identité attendue qu'à la voie)
POST /v1/defi    genre `n` ‖ n-… ‖ signature — la même preuve que la voie
GET  /v1/vu      {"adresse":"193.250.159.198","port":…,"famille":4}
(fermée)
```

- **Pourquoi pas une seconde voie IPv4** : les rapports d'état partiraient
  deux fois, la racine tiendrait deux voies par membre (`voie` de
  `GET /v1/annuaires`, décision 86, suit UNE connexion), et tout l'état
  vivant doublerait pour apprendre une adresse.
- **Pourquoi pas la voie passée en IPv4** : elle tient l'IPv6 d'abord (§0),
  et le membre y perdrait ce que l'IPv6 lui donne ; ce serait une seconde
  exception à §0 pour un besoin qu'une visite remplit.
- **Pourquoi pas un verbe nouveau** : `GET /v1/vu` existe, n'exige rien, et
  dit exactement ce qu'il faut ; la preuve de clé qui le précède est celle de
  la voie. **Rien de nouveau sur le fil de la visite** : c'est la racine qui
  retient, pas un verbe qui publie.
- **Le membre n'a pas à rapporter l'adresse** : la racine la tient de sa
  propre observation ; la lui faire répéter ne lui apprendrait rien qu'elle
  ne vérifierait de toute façon contre ce qu'elle a vu. Le membre la lit
  (`GET /v1/vu`) pour son journal, et c'est tout.

**Ce que la racine retient.** Sur **toute connexion où un membre accepté a
prouvé sa clé** — la visite, ou la voie elle-même si elle est en IPv4 —, la
racine note l'adresse observée **si elle est IPv4** (une IPv4 vue par une
socket double pile, `::ffff:a.b.c.d`, est déshabillée) et l'instant, **par
membre, en mémoire** (C13 : comme l'état vivant, jamais dans l'entrepôt, pas
répliquée entre racines). Elle l'oublie **trente minutes** après la dernière
observation — deux visites manquées. Une connexion en IPv6 n'efface rien. La
visite ne touche pas à la voie : ce n'est pas sur elle que la voie vit ou
tombe (décision 86).

**Vers quelle adresse.** L'adresse IPv4 **littérale** de la racine, lue dans
la liste embarquée pour l'identité que la voie attend (`asl-racines` :
`178.32.16.250:6630` pour nitrogen, `178.32.16.249:6630` pour argon) ; aucun
nom n'est résolu (C20). **Si la voie est déjà en IPv4** — `--federation` a
donné une adresse IPv4 —, il n'y a pas de visite : la voie est observée.

**Quand.** À chaque ouverture de la voie, puis **tous les quarts d'heure**
tant qu'elle tient — la cadence de la décision 92, celle des sondes qu'elle
sert. Elle ne fait jamais tomber la voie : un échec se dit, et la visite
suivante réessaie.

**Quand elle ne peut pas se faire — et c'est dit, pas contourné** :

- **la racine n'a pas d'adresse IPv4 connue** (une racine hors de la liste
  embarquée, désignée par `<locateur IPv6>=<n-…>`) : pas de visite, une ligne
  au journal par session (« pas d'adresse IPv4 connue pour cette racine :
  elle ne verra pas l'adresse IPv4 de la box ») ;
- **le membre n'a pas d'IPv4 sortante**, ou la racine ne répond pas en IPv4
  dans la patience de la voie : une ligne au journal au changement (« visite
  IPv4 vers … impossible : … »), et la visite suivante réessaie ;
- **dans les deux cas**, la racine n'a rien observé, et **ne sonde pas en
  IPv4** (ci-dessous) : l'écho reste ce qu'il était — la sonde de
  l'intérieur du membre, la sonde du dehors vers l'IPv6 du bail.

Le journal du membre dit l'adresse vue, **au changement** :
« fédération vers … : vue en IPv4 depuis 193.250.159.198 (visite) ».

##### 2. Ce que l'écho annonce : l'adresse externe, en confirmation

**Un membre de plus dans `passerelle`, facultatif** :

```jsonc
"passerelle": {"port": 51377, "via": "upnp", "externe": "193.250.159.198"}
```

- **Une chaîne IPv4 en notation pointée**, rien d'autre : une IPv6, un nom,
  une chaîne de travers — `400`. Le décodeur ne juge pas si elle est publique
  ; c'est l'usage qui le juge (ci-dessous).
- **Elle n'est jamais une cible** : elle **confirme** — elle dit « la box qui
  m'a accordé ce port a cette adresse » —, et une adresse n'est sondée que si
  une racine l'a observée elle-même chez le membre.
- **Quand `asl echo` l'écrit — toutes à la fois** : le bail va à un
  **annuaire local** (un renvoi, `421`) ; **aucun trou IPv6** n'a été obtenu
  (les conditions 1 à 3 de la décision 106 : pas de trou, une redirection
  IPv4 accordée, une adresse externe publique, lue par
  `GetExternalIPAddress` — celle que le double NAT lit déjà) ; et
  **l'annuaire local est en 0.45.0 au moins** (`GET /v1/version` : un membre
  d'avant refuserait le champ, et l'annonce entière avec lui). Sinon, rien ne
  change : `passerelle` part sans `externe`, ou ne part pas.
- **Ce que l'annuaire du bail en fait** : **rien de plus que ne pas se
  tromper**. Le candidat de la passerelle est `vu_depuis` au port accordé
  (décision 97) **seulement si `externe` est absente ou égale à l'adresse
  observée** ; sinon — le cas d'ici : un bail IPv6, un port IPv4 —, il n'y a
  pas de candidat de passerelle chez lui, et le membre ne sonde que le bail,
  comme avant. Il n'essaie jamais `externe` lui-même : ce serait une adresse
  choisie par un client, et, vue du réseau de la box, une boucle par la box.

##### 3. Ce que le membre rapporte

**Un drapeau de plus dans l'entrée d'état** (`POST /v1/federation/etat`,
§3 ter) :

| Drapeau | Ce qui suit la réponse d'annonce |
|---|---|
| `1` vivant | rien |
| `2` vivant, avec passerelle (0.44.0) | port (2, gros-boutiste) ‖ `via` (1) |
| **`3` vivant, avec passerelle et adresse externe (0.45.0)** | port (2) ‖ `via` (1) ‖ **l'adresse externe (4, octets de réseau)** |

Le membre écrit `3` quand l'annonce de l'écho porte `externe`, `2` sinon.
**Une racine d'avant la 0.45.0 refuse ce drapeau**, et le rapport entier avec
lui : **les racines se déploient d'abord**, comme en 0.44.0. Le membre
rapporte ce que l'écho a dit, sans le juger : c'est la racine qui compare.

##### 4. Quand la racine sonde, et quand elle se tait

Pour un écho fédéré dont le rapport porte une adresse externe `E` et un port
`P`, rapporté par le membre `M` :

1. **`O`, l'adresse IPv4 que cette racine a observée chez `M`**, depuis
   moins de trente minutes (la visite, § 1) ;
2. **si `O` existe, `O == E`, et `E` est globale**
   (`asl_annuaire::adresse_globale` : ni privée, ni partagée, ni bouclage,
   ni lien-local, ni nulle), la racine place **`E:P` en tête** de ses
   candidats du dehors, avec le `via` de la passerelle, puis celui d'avant
   (l'adresse que le membre a vue, au port observé, **si elle est
   globale**) ; les bornes de la décision 92 tiennent — **une sonde par
   changement de cible et au plus tous les quarts d'heure**, dans les
   soixante-quatre en vol ; la cible, pour ce calcul, est la première de la
   liste ;
3. **sinon, aucune sonde vers `E`** : la racine sonde ce qu'elle sondait
   avant (l'adresse du bail, si globale), et **le dit** au journal, au
   changement seulement, par machine :
   - `O` absente : « écho de m-… : la box dit E, mais l'annuaire local n-…
     ne nous a pas parlé en IPv4 depuis trente minutes — pas de sonde en
     IPv4 » ;
   - `O ≠ E` : « écho de m-… : la box dit E, l'annuaire local n-… nous parle
     depuis O — autre box, ou double NAT — pas de sonde en IPv4 » ;
   - `E` non globale (un écho qui aurait écrit une adresse privée malgré la
     règle) : « écho de m-… : adresse externe E non globale — pas de sonde
     en IPv4 ».

**Ce qui prouve se dit comme partout** : `echo: verifie`, `echo_par` à la
racine, **`echo_depuis: exterieur`**, **`echo_via: upnp`** (le `via` de la
passerelle) quand la preuve vient de `E:P`. Aucun champ nouveau dans l'état
de la machine : les discordances se disent au journal de la racine, pas aux
applications.

##### Ce que cela ouvre, et ce que cela borne

- **L'adresse sondée a parlé à la racine** — sur une connexion où la clé
  d'un annuaire local accepté a été prouvée. Le client ne choisit que le
  port, comme avant (décision 97) ; son adresse ne fait que confirmer.
- **Le pire qu'une machine d'un domaine hébergé obtienne** en mentant sur
  `externe` : rien, si ce n'est pas `O` ; si c'est `O`, qu'une racine
  envoie **un datagramme de 384 octets, signé, par quart d'heure**, vers
  l'adresse publique de la maison de l'annuaire local — au port de son
  choix. Borné, et l'annuaire local est l'autorité de ses domaines (C11).
- **Une machine hors de la maison** (un portable d'un domaine hébergé,
  derrière une autre box) : `E ≠ O`, pas de sonde en IPv4 — c'est exact :
  sa box n'est pas celle que la racine a vue.
- **Une paire** : chaque membre fait sa propre visite ; chaque racine compare
  à ce qu'elle a vu du membre qui rapporte l'écho, et de lui seul.
- **`asl ping` d'ailleurs ne l'apprend pas** : `GET /v1/ou/{m}/asl-echo`
  rend l'objet du membre, sans `E:P`. **Nommé et repoussé** : le jour où il
  le faut, la racine ajoutera `E:P` aux candidats qu'elle rend, une fois
  prouvé par elle.
- **Rien ne change pour une machine dont le bail est aux racines** : la
  décision 106 la sert déjà, et `externe`, si elle l'écrivait, ne ferait
  que ne pas contredire `vu_depuis`.

#### La durée : un bail court, renouvelé, retiré au propre

- **Une heure, renouvelée à mi-course** (toutes les trente minutes), tant que
  l'écho tourne — IGD v2 interdit d'ailleurs le bail infini
  (`NewLeaseDuration = 0`).
- **Une box qui n'accepte que le permanent** (`725
  OnlyPermanentLeasesSupported`, fréquent en IGD v1) : on le demande
  permanent, et c'est alors à nous de le retirer (**décidé**, décision 95 ;
  E18).
- **À l'arrêt** — Ctrl-C, `SIGTERM` de systemd ou de launchd — :
  `DeletePortMapping` et `DeletePinhole`, **avant** de fermer le bail.
- **Après un arrêt brutal** : `asl echo` retient dans son répertoire d'état
  ce qu'il a ouvert (port externe, `UniqueID`), et **le retire au démarrage
  suivant** avant d'ouvrir autre chose. Un bail d'une heure borne de toute
  façon ce qui traîne.
- **Quand la box refuse, ou n'a pas UPnP** — aucune réponse SSDP,
  `606 Action not authorized`, UPnP désactivé dans son interface — :
  **l'écho continue sans**, avec la socket du bail seule, et le dit une fois
  (« pas de passerelle UPnP : joignable depuis l'annuaire, peut-être pas
  d'ailleurs »). Il recherche la passerelle au démarrage, toutes les trente
  minutes, et quand son adresse change (**décidé**, décision 95 ; E23).

#### Comment l'annuaire l'apprend, la sonde, et le dit

**L'annonce de l'écho porte ce que la box a accordé** — **décidé**
(décision 97 ; E21) : un champ de plus, propre à l'annonce `asl-echo`,

```jsonc
"passerelle": {"port": 51377, "via": "upnp"}
```

**Le port, et jamais une adresse à viser.** (Depuis la décision 107, le
champ peut porter `externe`, l'adresse que la box a dite : elle **confirme**
ce qu'une racine a observé, elle n'est jamais une cible — « Chez un annuaire
local », plus haut.) L'annuaire en fait un candidat avec
**l'adresse qu'il a observée** (`vu_depuis`) et ce port ; il le place en tête,
avant le candidat du bail (adresse observée, port observé), et les sonde dans
cet ordre. C'est la règle de `modele.md` §4.3 qui tient : **il ne parle qu'à
l'adresse qui lui a parlé** — comme aujourd'hui, où le candidat réflexif est
l'adresse observée et le port annoncé. Une adresse externe choisie par le
client ferait de l'annuaire un balayeur ; il n'y en a donc pas, et c'est
aussi pourquoi `asl echo` ne l'annonce que si `GetExternalIPAddress` est
égale à `vu_depuis` (le double NAT ci-dessus). Pour un trou IPv6, le port est
celui de l'écho, `"via":"upnp"`, et rien ne change au candidat. Sans trou IPv6 mais
avec une redirection, le bail passe en IPv4 pour que ce `vu_depuis`-là soit
l'adresse externe de la box (décision 106, plus haut).

**Le champ demande un annuaire qui le connaît** : le décodeur d'annonce
refuse un champ inconnu (`asl-proto`, `crates/asl-proto/src/cadrage.rs:38`,
« Aucun champ inconnu »). `asl echo` lit donc `GET /v1/version` et n'envoie
`passerelle` qu'à un annuaire qui l'accepte — racines et membres d'annuaire
local. **L'annonce est faite deux fois** : sans le champ d'abord, pour
apprendre `vu_depuis` ; avec, une fois la box interrogée — la réannonce dans
la même connexion (§1.2), qui relance la sonde.

**Les racines, pour une machine d'un domaine hébergé** (décision 92) : le
membre de l'annuaire local rapporte le candidat de la passerelle avec les
autres, et la racine le sonde du dehors sous les mêmes bornes — une adresse
globale, qui est celle que le membre a vue. **Derrière une box qui ne perce
pas son pare-feu IPv6** (décision 107), le membre rapporte aussi l'adresse
externe que l'écho confirme, et la racine sonde **l'adresse IPv4 qu'elle a
elle-même observée chez ce membre**, au port accordé, si les deux
concordent.

**Ce que l'état d'écho dit en plus** — **décidé** (décision 97 ; E21) :
**par où la preuve est arrivée**, une chaîne de plus sur la machine :

```jsonc
"echo_via": "upnp"    // par la redirection ou le trou que la box a accordés
          | "nat"     // par le mapping que le bail tient ouvert, adresse ou port traduits
          | "direct"  // l'adresse observée est une adresse de la machine : ni traduction, ni passerelle
```

présente seulement avec `"echo":"verifie"`. **Une chaîne, et un mot inconnu
se dit tel quel** : les décodeurs déployés des applications lisent la machine
par clés et ignorent le reste, quelle qu'en soit la valeur
(`air-service-locator-android`, `coeur-reseau/…/reel/AnnuaireReel.kt:556-565` ;
`air-service-locator-ios`, `Sources/Coeur/Reseau/Reel/AnnuaireReel.swift:581-588`),
et celui d'`asl domain` saute un champ inconnu quelle que soit sa valeur
(`air-service-locator-client`, `crates/asl-client-tokio/src/domaines.rs:34`).
PCP et NAT-PMP viendront (décision 96 ; E16) : `pcp` et `natpmp`
s'ajouteront alors à la liste, sans rien casser.

#### La sécurité : un seul port, le sien

- **On n'ouvre que le port de l'écho, jamais un autre** — ni celui d'un
  daemon annoncé par `asl announce`, ni un port TCP, ni un port qu'on
  demanderait par la ligne de commande. `asl echo` ne sait redemander que
  `(UDP, son port, son adresse locale)`.
- **Ce qui entre par là ne trouve que l'écho**, qui se tait devant toute
  sonde non autorisée (« Qui l'écho croit ») : la redirection ne rend pas la
  machine plus bavarde, elle rend l'écho atteignable.
- **UPnP n'a aucune authentification** : n'importe quel appareil du réseau
  local peut répondre au `M-SEARCH`, ou se faire passer pour la box. Le pire
  qu'il obtienne : que l'écho croie avoir une redirection qu'il n'a pas — et
  la sonde de l'annuaire le détrompe (`injoignable`, ou `echo_via: nat`) —, ou
  qu'il apprenne le port de l'écho, qui ne répond qu'aux sondes signées.
- **L'écho n'active pas UPnP sur la box** ; si elle l'a désactivé, il s'en
  passe.
- **`--no-upnp`** désactive tout cela (et `ASL_ECHO_UPNP=0` dans
  l'environnement, pour une unité). **Activé par défaut** (décision 95 ;
  E15) : Thierry veut toutes les chances ; l'écho, lui, reste inactif tant
  qu'on ne l'a pas activé (décision 93).

#### Le code : sans une ligne de C (C4)

**`igd-next`** existe (0.17.1, licence **MIT**, Rust pur, **aucun `unsafe`**
dans ses sources ; dépôt `dariusc93/rust-igd`). Relevé sur ses manifestes,
sans rien ajouter au dépôt :

- elle sait **IGD v1 et v2** côté redirection (`AddPortMapping`,
  `AddAnyPortMapping`, `GetExternalIPAddress`, `DeletePortMapping`), en
  synchrone ou, avec `aio_tokio`, sur tokio ;
- elle **ne sait PAS** `WANIPv6FirewallControl` : pas de trou IPv6 — il
  faudrait l'écrire à côté ;
- sa découverte ne vise que `239.255.255.250:1900` par défaut ;
- ses dépendances : `attohttpc` **sans ses fonctions par défaut** (donc sans
  `native-tls` : pas de C), `url` — qui amène `idna` et la famille `icu_*` —,
  `xmltree` (`xml-rs`), `rand` 0.10, `log`, `base64`, `http` ; en `aio_tokio`,
  `hyper` en plus. **Une trentaine d'unités** construites de plus, estimées
  sans construire ; `check-sans-c.sh` du client, qui lit tout le workspace,
  n'y trouverait pas de C.
- **mais ses décodeurs ne sont pas les nôtres** : elle lit du XML et du HTTP
  **venus d'un appareil du réseau local, que personne n'authentifie** — et C3
  demande que tout décodeur soit fuzzé, C1 qu'il ne fasse aucune
  entrée-sortie.

**L'autre voie : l'écrire** — un codec d'étage 1 (C1), dans le dépôt client,
réservé à `asl-cli` : le `M-SEARCH` et sa réponse, une requête et une réponse
HTTP/1.1 minimales (`Content-Length` seul, pas de `chunked`), un lecteur XML
réduit à ce que la description et les réponses SOAP portent, les six actions
(`AddAnyPortMapping`, `AddPortMapping`, `DeletePortMapping`,
`GetExternalIPAddress`, `GetFirewallStatus`, `AddPinhole`/`UpdatePinhole`/`DeletePinhole`)
— quelques centaines de lignes, couvertes (C2) et fuzzées (C3), aucune
dépendance. **Décidé (décision 96 ; E17) : c'est celle-là** — notre client,
dans le dépôt client, `igd-next` lu comme référence et jamais ajouté au
graphe.

**Puis PCP, et NAT-PMP en repli** (décision 96 ; E16), dans une PR à part
qui suit celle d'UPnP : quand aucune passerelle UPnP ne répond, `asl echo`
parle PCP (RFC 6887) à la passerelle par défaut, port 5351 — une demande
`MAP` du seul port UDP de l'écho, et en IPv6 le trou dans le pare-feu que PCP
sait aussi ouvrir —, et NAT-PMP (RFC 6886) quand la box ne connaît que lui
(la réponse de version non prise en charge que PCP prévoit). Un codec
binaire d'étage 1, lui aussi couvert et fuzzé ; la passerelle par défaut se
lit dans la table de routage, différemment sous Linux et sous macOS. Les
mêmes règles tiennent : un seul port, le bail d'une heure, le retrait à
l'arrêt, `--no-upnp` qui coupe tout, et `via` qui dit `pcp` ou `natpmp`.

**Dans un cas comme dans l'autre, UPnP reste hors d'`asl-client`** : c'est
l'utilitaire `asl` qui le parle, pas la bibliothèque chargée dans les
programmes des autres (C4).

### Les datagrammes — version 1

**Tout est de longueur fixe, en octets de réseau, sans champ facultatif** :
un décodeur qui n'a rien à décider n'a rien à mal décider. Les adresses sont
seize octets (une IPv4 s'écrit `::ffff:a.b.c.d`) suivis du port sur deux.
Les identifiants (`m-…`, `n-…`) sont leurs seize octets, jamais leur texte
(la règle de `modele.md` §2.4). Les séparations de domaine suivent la forme
d'`asl-cle` (`crates/asl-cle/src/lib.rs:147`, `DOMAINE_POSSESSION`) :
`air-service-locator/v1/<nom>\x00`.

**L'en-tête** : l'octet `0x0A` (l'écho, version 1 ; `0x0B` à `0x0F` pour les
suivantes, `0x04` à `0x09` réservés), puis le **genre** sur un octet.

| Genre | Qui l'envoie | Longueur totale |
|---|---|---|
| `0x01` — sonde d'annuaire | L'annuaire qui tient le bail de l'écho | **384 octets**, bourrés de zéros |
| `0x02` — sonde munie d'un jeton | `asl ping` | **384 octets**, bourrés de zéros |
| `0x81` — réponse | L'écho | **132 octets** |

**Pas d'amplification, et c'est une règle de format** : une requête fait 384
octets, une réponse 132. **Une requête d'une autre longueur est ignorée** —
et le bourrage doit être fait de zéros, sinon ignorée aussi : un octet libre
serait un canal. 384 octets passent tout lien IPv6 (1 280 au moins) et ne se
fragmentent pas.

**La sonde d'annuaire** (`0x01`) :

```
0x0A ‖ 0x01 ‖ défi (16) ‖ annuaire n-… (16) ‖ cible m-… (16)
     ‖ émise_a (8, millisecondes d'époque) ‖ signature (64) ‖ zéros jusqu'à 384
signature = Ed25519, clé d'identité de l'annuaire, sur
  "air-service-locator/v1/echo-sonde-annuaire\x00" ‖ tout ce qui précède la signature
```

**La sonde munie d'un jeton** (`0x02`) :

```
0x0A ‖ 0x02 ‖ défi (16) ‖ jeton (193) ‖ signature du sondeur (64) ‖ zéros jusqu'à 384
signature du sondeur = Ed25519, clé de la machine qui sonde, sur
  "air-service-locator/v1/echo-sonde\x00" ‖ défi ‖ jeton
```

**La réponse** (`0x81`) :

```
0x0A ‖ 0x81 ‖ défi (16) ‖ machine m-… (16) ‖ adresse observée du sondeur (18)
     ‖ sondeur (16) ‖ signature (64)
signature = Ed25519, clé de la machine, sur
  "air-service-locator/v1/echo-reponse\x00" ‖ défi ‖ machine ‖ adresse observée ‖ sondeur
```

**Ce que la réponse signe, et pourquoi** (décision 90 ; E3) :

- **le défi du sondeur** : c'est lui qui fait la fraîcheur. Seize octets tirés
  par le sondeur, jamais réutilisés : une réponse ne vaut que pour la sonde
  qui l'a demandée ;
- **le `m-…`** : la machine dit qui elle est, et le sondeur le compare à celui
  qu'il visait ;
- **l'adresse observée du sondeur** : l'écho dit **d'où il a vu la sonde**,
  comme `vu_depuis` le dit d'une connexion (§2.2, `GET /v1/vu`). Le sondeur
  apprend son adresse réflexive, et un relais qui rejouerait la réponse sur un
  autre chemin se trahirait : l'adresse signée ne serait pas la sienne ;
- **l'identité du sondeur** — le `n-…` de l'annuaire pour une sonde `0x01`, le
  `m-…` du sondeur pour une sonde `0x02` : une preuve obtenue par l'un ne se
  présente pas comme faite pour un autre. Sans elle, un sondeur autorisé
  pourrait faire signer le défi d'un tiers et lui revendre la preuve.

**Ce qu'elle ne signe pas : l'heure de l'écho** (décision 90 ; E3). Le défi
suffit à la fraîcheur ; une date n'ajouterait rien que le sondeur ne sache
déjà — il sait quand il a envoyé —, et dirait l'horloge de la machine à qui
l'interroge. Si Thierry veut la date « constaté à » signée par la machine
plutôt que par le sondeur, c'est huit octets, et la réponse passe à 140.

**La clé** : celle de la machine, Ed25519, la même que pour tout le reste
(`modele.md` §2.3). La séparation de domaine empêche qu'une réponse d'écho
serve de preuve de possession, et l'inverse : les messages ne peuvent pas se
rencontrer, leurs préfixes diffèrent.

### Qui l'écho croit — pas de balayage

**L'écho ne répond qu'à deux sortes de sondes, et vérifie tout hors ligne** —
il n'appelle personne pour savoir s'il doit répondre.

**Une sonde d'annuaire** (`0x01`) est acceptée si et seulement si :

1. **l'annuaire est celui qui tient son bail, OU l'une des racines
   embarquées** (décision 91 ; E4, réponse (b), puisque les racines sondent
   aussi du dehors — décision 92) : le `n-…` que la poignée de main de SA
   connexion a vérifié (§0) — une racine s'il s'annonce aux racines, **le
   membre de l'annuaire local** s'il a été renvoyé (`421`, décision 59) —, ou
   l'une des `n-…` de la liste que le binaire porte ; et la signature tient
   sous cette clé ;
2. la cible est **son** `m-…` ;
3. `émise_a` est à moins de **deux minutes** de son horloge ;
4. le défi n'a pas été vu dans ces deux minutes (l'anti-rejeu : une mémoire
   bornée, 4 096 défis au plus, les plus vieux sortant d'abord).

**Une sonde munie d'un jeton** (`0x02`) est acceptée si et seulement si :

1. **le jeton est signé par une racine embarquée** — l'une des `n-…` de la
   liste que le binaire porte (`racines_embarquees`, `asl-client-tokio`) ; les
   annuaires locaux n'en délivrent pas (ils ne savent rien des droits :
   `annuaires.md` §7, question 12) ;
2. la cible du jeton est **son** `m-…`, et la clé de cible, **sa** clé — un
   jeton délivré avant un ré-enrôlement meurt avec l'ancienne clé ;
3. le jeton n'est pas expiré, à deux minutes près d'horloge ;
4. **la signature du sondeur tient sous la clé que le jeton nomme** : le jeton
   ne sert qu'à qui détient la clé privée pour laquelle il a été délivré ;
5. le défi n'a pas été vu (même mémoire).

**Tout le reste : le silence.** Pas d'erreur, pas de refus, pas d'ICMP — la
socket est liée, le noyau n'en envoie pas. Vu du dehors, un écho est un port
UDP qui ne répond pas, comme mille autres : **on ne balaie pas un réseau à la
recherche d'échos**, faute de quoi que ce soit qui les distingue.

**Le débit est borné par source, AVANT toute vérification** — une signature
coûte des dizaines de microsecondes, et un inconnu ne doit pas pouvoir les
faire dépenser à volonté : **cinq réponses par seconde et par source** (une
`/64` en IPv6, une adresse en IPv4), **dix d'avance** ; **cinquante par
seconde en tout** ; au-delà, silence, et une ligne de journal par minute au
plus. Les chiffres se mesureront.

### Le jeton — `POST /v1/echo/jetons`

**Décidé (décision 91).** Sur la voie machine, aux racines :

```
POST /v1/echo/jetons
{"machine":"m-…"}

200 {"jeton":"<386 chiffres hexadécimaux>","expire_a":1789217791000}
404 — pas d'écho annoncé, pas le droit, ou pas de machine :
      la même réponse, après le même délai (C9)
```

**Le jeton** (193 octets) :

```
version (1, 0x01) ‖ racine n-… (16) ‖ cible m-… (16) ‖ clé de la cible (32)
  ‖ sondeur m-… (16) ‖ clé du sondeur (32) ‖ émis_a (8) ‖ expire_a (8)
  ‖ signature (64)
signature = Ed25519, clé d'identité de la racine, sur
  "air-service-locator/v1/echo-jeton\x00" ‖ tout ce qui précède la signature
```

- **Qui l'obtient : qui tient `localiser` sur `asl-echo` de cette machine**
  (décision 91 ; E6) — c'est-à-dire la décision même de
  `GET /v1/ou/{m}/asl-echo`, calculée par `asl-auth` à partir du propriétaire
  de la machine qui demande (C10) : un droit sur la machine ou sur son
  domaine y mène ; un droit sur UN AUTRE service de la machine, non.
- **Lié au sondeur, par sa clé** : la clé du sondeur est celle que sa
  connexion a prouvée — la requête ne la dit pas, la connexion la porte (§3).
  **Ce n'est donc pas un jeton porteur** (C10 : « pas de jeton porteur qu'on
  se passe ») : intercepté, il ne sert à rien sans la clé privée du sondeur,
  qui ne quitte pas sa machine (C14). Un secret partagé n'est nulle part.
- **Lié à la cible, et à sa clé** : il ne vaut que pour cette machine, sous la
  clé qu'elle a aujourd'hui.
- **Court : soixante secondes** (décision 91 ; E5) — le temps d'un
  `asl ping` et de ses reprises. L'horloge de l'écho doit être juste à deux
  minutes près ; une machine sans heure (pas de NTP) ne répondra qu'à la sonde
  de l'annuaire… qui porte aussi une date. **Une machine dont l'horloge dérive
  de plus de deux minutes ne répond à aucune sonde**, et `asl echo` le dit
  dès que l'écart se voit (une sonde d'annuaire signée hors de la fenêtre).
- **Il porte la clé de la cible, signée par la racine** : c'est ainsi que
  `asl ping` vérifie la réponse « contre la clé que l'annuaire connaît pour
  cette machine », sans une route de plus pour la lire. Qui tient `localiser`
  apprend donc la clé publique de la machine visée — une clé publique ; le
  prix se dit, parce que `GET /v1/utilisateurs/{u}/machines` la tait
  aujourd'hui (§2.2 : « ni capacités, ni clé »).
- **Une ligne au journal** par jeton délivré : qui, pour quelle machine, quand
  — le journal ordinaire (`journal.md`), agrégé puis jeté (C18). **Un débit** :
  un jeton par seconde et par machine qui demande, dix d'avance.
- **Fait en 0.42.0.** `asl-api` route `POST /v1/echo/jetons`
  (`Ressource::JetonsEcho`, exigence `MachineLecture`) et lit ses corps
  (`asl_api::echo::{DemandeDeJeton, JetonRendu}` — le jeton en hexadécimal
  se relit en `asl_echo::Jeton`, et un `expire_a` qui ne serait pas le sien
  est refusé). `asl-session` décide : la résolution de
  `GET /v1/ou/{m}/asl-echo`, `asl_auth::decider_resolution`, un écho
  annoncé — `200` et le jeton, sinon le même `404` octet pour octet ;
  `429` au-delà du débit ; `500` si la racine n'a pas de clé d'identité
  (`--identity-key`), ce qui ne dépend pas de la cible. L'étage 3 signe
  **toujours** un jeton — un leurre quand la machine ou une clé manque,
  jamais rendu —, pour que « pas de machine » ne réponde pas plus vite que
  « pas le droit ». Le débit est tenu en mémoire, par machine qui demande
  (GCRA, dix d'avance). La ligne de journal : `jeton d'écho délivré : m-…
  pour m-…, jusqu'à …`. L'écho vérifie le jeton hors ligne par
  `asl_echo::Jeton::verifier` (0.41.0).
- **Pourquoi pas un champ de plus dans `GET /v1/ou`** : sa réponse est la
  réponse d'annonce, et **son décodeur refuse tout champ inconnu**
  (`asl-proto`, `cadrage.rs`, « Aucun champ inconnu ») — un jeton de plus y
  casserait tous les clients déployés. Et un jeton se délivre, se journalise
  et se limite : c'est un acte, pas une lecture.

### `asl ping <m-…|alias>` — ce qu'il fait, et ce qu'il dit

**Décidé (décision 93).** Sur la machine qui sonde — une machine enrôlée, qui porte
`lecture` :

1. **résoudre la cible** : un `m-…` tel quel ; sinon un nom ou un alias,
   cherché parmi les machines que ce compte voit (décision 93 ; E12) — plusieurs
   réponses, et `asl ping` les liste et refuse de choisir ;
2. **`GET /v1/ou/{m}/asl-echo`** aux racines : les candidats, réflexif
   d'abord, IPv6 d'abord (§3, « Les candidats sont ordonnés ») ;
3. **`POST /v1/echo/jetons`** sur la même connexion ;
4. **sonder chaque candidat**, dans l'ordre, un quart de seconde d'écart entre
   deux (à la façon de *Happy Eyeballs*), depuis une socket éphémère ; trois
   envois par candidat, une seconde d'attente chacun — l'UDP perd, et un
   seul envoi confondrait perte et silence ;
5. **vérifier** : le défi est le sien, le `m-…` est la cible, le sondeur est
   lui, et **la signature tient sous la clé que le jeton porte**.

**Il dit TOUJOURS d'où la sonde est partie** — la machine qui sonde, et
l'adresse sous laquelle l'écho l'a vue, signée :

```
$ asl ping grenier
sonde partie de m-3F… (carbon), vue par l'écho comme [2a01:e0a:…]:53211
  [2001:db8::1c2d]:41877  udp  réflexif  joignable d'ici — 18 ms, preuve vérifiée
  192.168.1.20:41877      udp  annoncé   pas de réponse (3 envois, 3 s)
grenier (m-7Q2H…) : joignable d'ici, 18 ms, preuve vérifiée
  — clé de m-7Q2H… selon la racine n-… ; constaté à 14:02:31
```

**Les échecs, et ce qu'ils veulent dire** — chacun sa sortie, jamais un
« erreur » générique :

| Ce qu'`asl ping` voit | Ce qu'il dit | Code de sortie |
|---|---|---|
| `404` à la résolution ou au jeton | « introuvable : pas d'écho annoncé, ou pas le droit de la localiser » — les deux ne se distinguent pas, et c'est C9 | 3 |
| Aucune réponse sur aucun candidat | « pas de réponse d'ici » — filtré en chemin, écho arrêté depuis, ou sonde refusée : l'écho se tait dans les trois cas, et `asl ping` ne prétend pas savoir lequel | 1 |
| Une réponse bien formée, signée d'une AUTRE clé | « **quelqu'un d'autre répond à cette adresse** » — une adresse réattribuée, un NAT partagé, un port repris : exactement ce qu'un trois-temps TCP n'aurait pas vu | 2 |
| Une réponse mal formée, ou d'une autre longueur | « réponse illisible » | 2 |
| Réponse vérifiée | « joignable d'ici, x ms, preuve vérifiée » | 0 |

**`asl ping` ne change rien chez l'annuaire** : son verdict est le sien,
« d'ici, maintenant », et il n'est pas remonté — sinon n'importe quel sondeur
autorisé écrirait l'état d'une machine qui n'est pas la sienne.

### La sonde de l'annuaire, par l'écho

**Décidé (décision 92).** Quand une machine annonce `asl-echo`, l'annuaire qui tient ce bail
le sonde **par l'écho**, et non par un trois-temps :

- **vers le seul candidat réflexif** — la règle de `modele.md` §4.3 ne change
  pas : jamais une adresse annoncée ;
- **depuis une socket UDP éphémère**, pas depuis son port d'écoute (6630) :
  une sonde qui partirait du port auquel le bail parle passerait le pare-feu
  à état que le bail a ouvert, et ne mesurerait que le bail ;
- **trois envois, une seconde chacun** — trois secondes en tout, l'`ATTENTE` de
  `sonde.rs:52` ;
- **la réponse est vérifiée sous la clé que l'annuaire tient pour la
  machine** — celle qui a authentifié le bail ; aux racines, l'entrepôt ; chez
  un annuaire local, celle que `GET /v1/federation/machines` lui a transmise.

**Le verdict est celui d'aujourd'hui, et c'est voulu.** Le point `udp` de
`asl-echo` reçoit :

| Ce qui s'est passé | Verdict, sur le fil |
|---|---|
| Réponse vérifiée | **`joignable`**, avec `candidat` (l'adresse qui a répondu, au port observé), `origine: reflexif` et `a` |
| Aucune réponse, ou une réponse fausse | **`injoignable`**, avec `a` |
| Pas encore sondé | **`en_cours`** |

**Aucun mot nouveau dans la réponse d'annonce**, parce que son décodeur refuse
tout ce qu'il ne connaît pas (`asl-proto`, `Verdict::analyser` ;
`crates/asl-proto/src/lib.rs:1300-1420`, et côté client
`crates/asl-cli/src/rendu.rs:137-149`
qui les met en français) : un verdict `joignable_prouve` ferait refuser la
réponse entière par chaque `asl` et chaque application déployés. **Sur le point
`asl-echo`, `joignable` veut dire « preuve de clé vérifiée »** — l'annuaire ne
le pose pas autrement.
**C6 reçoit une exception, et une seule** : un point UDP devient `joignable`
quand, et seulement quand, un écho a signé (`contraintes.md`, C6).

**Ce que les lecteurs déployés en font — relevé en 0.43.0, et il faut le dire
exactement.** Le mot n'est pas nouveau, mais **une mesure sur un point UDP
l'est** : jusqu'à la 0.42.0, `asl_proto::Reponse::decoder` et
`Poussee::decoder` refusaient tout `joignable` ou `injoignable` porté par un
point UDP (`Erreur::VerdictImpossible`, C6 dans un type). Donc :

- **`asl` ≤ 0.22.3 refuse l'objet d'annonce de CE service, et de lui seul** :
  `asl where m-… asl-echo` échoue, et `asl domain` dit « la réponse ne se lit
  pas » sur la ligne de l'écho ; les autres services de la même machine se
  lisent comme avant. `asl-proto` accepte la mesure sur UDP **depuis 0.43.0**
  — il ne connaît pas le nom du service, une poussée ne le porte pas —, et
  un client qui l'épingle lit tout ;
- **les applications Android et iOS la tolèrent** : elles lisent le verdict
  par clé, sans contrainte de protocole
  (`coeur-reseau/…/LectureDesServices.kt:63-72`,
  `Sources/Coeur/Reseau/Reel/AnnuaireReel.swift:715-724`) ;
- **les champs `echo*` de la machine sont tolérés** : des chaînes et des
  entiers, que les applications lisent par clés et qu'`asl domain` saute.

**L'état par machine — ce que les applications lisent.** Un champ de plus sur
chaque machine, là où la machine est déjà rendue, **des chaînes et des
entiers seulement** — les décodeurs déployés ne sautent qu'une clé inconnue de
ces deux sortes (décision 86) :

```jsonc
// GET /v1/machines (le propriétaire) ; GET /v1/domaines/{d}, "machines" (qui a `voir`, décision 91 ; E7)
{"machine":"m-…","nom":"grenier", …,
 "echo":"verifie",            // "verifie" | "injoignable" | "autre_cle" | "en_cours"
 "echo_a":1789217751000,      // l'instant de la mesure — absent sur "en_cours"
 "echo_par":"n-…",            // l'annuaire qui a sondé
 "echo_depuis":"exterieur",   // "exterieur" | "interieur" (la règle de `sonde_locale`)
 "echo_via":"upnp"}           // "upnp" | "nat" | "direct" — décisions 94 et 97 ; avec "verifie" seulement
```

- **Absent** : aucun `asl-echo` n'est annoncé — « pas d'écho », qui n'est ni
  un échec ni un succès. Pas `null`, pas une chaîne vide.
- **`autre_cle`** : une réponse est venue, bien formée, **signée par une autre
  clé**. Sur le fil de l'annonce, c'est `injoignable` ; ici, c'est dit, parce
  que c'est le cas que l'écho est fait pour voir.
- **Pas d'adresse** : l'état dit qu'on a prouvé, pas où. L'adresse reste
  derrière `localiser` (`GET /v1/ou/{m}/asl-echo`).
- **`echo_depuis`** suit la règle de `sonde_locale` (décision 60, §2.2) : le
  bail est venu d'une adresse littérale de l'annuaire qui sonde — il tourne
  sur la machine même, ou sur son réseau — et la preuve vaut « de
  l'intérieur ». `sonde_par`/`sonde_locale` restent sur l'objet de service
  (`GET /v1/machines/{m}/services`), où ils disent la même chose du point
  `asl-echo`.

**Quand l'annuaire sonde** (décision 92 ; E9) : à l'annonce et à chaque changement
de candidat, comme aujourd'hui (`modele.md` §4.3) — **et toutes les
quinze minutes** tant que le bail tient : un datagramme de 384 octets, pour
que « constaté à » ne vieillisse pas indéfiniment et qu'un pare-feu fermé
depuis se voie. La poussée (§1.4) porte le nouveau verdict à `asl echo` quand
il change, et à lui seul.

### Avec les annuaires locaux — qui sonde, et d'où

**L'annuaire qui tient le bail sonde, et c'est le seul que l'écho croit pour
une sonde d'annuaire.** Pour une machine d'un domaine confié, c'est **le
membre de l'annuaire local** vers lequel le `421` l'a renvoyée : il sonde, il
vérifie avec la clé qu'il tient déjà, et rapporte le verdict aux racines par
sa voie (`POST /v1/federation/etat`), comme ceux de tout service fédéré — les
racines le rendent avec `sonde_par` et `echo_par` à son `n-…`.

**Un annuaire local sonde souvent « de l'intérieur »**, et l'état le dit
(`echo_depuis: interieur`) : sur la même machine, ou le même réseau, sa preuve
dit que la clé est là, pas qu'on la joint du dehors — l'essai de speedy
(27/09, `sonde_locale`) vaut ici aussi.

**Les racines sondent aussi, du dehors** (décision 92 ; E8) — c'est ce qui
manquait pour qu'un « joignable » d'un domaine hébergé veuille dire « depuis
l'Internet ». **Oui, et borné** — vers l'adresse que le
membre a vue, **seulement si elle est globale** (ni privée, ni lien-local, ni
ULA, ni `::ffff:` d'une privée), une fois par changement et par quart d'heure,
dans la borne de soixante-quatre sondes en vol (`sonde.rs:60`). **Et l'écho
croit donc aussi les racines embarquées** pour une sonde d'annuaire
(décision 91 ; E4, b) : leur `n-…` est dans le binaire. Le risque se nomme : une
racine enverrait un datagramme vers une adresse qu'un annuaire local lui a
rapportée, c'est-à-dire désignée par un tiers ; il est borné — un datagramme
de 384 octets, signé, qui nomme sa cible, sans réponse amplifiée — et
l'annuaire local est l'autorité de son domaine (C11). L'état porte alors le
`n-…` de la racine dans `echo_par`, et `echo_depuis: exterieur`.

**Et en IPv4, quand la box du membre et celle de l'écho sont la même**
(décision 107) : le membre fait voir aux racines l'adresse IPv4 de sa box par
une visite, l'écho confirme l'adresse externe que sa box lui a dite, et une
racine sonde `adresse observée:port accordé` du dehors **si, et seulement
si, les deux concordent** ; sinon elle se tait, et le dit à son journal
(« Chez un annuaire local : les racines voient l'adresse de la box, l'écho
la confirme », plus haut).

**Ce n'est pas la sonde de l'`asl-directory`** (décision 83, qui ne change
pas) : l'écho prouve une MACHINE. Une machine qui héberge un annuaire local et
qui est enrôlée peut faire tourner `asl echo` ; sa preuve dit que la machine
est là, pas que le port de l'annuaire est ouvert.

### Qui peut quoi — C9 et C10

| Geste | Qui | Ce qu'il apprend |
|---|---|---|
| Voir l'état d'écho d'une machine | Le propriétaire ; **qui a `voir` sur son domaine** (décision 91 ; E7) | `echo`, `echo_a`, `echo_par`, `echo_depuis`, `echo_via` — pas d'adresse, pas de port |
| Résoudre `asl-echo` | Qui a `localiser` sur le service (règle ordinaire de `GET /v1/ou`) | Les candidats : adresses et port |
| Obtenir un jeton, donc `asl ping` | **Qui a `localiser`** (décision 91 ; E6) — la même décision | La clé publique de la cible, et, par la sonde, sa joignabilité d'ici |
| Faire répondre l'écho | L'annuaire du bail ; le porteur d'un jeton **et de la clé qu'il nomme** | La preuve signée, et son adresse vue par l'écho |

- **C9** : `POST /v1/echo/jetons` rend le même `404`, après le même travail,
  pour « pas de machine », « pas d'écho annoncé » et « pas le droit » — la
  décision est celle de `GET /v1/ou`, et son type ne porte pas de raison
  (`Decision::Refuser`).
- **C10** : la décision se calcule depuis le compte de la machine qui demande,
  jamais depuis le `m-…` désigné ; un essai par chemin, avec un compte tiers.
  Le jeton n'est pas porteur (il lie une clé), et l'écho lui-même ne révèle
  rien à qui n'en a pas : le silence ne distingue pas « pas d'écho » de
  « pas le droit ».
- **C14** : aucun secret partagé — des signatures, trois clés : celle de la
  racine (le jeton), celle du sondeur (la sonde), celle de la machine (la
  réponse).
- **C19, C20** : aucun tiers, aucun nom ; des adresses et des clés.

### L'installation — une unité, désactivée, chez celui qui porte la clé

**L'identité vit chez l'utilisateur** (`~/.config/asl`, ou
`$XDG_CONFIG_HOME/asl`, ou `--state` ; sur Mac, le conteneur de l'application
en repli : `crates/asl-cli/src/etat.rs:84-137` du client). L'écho doit donc
tourner **sous le compte qui la détient**, et jamais en root — `asl echo`
refuse de démarrer sous `uid 0`, comme l'annuaire (C8).

**Linux — une unité systemd UTILISATEUR** (décision 93 ; E10), posée par
le paquet `asl` en `/usr/lib/systemd/user/asl-echo.service`, **désactivée** :

```ini
[Unit]
Description=asl-echo — l'écho de cette machine (air-service-locator)
Documentation=man:asl(1)

[Service]
ExecStart=/usr/bin/asl echo
Restart=always
RestartSec=10
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

- **Le durcissement** (`ProtectSystem=`, `ProtectHome=`) reste à éprouver :
  dans une unité utilisateur, ces options demandent des espaces de noms que
  toutes les distributions n'ouvrent pas.
- **L'activer** : `systemctl --user enable --now asl-echo`. Sur un serveur sans
  session ouverte, `loginctl enable-linger <compte>` pour qu'elle démarre au
  boot — et la documentation le dit, parce que c'est ce qu'on oublie.
- **Le paquet reste sans script de mainteneur** : il pose un fichier, n'active
  rien, ne crée aucun compte. C'est la ligne de `scripts/paquet.sh:10-25` du
  client (« aucune unité systemd … aucun `postinst` ») qui change, et seulement
  sur son premier tiret : une unité est posée, et c'est à l'utilisateur de
  l'activer.
- **L'alternative, écartée en v1** (E10, b) : une unité SYSTÈME modèle, `asl-echo@.service`,
  avec `User=%i` et `ExecStart=/usr/bin/asl echo` — `%h` y vaut la maison de
  `User=`. Elle démarre au boot sans *linger*, mais c'est root qui l'active :
  un geste d'administrateur pour une clé d'utilisateur.

**macOS — deux chemins, un seul label** (décision 93 ; E11). **Pour qui a
installé `asl`** : un LaunchAgent,
`~/Library/LaunchAgents/org.airdesktop.asl-echo.plist` :

```xml
<dict>
  <key>Label</key><string>org.airdesktop.asl-echo</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/asl</string><string>echo</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
```

posé par `asl echo --install` (et retiré par `--uninstall`), chargé par
`launchctl bootstrap gui/$(id -u)`. **Pour un Mac enrôlé par l'application** :
elle l'active depuis la fiche « ce Mac » (« Répondre aux sondes de
l'annuaire ») en enregistrant **un agent embarqué dans son paquet**
(`SMAppService.agent`, macOS 13) — une application en bac à sable n'écrit pas
dans `~/Library/LaunchAgents`.

**Ce qu'un essai réel a montré** (oxygen, macOS 15.7.9, 2026-09-29) :

- **un agent lancé par launchd, NON sandboxé** — signé Developer ID (équipe
  `SB7H9B6TY8`, runtime renforcé) ou ad hoc — **lit** l'identité de machine
  rangée dans `~/Library/Containers/org.airdesktop.servicelocator.mac/Data/Library/Application Support/asl/identite`
  (mode 600), **sans invite TCC** ;
- **un agent en bac à sable** (`app-sandbox`) : lecture **refusée** — le
  processus est enfermé dans son propre conteneur.

**Décidé (2026-09-29, Thierry ; décision 93, E11 révisé) : l'application Mac
ira aussi sur le Mac App Store. L'application ET l'agent `asl-echo` sont donc
en bac à sable, et partagent un conteneur de groupe.**

1. **Les droits, sur les deux** : `com.apple.security.app-sandbox`,
   `com.apple.security.application-groups` =
   `SB7H9B6TY8.org.airdesktop.servicelocator`, et
   `com.apple.security.network.client` **et** `network.server` — l'agent lie
   une socket et reçoit de l'UDP entrant, ce que le bac à sable range côté
   « serveur » (c'est déjà ce que l'application a dû déclarer pour QUIC :
   `Sources/Mac/ServiceLocatorMac.entitlements` du dépôt iOS).
2. **Le chemin, fixé** :

   ```
   ~/Library/Group Containers/SB7H9B6TY8.org.airdesktop.servicelocator/Library/Application Support/asl/identite
   ~/Library/Group Containers/SB7H9B6TY8.org.airdesktop.servicelocator/Library/Application Support/asl/racines
   ```

   **Pourquoi celui-là.** `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`
   rend la racine du conteneur de groupe ; l'usage d'Apple y range, comme
   dans un conteneur d'application, un `Library/` avec ses sous-dossiers
   ordinaires. `Library/Application Support/asl/` reprend **exactement** ce que
   l'application écrit aujourd'hui dans son conteneur
   (`FileManager … .applicationSupportDirectory` puis `asl/` :
   `Sources/Mac/MachineDeCeMac.swift:152-165` du dépôt iOS) — seul le préfixe
   change —, et garde un **dossier `asl/`** au format d'`asl` : c'est lui qu'on
   passe à `--state`, identité et cache des racines ensemble
   (`crates/asl-cli/src/etat.rs:30` et `:376` du client : `identite`,
   `racines`). Le cache des racines aurait pu aller dans `Library/Caches/` ;
   il reste à côté de l'identité parce qu'`asl` tient les deux dans le même
   répertoire d'état, et qu'un second chemin serait une seconde règle.
   **Dans le bac à sable, `HOME` désigne le conteneur propre du processus** :
   l'agent (du code d'`asl`) calcule ce chemin depuis le répertoire de
   l'utilisateur (`getpwuid`), jamais depuis `HOME` — ou reçoit `--state` en
   argument de son plist, résolu par l'application.
3. **La migration, par l'application, au premier lancement** — copier,
   vérifier, et seulement alors retirer ; **jamais de perte** :
   1. si `identite` existe dans le conteneur de groupe **et** est identique à
      l'ancienne : l'étape 5 seulement (une migration interrompue après la
      copie) ;
   2. créer `…/asl/` en `0700` ; écrire `identite.nouvelle` en `0600`,
      `fsync`, renommer en `identite` (le renommage est atomique : on ne voit
      jamais un fichier à moitié écrit) ; de même pour `racines` ;
   3. **relire** le nouveau fichier et le **comparer octet à octet** à
      l'ancien ;
   4. égal : l'application écrit désormais là, et démarre l'agent ;
   5. retirer l'ancien `identite` (puis `racines`) du conteneur de
      l'application.

   **Les échecs partiels** :
   - *la copie ou la relecture échoue* (disque plein, droit refusé,
     contenu différent) : le nouveau fichier est retiré s'il existe,
     **l'ancien reste**, l'application continue de le lire, **l'agent
     n'est pas démarré** (il ne verrait rien) et la fiche « ce Mac » le dit ;
     on réessaie au lancement suivant ;
   - *arrêt entre la copie et le retrait* : deux copies identiques ; le
     lancement suivant le constate (étape 1) et retire l'ancienne ;
   - *le retrait échoue* : deux copies identiques, sans danger ; réessayé ;
   - ***une `identite` DIFFÉRENTE existe déjà dans le conteneur de groupe***
     (un `asl enroll --state` qui y a écrit, une restauration) : **on ne
     touche à rien**, ni à l'une ni à l'autre, et l'application le dit — deux
     clés, deux machines peut-être, que seul l'utilisateur peut départager.
4. **`asl` sur macOS cherche l'identité dans cet ordre** (modification du
   client, « Travail à faire ») :
   1. **`--state <dossier>`, puis `ASL_STATE`** : ce qui est dit est pris tel
      quel, **sans aucune recherche ni repli** — comme aujourd'hui ;
   2. **le conteneur de groupe** :
      `~/Library/Group Containers/SB7H9B6TY8.org.airdesktop.servicelocator/Library/Application Support/asl/`,
      s'il porte une `identite` ;
   3. **l'ancien chemin du conteneur de l'application**,
      `~/Library/Containers/org.airdesktop.servicelocator.mac/Data/Library/Application Support/asl/`,
      s'il porte une `identite` — le repli de la transition, avec un
      avertissement (« la migration de l'application n'a pas eu lieu ») ;
   4. **`$XDG_CONFIG_HOME/asl`, sinon `~/.config/asl`** — et c'est aussi là
      qu'`asl enroll` écrit quand rien d'autre n'existe.

   **Cela renverse une préséance** : aujourd'hui `~/.config/asl` passe avant
   le conteneur (`etat.rs:84-137`). Sur un Mac, l'identité de l'application
   devient celle de la machine. Si `~/.config/asl/identite` existe aussi, et
   porte une autre machine, `asl` le dit à chaque commande plutôt que d'en
   ignorer une en silence.
5. **L'App Review** : sur le Mac App Store, l'agent est embarqué dans le
   paquet et **passe l'App Review avec l'application** — un agent qui écoute
   sur un port UDP, et qui demande une redirection à la box (décision 94) :
   il faudra le dire aux relecteurs.

**Le constat de sécurité, juste** : dans le bac à sable, la graine du
conteneur de groupe **n'est plus lisible par les processus sandboxés hors du
groupe** — les autres applications de l'App Store, par exemple. Elle **reste
lisible par tout processus NON sandboxé de l'utilisateur**, exactement comme
`~/.config/asl/identite` sous Linux (un fichier 600, même utilisateur) : le
conteneur ne protège pas la clé d'un programme ordinaire lancé par
l'utilisateur, et personne ne doit le croire. (macOS 15 aurait ajouté une
invite pour l'accès d'une application au conteneur de groupe d'une autre
équipe — **à vérifier sur oxygen**, comme la lecture du conteneur l'a été.)

**Et l'attestation reste « aucune ».** Le Mac crée son compte en `aucune`
(`docs/attestation/enrolement-macos.md:10` : « App Attest
(`DCAppAttestService`) n'existe pas sur macOS »). La documentation d'Apple
déclarerait `DCAppAttestService` disponible sur macOS, `isSupported`
dépendant du matériel : **à vérifier** — cela ne peut pas se citer sans la
consulter. Si c'était vrai sur certains Mac, cela changerait ce que le Mac
peut prouver. **Ce que le Mac fait si les racines refusent un jour
`aucune`** est tranché (2026-09-29, Thierry ; décision 98 ; E22) : **il ne
crée jamais de compte, il rejoint** un compte ouvert sur un téléphone
attesté (`POST /v1/appareils`, signé par un appareil déjà enrôlé) ;
« aucune » ne serait admis pour les Mac que si un utilisateur sans téléphone
devait pouvoir commencer par le Mac ; et la question se rouvre si
`DCAppAttestService` s'avère disponible sur des Mac.

**Les applications** :

- **Mac** : sur la fiche « ce Mac », proposer d'activer l'écho s'il ne l'est
  pas, et montrer l'état : « preuve de clé vérifiée, constatée à 14:02 par
  la racine n-…, de l'extérieur » / « injoignable depuis l'annuaire » /
  « **une autre machine répond à cette adresse** » / « pas d'écho ».
- **iOS, Android** : le même état sur la fiche de chaque machine, lu dans
  `GET /v1/machines` (les miennes) et `GET /v1/domaines/{d}` (celles que je
  vois, décision 91) — les champs ci-dessus. **Le décodeur accepte
  les champs absents** (racine d'avant, pas d'écho) **et un mot inconnu**, dit
  tel quel plutôt que de refuser la liste. Une application ne sonde pas : un
  téléphone n'est pas une machine, et n'a pas de jeton.

### Travail à faire

Tout est tranché (décisions 89 à 98) ; ce qui suit est le découpage en PR,
**dans l'ordre où elles se mergent**. Chacune change la version ; le cran est
indiqué pour le serveur.

**Serveur** (`air-service-locator-server`), quatre PR :

1. **Le codec `asl-echo`** (mineur) : la crate d'étage 1 — les trois
   datagrammes et le jeton, écrits et lus, longueurs fixes, bourrage vérifié ;
   les quatre séparations de domaine dans `asl-cle` ; des vecteurs figés ;
   100 % de couverture (C2), une cible de fuzz par décodeur (C3). Le client
   la lit : elle précède tout ce que le client fait de l'écho.
   **Fait en 0.41.0** (« Le transport », ci-dessus).
2. **Le jeton** (mineur ; décision 91) : `POST /v1/echo/jetons` sur la voie
   machine, la décision de `GET /v1/ou/{m}/asl-echo` dans `asl-auth`, un essai
   C9 et un essai C10 ; la signature par la clé d'identité de la racine ; le
   débit et la ligne de journal ; `421` chez un annuaire local.
   **Fait en 0.42.0** (« Le jeton », ci-dessus).
3. **La sonde par l'écho et l'état** (mineur ; décisions 90 et 92) : le nom
   `asl-echo` réservé à sa forme ; son candidat réflexif au port observé
   (`asl-annuaire`, `Session::candidats`) ; le point UDP qui se sonde
   (`se_sonde`, les `Ordres`) ; une socket UDP de sonde et ses trois envois
   dans `asl-loop-tokio::sonde` ; `echo`, `echo_a`, `echo_par`, `echo_depuis`
   dans `GET /v1/machines` et `GET /v1/domaines/{d}` ; la même sonde chez un
   annuaire local, et son verdict dans l'état fédéré ; la sonde des racines
   vers les échos fédérés ; la cadence de quinze minutes.
   **Fait en 0.43.0.** Le nom réservé à sa forme : `asl-session` rend `400`
   à une annonce `asl-echo` qui ne porte pas un seul point UDP
   (`asl_proto::forme_d_echo`). `asl_annuaire::Session` sait qu'elle tient un
   écho : son point UDP se sonde, son candidat réflexif porte le port observé,
   et `a_resonder` rend ses points toutes les quinze minutes
   (`CADENCE_D_ECHO_MS`). `asl-loop-tokio::sonde::prouver` sonde depuis une
   socket UDP éphémère, trois envois d'une seconde, avec la sonde
   `0x01` signée par la clé d'identité de l'annuaire qui tient le bail — une
   racine, ou le membre de l'annuaire local — et vérifie la réponse sous la clé
   que l'entrepôt tient pour la machine. `asl-proto` accepte une mesure sur un
   point UDP (voir « Aucun mot nouveau », plus haut, pour ce que les lecteurs
   déployés en font). Les racines sondent du dehors l'écho que rapporte un
   membre, vers l'adresse et le port qu'il a vus, **si l'adresse est
   globale** (`asl_annuaire::adresse_globale`), une fois par changement et au
   plus tous les quarts d'heure (`sonder_du_dehors`). L'état par machine —
   `echo`, `echo_a`, `echo_par`, `echo_depuis` — est dans `GET /v1/machines`
   et dans les `machines` de `GET /v1/domaines/{d}`. **Trois précisions**,
   que la forme impliquait sans les écrire :
   - **`echo_depuis` d'un bail tenu par une racine** : `exterieur` si
     l'adresse observée est globale, `interieur` sinon — bouclage, privée,
     lien-local, ULA, partagée. Une racine n'a pas, comme un membre, de liste
     d'adresses à elle à comparer ; pour un écho qu'un membre rapporte, c'est
     la règle de `sonde_locale`, sur ses adresses ;
   - **un membre ne rapporte pas `autre_cle`** : son rapport est l'objet
     d'annonce, où une autre clé est `injoignable`. Les racines le disent
     quand ELLES sondent du dehors, et leur constat l'emporte alors sur celui
     du membre (`echo_par` à la racine, `exterieur`) ;
   - **la resonde du quart d'heure pousse le verdict à `asl echo`** chaque
     fois : `joignable` porte sa date, et une date nouvelle est un verdict
     nouveau.
4. **Le champ `passerelle`** (mineur ; décisions 94 et 97) : le champ
   `{"port", "via"}` de l'annonce `asl-echo` dans `asl-proto` (décodé, fuzzé,
   refusé sur toute autre annonce) ; son candidat en tête — adresse observée,
   port accordé — ; rapporté par un membre d'annuaire local et sondé par les
   racines sous les bornes de la décision 92 ; `echo_via` (`upnp` | `nat` |
   `direct`) sur la machine. La version qui le porte est celle qu'`asl echo`
   lira dans `GET /v1/version` avant d'envoyer le champ.
   **Fait en 0.44.0 — la version qu'`asl echo` lit avant d'envoyer
   `passerelle`.** `asl_proto::Annonce` porte `passerelle: Option<Passerelle>`
   (`{"port","via"}`, `via` ∈ `upnp` | `pcp` | `natpmp` : les deux derniers
   sont décidés, décision 96, et ce lecteur les connaît déjà) ; le décodeur la
   refuse sur toute autre annonce (`ChampHorsPropos`), et
   `Annonce::avec_passerelle` aussi (`PasserelleHorsEcho`). La session place
   son candidat en tête — l'adresse observée, le port accordé —, avant celui
   du bail, et une passerelle nouvelle dans une réannonce relance la sonde.
   L'annuaire sonde les candidats dans cet ordre, et le premier qui prouve
   arrête. **`echo_via`**, avec `verifie` seulement : `upnp` (ou `pcp`,
   `natpmp`) par la passerelle ; au port du bail, `direct` quand l'adresse
   observée est l'une de celles que la machine annonce (le verdict de NAT
   `non`), `nat` sinon — y compris sans adresse annoncée : l'annuaire ne dit
   pas « direct » sans l'avoir constaté (C6). Un membre d'annuaire local
   rapporte la passerelle aux racines dans son entrée d'état (un drapeau de
   plus, `asl_registre::PasserelleRapportee`) ; **une racine d'avant 0.44.0
   refuserait ce drapeau** — les racines se déploient donc d'abord. Les
   racines sondent du dehors la passerelle rapportée, puis le bail, sous les
   bornes de la décision 92. Pour un écho qu'un membre a vérifié, `echo_via`
   se déduit du candidat qui a répondu : au port observé, `nat` ou `direct`
   selon le verdict de NAT ; à un autre port, la passerelle que le membre
   rapporte.
5. **L'adresse de la box chez un annuaire local** (mineur, 0.45.0 ;
   décision 107) : `externe` dans la `passerelle` d'`asl-proto` (une IPv4
   pointée, `400` sinon ; fuzzé) ; le candidat de la passerelle chez
   l'annuaire du bail seulement si `externe` est absente ou égale à
   `vu_depuis` ; le drapeau `3` de l'entrée d'état (`asl-registre`) ; côté
   membre, la visite IPv4 vers chaque racine (à l'ouverture, puis tous les
   quarts d'heure ; le journal au changement) ; côté racine, l'adresse IPv4
   observée par membre (trente minutes), la comparaison avec `externe`, la
   sonde `E:P` en tête quand elles concordent, le journal quand elles ne
   concordent pas. Les essais : la concordance sonde en IPv4 et rend
   `verifie`, `upnp`, `exterieur` ; la discordance ne sonde pas en IPv4, et
   le dit.
   **Fait en 0.45.0 — la version qu'`asl echo` lit avant d'écrire
   `externe`.** `asl_proto::Passerelle` porte `externe:
   Option<Ipv4Addr>` ; `asl_annuaire::Session::candidats` ne pose le
   candidat de la passerelle que si `externe` est absente ou égale à
   `vu_depuis` ; `asl_registre::PasserelleRapportee` porte l'adresse, et
   l'entrée d'état le drapeau `3`. Côté membre, le fédérateur tient la
   visite dans **sa propre tâche** — une racine muette en IPv4 ne retient
   jamais la voie —, réveillée à chaque ouverture de la voie et tous les
   quarts d'heure ; l'adresse visitée est celle de la liste embarquée
   (`racines::visite_ipv4_pour`), aucune si `--federation` est déjà une
   IPv4 ou désigne plusieurs identités (l'alias commun). Côté racine,
   `EtatFedere::noter_une_ipv4` retient l'adresse de toute requête d'un
   membre accepté (trente minutes, `IPV4_VUE_US`), et
   `asl_annuaire::sonder_l_ipv4` décide : sonder, pas vue, discordante, non
   globale — le journal le dit au changement, par machine. **Une
   précision** : un écho dont l'adresse externe est celle que le membre a
   vue (`vu_depuis`) garde la règle de la décision 97 — la passerelle à
   l'adresse vue —, sans passer par la comparaison.

**Client** (`air-service-locator-client`), six PR, après les PR 1 et 2 du
serveur :

1. **`asl echo`, sur la socket du bail** (décisions 89, 90, 93) :
   `asl-client-tokio` sait tenir une connexion sur une socket non connectée
   qu'on lui donne, et rend à l'appelant les datagrammes qui ne sont pas du
   QUIC (`lib.rs:255-262`) ; puis tirer le port, annoncer `asl-echo`, tenir le
   bail comme `asl announce` (`crates/asl-cli/src/commandes.rs:436-527`),
   répondre aux sondes, borner le débit, refuser root, dire le verdict poussé ;
   `--install` / `--uninstall` sur Mac (le LaunchAgent).
2. **`asl ping`** (décisions 91 et 93) : résoudre un `m-…`, un nom ou un
   alias, demander le jeton, sonder, vérifier, dire d'où ; les codes de
   sortie ; l'ABI (`asl-client-ffi`) si une liaison en veut.
3. **UPnP** (décisions 94 à 97) : **notre** client IGD, codec d'étage 1
   couvert et fuzzé, `igd-next` lu comme référence (E17), dans `asl-cli`
   seulement, jamais dans `asl-client` (C4) ; SSDP sur le lien local (IPv4 et
   IPv6), `LOCATION` littérale seulement (C20) ; `AddAnyPortMapping` /
   `AddPortMapping` du seul port de l'écho ; `GetExternalIPAddress` comparée à
   `vu_depuis` — un double NAT se dit et ne s'annonce pas (E19) ; `AddPinhole`
   si la box le propose, silence sinon hors du mode bavard (E20) ; le bail
   d'une heure renouvelé toutes les trente minutes, permanent seulement si la
   box l'exige, retiré à l'arrêt et, après un arrêt brutal, au démarrage
   suivant (E18) ; la recherche de la box au démarrage, toutes les trente
   minutes et à chaque changement d'adresse (E23) ; actif par défaut,
   `--no-upnp` et `ASL_ECHO_UPNP=0` (E15) ; la réannonce avec `passerelle`
   vers un annuaire dont la version l'accepte (E21 ; PR 4 du serveur).
4. **PCP, puis NAT-PMP en repli** (décision 96 ; E16) : le codec binaire
   d'étage 1, fuzzé ; la passerelle par défaut lue sous Linux et sous macOS ;
   les mêmes règles que pour UPnP, `via` = `pcp` ou `natpmp`.
5. **L'unité systemd utilisateur** (décision 93) : `asl-echo.service` posée
   désactivée par `scripts/paquet.sh`, sans script de mainteneur, et
   `check-paquet.sh` qui le vérifie ; la page de manuel (`asl echo`,
   `asl ping`, `--no-upnp`, `loginctl enable-linger`).
6. **L'identité sur macOS** (décision 93, révisée) : `etat.rs` cherche
   `--state`/`ASL_STATE` sans repli, puis le conteneur de groupe
   `SB7H9B6TY8.org.airdesktop.servicelocator`, puis l'ancien conteneur de
   l'application (avec un avertissement), puis `~/.config/asl` ; il dit quand
   deux identités différentes coexistent ; le chemin se calcule depuis le
   répertoire de l'utilisateur, pas depuis `HOME` (bac à sable). Elle précède
   la migration de l'application Mac.
7. **Le bail en IPv4 quand la box ne perce pas son pare-feu IPv6**
   (décision 106) : la passerelle conclut, à chaque tour, dans quelle famille
   le bail doit se tenir ; l'écho ferme le bail IPv6 et rouvre en IPv4 sur la
   même socket — double pile posée explicitement —, vérifie `vu_depuis`
   contre l'adresse externe de la box, et ne revient en IPv6 que sur un trou
   obtenu, une redirection perdue ou un double NAT révélé. Rien côté serveur.
8. **L'adresse externe confirmée chez un annuaire local** (décision 107 ;
   après la PR 5 du serveur) : quand le bail va à un annuaire local, sans
   trou IPv6, avec une redirection IPv4 et une adresse externe publique,
   `passerelle` porte `externe` (`GetExternalIPAddress`, déjà lue pour le
   double NAT) — vers un annuaire local en 0.45.0 au moins.
9. **La socket liée à l'adresse IPv6 stable** (décision 108) : lire les
   drapeaux dans `/proc/net/if_inet6` sous Linux (`IFA_F_TEMPORARY`,
   `IFA_F_DEPRECATED`, `IFA_F_TENTATIVE`, `IFA_F_DADFAILED`) ; retenir
   l'interface de l'adresse source que le système prendrait pour l'annuaire,
   et la plus petite de ses adresses stables et globales, ULA exclues ;
   annoncer CETTE adresse ; relier la socket au même port, en `[::]` double
   pile, pour une bascule en IPv4, et s'y relier au retour ; garder le choix
   du système ailleurs (macOS) et le dire une fois. Rien côté serveur.

**Applications**, après la PR 3 du serveur (et la PR 4 pour `echo_via`) :

1. **Mac, iOS, Android — l'état d'écho** sur la fiche d'une machine :
   `echo`, `echo_a`, `echo_par`, `echo_depuis`, `echo_via` ; décodeur
   tolérant (champs absents, mot inconnu dit tel quel) ; sur « ce Mac »,
   proposer d'activer l'écho.
2. **Mac — le groupe d'application, la migration, l'agent** (décision 93,
   révisée), après la PR 6 du client : les droits de bac à sable et de groupe
   sur l'application et l'agent ; la migration de l'identité vers le conteneur
   de groupe (copier, relire, comparer, puis retirer ; les échecs partiels) ;
   l'agent `SMAppService` activé depuis « ce Mac » ; ce qu'on dit à l'App
   Review.
3. **Mac, plus tard — rejoindre plutôt que créer** (décision 98) : le jour où
   une racine refuse `aucune`, l'application Mac n'offre plus que de rejoindre
   un compte ouvert sur un téléphone attesté. Rien à coder avant.

### Les questions E1 à E14 — tranchées

**Thierry a répondu le 2026-09-29 : « d'accord pour tout ».** Chaque
recommandation est devenue une décision ; les questions restent écrites avec
leurs options, pour qu'on sache ce qui a été écarté.

**E1. Par quoi l'écho répond-il ?**
- (a) **Des datagrammes UDP bruts, un aller-retour signé.** Pas d'état avant
  vérification, pas d'amplification, un codec de plus à fuzzer.
- (b) QUIC. On réutilise la pile, mais il faut un certificat par machine,
  deux allers-retours, et une connexion lourde que n'importe qui peut ouvrir.
- (c) UDP, avec un repli TCP (même format, préfixé de sa longueur). Pour les
  réseaux qui bloquent l'UDP sortant ; un second chemin à tenir.
- **Décidé (2026-09-29, Thierry ; décision 90) : (a)**, et (c) plus tard si un réseau réel le demande.

**E2. L'écho écoute-t-il sur la socket de son propre bail ?**
- (a) **Oui.** Derrière une box IPv4, le port vu par l'annuaire est celui de
  l'écho, et le keepalive le garde ouvert : l'UDP devient joignable sans
  redirection de port, là où le NAT le permet. Il faut modifier la
  bibliothèque cliente (socket non connectée, tri au premier octet).
- (b) Non, une socket à part. Rien à modifier côté bibliothèque, mais derrière
  un NAT IPv4, l'écho n'est joignable que si l'on redirige son port — qui
  change à chaque démarrage.
- **Décidé (2026-09-29, Thierry ; décision 90) : (a).**

**E3. Que signe la réponse ?**
- (a) **Le défi, le `m-…`, l'adresse vue du sondeur, et l'identité du
  sondeur.** La preuve ne sert qu'à celui qui l'a demandée, et dit d'où.
- (b) La même chose, plus l'heure de la machine. Une date signée par la machine
  elle-même ; mais elle dévoile son horloge, et le défi suffit déjà.
- (c) Le défi et le `m-…` seulement. Plus court, mais une preuve pourrait être
  obtenue pour le compte d'un autre.
- **Décidé (2026-09-29, Thierry ; décision 90) : (a).**

**E4. Quelles sondes d'annuaire l'écho croit-il ?**
- (a) **Celle de l'annuaire qui tient son bail, et elle seule.** La règle la
  plus étroite ; les racines ne sondent pas une machine d'un domaine hébergé.
- (b) Celle-là, et celles des racines embarquées. Nécessaire si l'on répond
  « oui » à E8.
- **Décidé (2026-09-29, Thierry ; décision 91) : (b)**, puisque E8 est « oui ».

**E5. Combien de temps vit un jeton, et à quoi est-il lié ?**
- (a) **Soixante secondes, lié à la clé du sondeur et à celle de la cible** ;
  horloge de l'écho juste à deux minutes près.
- (b) Cinq minutes : plus tolérant aux horloges et aux réseaux lents, mais un
  droit retiré continue de servir cinq minutes.
- (c) Lié à l'adresse du sondeur plutôt qu'à sa clé : pas de signature du
  sondeur, mais faux dès que la machine change d'adresse ou de famille.
- **Décidé (2026-09-29, Thierry ; décision 91) : (a).**

**E6. Qui peut lancer `asl ping` vers une machine ?**
- (a) **Qui tient `localiser`** sur elle (ou son domaine) — la règle de
  `GET /v1/ou`, qui donne déjà son adresse.
- (b) Qui tient `voir` : plus large, mais `asl ping` révèle l'adresse, que
  `voir` ne donne pas (décision 80).
- (c) Son propriétaire seulement.
- **Décidé (2026-09-29, Thierry ; décision 91) : (a).**

**E7. Qui voit l'état d'écho (vérifié, injoignable, autre clé) ?**
- (a) Le propriétaire seulement (`GET /v1/machines`).
- (b) **Le propriétaire, et qui tient `voir` sur le domaine**
  (`GET /v1/domaines/{d}`) — `voir` donne déjà « l'état » (`modele.md` §2.13),
  sans adresse.
- **Décidé (2026-09-29, Thierry ; décision 91) : (b).**

**E8. Les racines sondent-elles aussi, du dehors, l'écho d'une machine d'un
domaine hébergé par un annuaire local ?**
- (a) Non : seul l'annuaire local sonde, souvent de l'intérieur, et l'état le
  dit ; pour savoir du dehors, on lance `asl ping` d'ailleurs.
- (b) **Oui, borné** : vers l'adresse que l'annuaire local a vue, si elle est
  globale, une fois par changement et par quart d'heure. On sait enfin si la
  maison est joignable de l'Internet ; en échange, les racines envoient un
  datagramme vers une adresse qu'un annuaire local leur a rapportée.
- **Décidé (2026-09-29, Thierry ; décision 92) : (b)** — c'est exactement le cas du pare-feu de speedy
  (27/09).

**E9. Quand l'annuaire sonde-t-il l'écho ?**
- (a) À l'annonce et à chaque changement d'adresse, comme aujourd'hui.
- (b) **Cela, et toutes les quinze minutes** tant que le bail tient : un
  datagramme, pour que « constaté à » reste frais et qu'un pare-feu fermé
  depuis se voie.
- **Décidé (2026-09-29, Thierry ; décision 92) : (b).**

**E10. Comment l'écho tourne-t-il sous Linux ?**
- (a) **Une unité utilisateur** (`systemctl --user`), posée désactivée par le
  paquet ; `loginctl enable-linger` sur un serveur sans session.
- (b) Une unité système modèle `asl-echo@<compte>`, activée par root : démarre
  au boot sans rien de plus, mais c'est root qui décide pour la clé d'un
  utilisateur.
- (c) Les deux.
- **Décidé (2026-09-29, Thierry ; décision 93) : (a)**, et (b) seulement si un parc réel le demande.

**E11. Comment l'écho tourne-t-il sur un Mac ?**
- (a) **Un LaunchAgent** `~/Library/LaunchAgents/org.airdesktop.asl-echo.plist`
  posé par `asl echo --install`, pour qui a installé `asl` ; **et** un agent
  embarqué dans l'application Mac (`SMAppService`), activé depuis « ce Mac »,
  pour un Mac enrôlé par l'application.
- (b) Seulement le LaunchAgent d'`asl` : l'application ne fait que montrer
  l'état et dire la commande à taper.
- **Décidé (2026-09-29, Thierry ; décision 93) : (a)** — **révisé le même jour** :
  l'application ira aussi sur le Mac App Store ; l'application et l'agent sont
  en bac à sable, et partagent le conteneur de groupe
  `SB7H9B6TY8.org.airdesktop.servicelocator`, où l'identité déménage
  (« L'installation », ci-dessus : le chemin, la migration, l'ordre de
  recherche d'`asl`).

**E12. Que peut-on donner à `asl ping` ?**
- (a) Un `m-…` seulement.
- (b) **Un `m-…`, ou un nom ou un alias de machine** cherché parmi les
  machines que ce compte voit ; plusieurs réponses → la liste, et aucun choix
  fait à sa place. (Aucune route ne résout un alias de machine aujourd'hui :
  `modele.md` §6.0 ; la recherche se ferait dans `asl`, sur ce qu'il sait
  lister.)
- **Décidé (2026-09-29, Thierry ; décision 93) : (b).**

**E13. Le nom `asl-echo` est-il réservé ?**
- (a) **Réservé à sa forme** : une annonce `asl-echo` porte un seul point, en
  UDP, sinon `400` ; l'annuaire le sonde par l'écho.
- (b) Réservé à `asl echo` : impossible à vérifier (la clé est par machine) —
  une promesse que le serveur ne peut pas tenir.
- (c) Pas réservé : un daemon qui prendrait ce nom pour autre chose serait
  sondé par l'écho et dit injoignable.
- **Décidé (2026-09-29, Thierry ; décision 90) : (a).**

**E14. L'écho est-il actif par défaut ?**
- (a) **Non** : le paquet pose l'unité désactivée ; `asl enroll` suggère de
  l'activer, et l'application Mac le propose.
- (b) Oui, dès l'enrôlement : chaque machine est vérifiable d'office, mais un
  port s'ouvre sans que personne l'ait demandé — et le paquet devrait exécuter
  un script pour l'activer.
- **Décidé (2026-09-29, Thierry ; décision 93) : (a).**

### Les questions E15 à E23 — tranchées

**Thierry a répondu le 2026-09-29 : « d'accord pour tout ».** Comme pour E1
à E14, chaque recommandation est devenue une décision (95 à 98), et les
options écartées restent écrites.

**E15. UPnP est-il actif par défaut ?**
- (a) **Oui** : `asl echo` demande une redirection à la box sans qu'on le lui
  dise, et `--no-upnp` l'en empêche. Toutes les chances, comme tu le veux ;
  en échange, un port s'ouvre sur la box dès que l'écho tourne (l'écho, lui,
  n'est pas actif par défaut : décision 93).
- (b) Non : il faut `--upnp`. Rien ne change sur la box sans un geste, mais
  la plupart des gens ne le feront pas, et l'écho restera injoignable du
  dehors derrière une box IPv4.
- **Décidé (2026-09-29, Thierry ; décision 95) : (a).**

**E16. Faut-il aussi parler NAT-PMP ou PCP, quand UPnP ne répond pas ?**
- (a) Non, UPnP seul en v1 : un protocole de moins.
- (b) PCP seul (RFC 6887) : il sait aussi ouvrir un trou IPv6, et certaines
  box le préfèrent à UPnP.
- (c) PCP, et NAT-PMP (RFC 6886) quand la box ne connaît que lui : les deux
  partagent le port 5351, et PCP prévoit ce repli. Un codec binaire de plus,
  petit ; il faut trouver l'adresse de la passerelle (la route par défaut),
  différemment sous Linux et sous macOS.
- **Décidé (2026-09-29, Thierry ; décision 96) : (c)**, après UPnP, dans
  une PR à part : c'est ce qui donne le plus de chances, et le format est
  bien plus simple que celui d'UPnP.

**E17. Utiliser `igd-next`, ou écrire notre propre client UPnP ?**
- (a) `igd-next` : MIT, Rust pur, IGD v1 et v2 déjà écrits. Mais une trentaine
  de crates de plus, pas de trou IPv6, et des décodeurs XML et HTTP qui lisent
  ce qu'envoie un appareil du réseau sans être fuzzés par nous (C3).
- (b) **Le nôtre**, dans le dépôt client, réservé à `asl` : quelques centaines
  de lignes, aucune dépendance, fuzzé, et le trou IPv6 compris.
- **Décidé (2026-09-29, Thierry ; décision 96) : (b)**, en lisant
  `igd-next` comme référence.

**E18. Combien de temps dure la redirection ?**
- (a) **Une heure, renouvelée toutes les trente minutes** ; permanente
  seulement si la box n'accepte que cela, et retirée au démarrage suivant si
  l'écho s'est arrêté brutalement.
- (b) Toujours permanente : plus simple, mais une redirection oubliée reste
  sur la box pour toujours si la machine disparaît.
- (c) Jamais permanente : on se passe d'UPnP sur les box qui l'exigent (les
  vieilles, souvent).
- **Décidé (2026-09-29, Thierry ; décision 95) : (a).**

**E19. Et s'il y a deux NAT (la box derrière celle de l'opérateur, ou derrière
une autre box) ?**
- (a) **On ne l'annonce pas, et on le dit** : « double NAT, la redirection ne
  suffira pas ». La redirection reste posée (elle ne gêne pas), mais
  l'annuaire n'en entend pas parler.
- (b) On essaie aussi d'ouvrir la box du dessus : UPnP ne le permet pas (on ne
  la voit pas depuis le réseau local), et PCP seulement si l'opérateur le
  sert.
- **Décidé (2026-09-29, Thierry ; décision 97) : (a).**

**E20. Le trou IPv6 dans le pare-feu de la box (`AddPinhole`) ?**
- (a) **On le tente si la box le propose** et l'autorise ; sinon on se tait (le
  dire seulement en mode bavard). C'est rare, mais ça ne coûte presque rien.
- (b) Pas en v1 : moins de code, mais une machine en IPv6 derrière un pare-feu
  de box reste injoignable du dehors, même quand la box aurait accepté.
- **Décidé (2026-09-29, Thierry ; décision 97) : (a).**

**E21. Comment l'annuaire apprend-il la redirection, et comment le dit-il ?**
- (a) **Un champ `passerelle` dans l'annonce de l'écho (le port seul, et
  `via`), l'adresse étant toujours celle que l'annuaire a observée ; puis
  `echo_via` = `upnp` | `nat` | `direct` sur la machine**, en chaînes. Il
  faut un annuaire à jour ; l'écho vérifie sa version avant d'envoyer le champ.
- (b) Aucun champ : on compte sur la box pour que les paquets sortants
  prennent le port de la redirection. Souvent faux, et l'annuaire ne saurait
  pas par où la preuve est passée.
- (c) Un champ avec l'adresse externe aussi : écarté — l'annuaire sonderait
  une adresse que le client choisit, c'est-à-dire n'importe laquelle.
- **Décidé (2026-09-29, Thierry ; décision 97) : (a).**

**E22. Si les racines finissent par refuser les comptes en attestation
« aucune », que fait le Mac ?** Aujourd'hui le Mac ouvre son compte en
« aucune » (App Attest n'y existe pas, selon nos essais ; à vérifier dans la
documentation d'Apple) ; une racine qui exigerait une attestation l'en
empêcherait.
- (a) **Garder « aucune » admis pour les Mac** tant qu'Apple n'offre rien
  (la posture facultative, ou une exception par plate-forme) : le Mac reste
  utilisable ; sa clé vit dans l'enclave, sous Touch ID, sans que l'annuaire
  puisse le prouver.
- (b) Un Mac ne crée jamais de compte : il **rejoint** un compte ouvert sur un
  téléphone attesté (`POST /v1/appareils`, signé par un appareil déjà
  enrôlé). Il reste utilisable, mais on ne peut plus commencer par le Mac.
- (c) Refuser le Mac tant qu'il ne s'atteste pas : plus de Mac du tout.
- **Décidé (2026-09-29, Thierry ; décision 98) : (b)**, et (a) seulement
  si un utilisateur sans téléphone doit pouvoir commencer ; revoir si
  `DCAppAttestService` s'avère disponible sur des Mac.

**E23. Quand l'écho cherche-t-il la box ?**
- (a) **Au démarrage, toutes les trente minutes, et quand l'adresse de la
  machine change** (une migration du bail, un autre réseau) : une box
  redémarrée, ou un portable qui change de Wi-Fi, retrouve sa redirection.
- (b) Au démarrage seulement : plus simple, mais une box redémarrée qui a perdu
  la redirection n'en redonne pas avant le redémarrage de l'écho.
- **Décidé (2026-09-29, Thierry ; décision 95) : (a).**

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

**L'écho en réalise un cas, pour lui seul** (décidé ; décision 90, §3 quater,
question E2) : `asl echo` tient son bail **sur la socket où il écoute**, et son
candidat réflexif porte alors le port observé. Le cas général — le daemon d'un
autre, avec sa propre socket — reste repoussé.

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
