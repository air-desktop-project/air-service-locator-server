# Les annuaires — réplication et fédération

Un annuaire appartient à un utilisateur. Il y en a plusieurs, et ils se parlent.

**Ce document est le moins avancé des quatre.** Il pose les trois relations qu'il
ne faut pas confondre, l'ancre de confiance, ce qui se réplique et ce qui ne doit
surtout pas se répliquer. Le reste est nommé comme ouvert plutôt que supposé
résolu — la synchronisation entre autorités distinctes est le sujet où une
décision prise à la légère coûte le plus cher, et le plus tard.

**Le 2026-09-26, la fédération a pris une forme précise (Thierry)** : l'annuaire
**local** d'un utilisateur, qui fait autorité sur des **domaines** (`modele.md`
§2.11) et que les racines fédèrent (§2 bis, §4.1, §5.4). Trois choses écrites
ici en sont renversées, et chacune le dit à sa place — **l'inscription libre**
(§1, §4.1), **« le propriétaire des racines n'arbitre rien »** (§1, §4.3) pour
ce qui est de l'inscription, et **« l'état vivant ne traverse pas la
fédération »** (§3, §5.3). Le reste — l'annuaire `ordinaire` qui fait autorité
sur des comptes, la confiance bilatérale, la réplication sélective — devient une
suite nommée (§8).

---

## 1. TROIS relations, et les confondre serait la faute

Elles ont l'air de la même — « faire que deux annuaires aient les mêmes
données » — et elles n'ont ni le même modèle de confiance, ni la même portée, ni
le même protocole.

| | **Réplication des racines** | **Enregistrement** | **Confiance bilatérale** |
|---|---|---|---|
| Entre qui | Les deux racines | Un annuaire et une racine | Deux annuaires quelconques |
| Autorité | **La même** | Différentes | Différentes |
| Ce qui circule | Tout | **L'existence de l'annuaire, et rien d'autre** | Ce que les deux administrateurs ont choisi |
| Qui décide | Personne — c'est de la haute disponibilité | L'annuaire qui s'enregistre | **Les DEUX administrateurs** |
| Ce qu'on craint | Une panne | Un annuaire qui usurpe une identité | Un pair qui ment |

**Une quatrième relation, depuis le 2026-09-26 : la FÉDÉRATION d'un annuaire
local** (§2 bis, §4.1, §5.4).

| | **Fédération d'un annuaire local** |
|---|---|
| Entre qui | Un annuaire local et les racines |
| Autorité | Différentes — les racines sur les comptes, le local sur les domaines qu'il héberge |
| Ce qui circule | **Vers le local** : les machines rattachées à ses domaines, avec leurs clés et leurs révocations. **Vers les racines** : les services de ces machines et leur état vivant — identifiant, adresse, port, vivant ou non |
| Qui décide | **Un administrateur des racines approuve l'inscription** (`modele.md` §2.12) |
| Ce qu'on craint | Un annuaire qui affirmerait des adresses fausses, et ferait des racines le relais de son mensonge |

**S'enregistrer auprès d'une racine ne donne accès à RIEN** — pour un annuaire
`ordinaire`, qui ne demande qu'à être recensé (§4.1, suite nommée §8). C'est se faire
recenser, pour que d'autres annuaires puissent vous trouver et vous proposer une
relation. Une racine est un **registre et un entremetteur**, pas un dépositaire :
elle ne détient pas les données des annuaires qu'elle recense.

**La confiance n'est pas centrale, elle est bilatérale.** Ce sont les
administrateurs des deux annuaires concernés qui l'acceptent, jamais le
propriétaire des racines. Il ne joue aucun rôle d'arbitre, et ne doit pas en
jouer : un réseau où le fondateur décide qui parle à qui n'est pas une
fédération.

**Ce paragraphe ne vaut plus pour l'annuaire local, et c'est décidé** (2026-09-26,
`replication.md` décision 32) : son inscription est **approuvée** par un
administrateur des racines. Ce n'est pas décider « qui parle à qui » — deux
annuaires locaux ne se parlent pas —, c'est décider **ce que les racines
acceptent de servir en leur nom** : un annuaire local ne se contente pas d'être
recensé, il fait porter par les racines l'état de ses services (§5.4). Ce qui
reste vrai : entre deux annuaires `ordinaires`, la confiance est bilatérale et
personne ne l'arbitre (§4.3, suite nommée §8).

## 2. L'autorité

**Tout objet a exactement un annuaire d'autorité, et un seul.** Celui où le
compte a été créé.

- Un compte, ses appareils, ses machines, ses services et les autorisations
  qu'il accorde relèvent de son annuaire d'autorité.
- **Un annuaire n'accepte d'un pair QUE ce dont ce pair est l'autorité**, et il
  le vérifie à la signature. C'est la contrainte C11, et elle est la seule chose
  qui sépare une fédération d'une pagaille.
- Un annuaire qui reçoit une assertion hors du périmètre de son émetteur la
  **refuse et la journalise**. Il ne la corrige pas, il ne l'ignore pas en
  silence : une assertion hors périmètre est soit un défaut, soit une attaque, et
  les deux méritent d'être vues.

## 2 bis. L'autorité par DOMAINE — l'annuaire local

**Décidé le 2026-09-26 (Thierry).** Un utilisateur déploie chez lui — sur une
de ses machines, macOS ou Linux, Windows plus tard — une instance
d'`asl-server` : son **annuaire local**. Il y héberge un ou plusieurs de ses
domaines (`modele.md` §2.11), et **l'annuaire local fait autorité sur ce que
ces domaines contiennent** ; les racines ne font autorité que sur la racine —
les comptes, leurs appareils, leurs autorisations, et les domaines qu'aucun
annuaire local n'héberge.

**Ce que l'autorité se partage, à la ligne** — et le partage est ce qui la rend
sûre (décidé le 2026-09-26, Thierry) :

| Ce qui s'écrit | Où | Pourquoi là |
|---|---|---|
| Le compte, ses appareils, ses autorisations, son alias | **Racines** | Rien ne change : c'est le compte, et il n'est pas dans un domaine. |
| Le domaine lui-même — propriétaire, alias, hébergeur ; **ses groupes, leurs membres, les droits** | **Racines**, depuis les applications | Ce sont des décisions du **compte**, sous biométrie. Un annuaire local, qui n'est qu'une machine chez quelqu'un, ne doit pas pouvoir réécrire à qui appartient un domaine, qui le gère, ni qui peut y lire. |
| **Le domaine racine** — niveau 0, son groupe d'administrateurs (`modele.md` §2.11) | **Racines**, sous la clé d'exploitant pour ses administrateurs | Il n'est hébergé par aucun annuaire local, et ne transmet aucun droit aux domaines du niveau 1. |
| La machine — nom, capacités, clé, domaine de rattachement | **Racines**, depuis les applications | Même raison ; c'est aussi là que la clé s'enrôle. Les racines les **transmettent** à l'annuaire local qui héberge le domaine, pour qu'il authentifie les annonces (§5.4). |
| **Les services** d'une machine rattachée à un domaine hébergé, et **leur état vivant** | **L'annuaire local** | C'est à lui que les daemons s'annoncent : il est le seul à les voir. Il en informe les racines (§5.4). |

**C11 prend donc une forme nouvelle** : un annuaire local n'est cru que sur les
services des machines rattachées aux domaines qu'il héberge, et qu'on lui a
transmises. Une affirmation sur une autre machine est **refusée et journalisée**
(`contraintes.md` C11).

**Les machines d'un domaine hébergé s'annoncent à l'annuaire local**, qui relaie
aux racines. Une machine sans domaine, ou dans un domaine hébergé par les
racines, s'annonce aux racines comme aujourd'hui.

### L'ancre de confiance — deux adresses ET deux clés

Les deux racines vivent sur **deux adresses IPv6 connues de tout annuaire**,
inscrites dans le code. C'est le point de départ : un annuaire neuf n'a rien
d'autre.

**Une adresse ne suffit pas, et l'oublier serait la faille de tout l'édifice.**
Qui détourne une route parle depuis cette adresse. Ce qui est épinglé dans le
code, ce sont donc **les CLÉS PUBLIQUES des deux racines**, et l'adresse n'est
qu'un moyen de les joindre. Un annuaire qui répond sur la bonne adresse sans
pouvoir signer n'est pas une racine.

### Les deux machines existent — et elles ne satisfont PAS la contrainte ci-dessous

Provisionnées le **2026-09-09**, sur le domaine `air-desktop.org` :

| Racine | IPv6 | IPv4 | Système |
|---|---|---|---|
| `nitrogen.air-desktop.org` | `2001:41d0:20a:900::1dd4` | `178.32.16.250` | Ubuntu 26.04 LTS |
| `argon.air-desktop.org` | `2001:41d0:20a:900::1d32` | `178.32.16.249` | Ubuntu 26.04 LTS |

**`2001:41d0::/32` EST L'ALLOCATION D'OVH, PAS LA NÔTRE.** Ces adresses sont
donc perdues le jour où l'on change d'hébergeur — exactement ce que le point
suivant interdit. Le problème est réel et il est ouvert ; trois issues, et
aucune n'est gratuite :

1. **Une allocation à nous** (PI, via un RIR ou un courtier), annoncée par
   l'hébergeur du moment. C'est la seule qui tienne la promesse littéralement,
   et c'est un engagement administratif et financier durable.
2. **Ancrer sur les NOMS plutôt que sur les adresses.** `nitrogen.air-desktop.org`
   nous suit d'un hébergeur à l'autre. Mais un annuaire neuf devrait alors
   résoudre un nom avant de parler — donc embarquer un client DNS, dépendre
   d'un résolveur, et hériter de ce qu'un résolveur peut faire de travers.
3. **Accepter la renumérotation**, et prévoir que les deux ancres soient
   REMPLAÇABLES : un annuaire qui ne joint plus ses racines apprend les
   nouvelles adresses par un canal signé. Cela déplace le problème vers « qui
   signe la mise à jour », ce qui est au moins une question qu'on sait traiter —
   les clés publiques, elles, sont déjà l'ancre véritable.

**Depuis le 2026-09-27, la poignée de main TLS elle-même s'appuie sur ces
clés** (§2 quater) : l'issue 3 devient la voie retenue, et l'issue 2 est
abandonnée.

**Ce qui est épinglé dans le code reste les CLÉS**, et c'est ce qui rend les
trois issues envisageables plutôt qu'urgentes : une adresse qui change ne trahit
personne tant que la signature ne suit pas.

Deux conséquences qu'il faut regarder en face :

- **Ces adresses ne se renumérotent pas.** Elles sont dans du code déployé chez
  des tiers qui ne se mettent pas à jour. Elles doivent venir d'une allocation
  qu'on ne perd pas en changeant d'hébergeur.
- **Une racine joignable seulement en IPv6 exclut un annuaire sur un réseau
  IPv4.** C'est cohérent avec « IPv6 d'abord » (`modele.md` §1) et c'est un
  choix plus dur : ici IPv4 n'est pas un repli dégradé, il est absent. À
  confirmer, parce que cela décide qui peut déployer un annuaire.

### Comment on sait à qui demander

Un identifiant porte 128 bits d'aléa et **ne dit pas d'où il vient**. C'est un
choix, et il a une contrepartie : il faut un moyen de savoir quel annuaire fait
autorité pour un compte donné.

**Les racines tiennent l'index DES ANNUAIRES**, pas celui des comptes. Elles
savent quels annuaires existent et comment les joindre ; c'est ce qui leur
permet de jouer les entremetteurs (§4).

Savoir quel annuaire fait autorité pour un compte donné est une autre question,
et elle se pose différemment selon ce qu'on a répliqué (§5) : un annuaire qui a
souscrit aux comptes d'un pair sait déjà à qui ils appartiennent.

L'autre forme — **faire porter l'annuaire par l'identifiant** (`u-<annuaire>-<aléa>`)
— éviterait cet index et rendrait la résolution autonome. Elle a été écartée
pour une raison précise : un compte ne pourrait plus changer d'annuaire sans
changer d'identifiant, et un identifiant est ce qu'on a transmis à ses amis par
SMS. **Ce n'est pas une décision fermée** — elle mérite d'être rouverte le jour
où le coût de l'index se mesurera.

## 2 quater. L'identité par la clé — ASL sans DNS

**Décidé le 2026-09-27 (Thierry)**, dans ses mots :

> « ASL doit pouvoir fonctionner SANS DNS. Ce service REMPLACE le DNS
> classique : la différence est qu'il est HORS de contrôle des structures
> classiques : un utilisateur crée ses domaines SANS l'avis de qui que ce soit,
> les enregistre, les maintient, les déploie sur ses machines, et résout
> ensuite des noms/alias sans dépendre de qui que ce soit. Dès lors qu'il
> dispose d'un compte, il dispose de l'accès aux ressources propagées par ce
> service. »

Et sa question : les certificats doivent-ils reposer sur le nom DNS, ou sur
les identifiants ASL ? **Sur les identifiants.** C'est la contrainte C20
(`contraintes.md`) et les décisions 53 à 58 (`replication.md`).

### Ce qui dépendait encore du DNS, et le principe qu'on appliquait à moitié

§2 posait déjà la bonne règle — « ce qui est épinglé, ce sont les CLÉS
PUBLIQUES des racines, et l'adresse n'est qu'un moyen de les joindre » —, et
l'identifiant `n-…` d'un annuaire se DÉDUIT déjà de sa clé d'identité
(`modele.md` §2.7). Mais la poignée de main TLS, elle, jugeait encore un
**nom** sous une **autorité** : le client exigeait un certificat qui remonte à
une racine PEM (`--roots`, `--ca`, `--peer-ca`, `--federation-ca`) et qui porte
le nom demandé (`nitrogen.air-desktop.org`). D'où, à la première mise en
service d'un annuaire local, une autorité TLS à frapper pour la maison et un
enregistrement DNS à publier : exactement la dépendance que le produit refuse.

### La règle : on joint une ADRESSE, on attend une IDENTITÉ

1. **L'identité d'un annuaire EST sa clé d'identité Ed25519** — celle d'où se
   déduit son `n-…`. Racine ou annuaire local, il présente en TLS un
   **certificat auto-signé par cette clé**. Il n'y a ni autorité, ni nom jugé,
   ni date jugée.
2. **Le client vérifie deux choses, et rien d'autre** : que la clé publique du
   certificat se déduit en l'identifiant `n-…` qu'il attend (la dérivation de
   `modele.md` §2.7), et la signature de la poignée de main TLS 1.3, qui prouve
   la possession de cette clé. Un certificat valide sous n'importe quelle
   autorité, pour n'importe quel nom, qui ne porte pas LA clé attendue, n'est
   pas l'annuaire.
3. **Les adresses ne sont que des locateurs.** Une IPv6, une IPv4, ou un nom
   DNS si l'on en a un : le client s'en sert pour joindre, jamais pour croire.
   Une adresse qui change ne trahit personne ; une adresse détournée ne sert à
   rien à qui n'a pas la clé.
4. **Où le client apprend l'identité attendue** :
   - les **racines** : une liste embarquée dans le logiciel et les
     applications, `{n-…, clé, locateurs}` pour chacune (§2 : c'est l'ancre, et
     elle l'était déjà) ;
   - un **annuaire local** : par les racines — le `421` porte déjà son `n-…`
     et les adresses de ses membres (`protocole.md` §3 ter) ; et les
     applications le lisent dans `GET /v1/annuaires` et `heberge_par`. La
     chaîne de confiance est donc : clé de racine épinglée → racine vérifiée →
     identité de l'annuaire local qu'elle nomme ;
   - le **pair** d'une racine : `--peer-key`, qui existe depuis 0.7.0.
5. **Le DNS reste permis — comme locateur.** `asl-root.air-desktop.org`,
   `nitrogen.air-desktop.org`, `speedy.air-desktop.org` sont des commodités ;
   aucune n'entre dans la décision de croire, et l'absence de résolveur ne
   bloque rien : les locateurs embarqués sont des adresses.

### Pourquoi un certificat auto-signé, et pas des clés brutes (RFC 7250)

RFC 7250 ferait voyager la clé seule, sans enveloppe X.509 — c'est ce qu'on
veut dire. **La pile ne le porte pas** : ni `ams-tls` ni `ams-quic-tls` ne
négocient `server_certificate_type` (vérifié le 2026-09-27 dans
`air-mail-server` à `6f0ea51`), et C15 interdit de réécrire la pile. Un
certificat auto-signé, lui, passe partout où un certificat passe : même
`ServerConfig` (`ams_tls::quic_server_config` accepte une chaîne d'un seul
certificat Ed25519 — les racines présentent déjà de l'Ed25519), même
`ClientConfig`, et **un vérificateur propre à ASL** branché par
`rustls::ClientConfig::…dangerous().with_custom_certificate_verifier(…)` —
ASL construit déjà lui-même ses configurations clientes (`configuration_tls`
dans `asl-client-tokio` et dans le tireur d'`asl-loop-tokio`), et
`ams_quic_tls::Connection::connect` prend un `Arc<ClientConfig>`. C'est ce
qu'`air-mail-server` fait déjà pour DANE (`ams_tls::relay::dane_config`, le
vérificateur `Dane`) : une ancre qui n'est pas une autorité, sans toucher à la
pile. L'enveloppe X.509 n'est qu'un emballage que le vérificateur ouvre pour
lire la clé.

### Ce que ça règle, et ce que ça ne règle pas

- **Plus d'autorité TLS à tenir**, ni pour les racines ni pour les maisons.
  Plus de certificat à renouveler : la validité n'est pas jugée (décision 54).
- **L'issue 3 de §2 (renumérotation) devient naturelle.** Ce qui est épinglé
  est la clé : une racine qui change d'hébergeur publie ses nouveaux locateurs,
  et le client qui l'a jointe une fois par l'ancien les apprend sur une
  connexion déjà vérifiée par clé (décision 56, proposé). Les issues 1
  (allocation à nous) et 2 (ancrer sur les noms) ne sont plus nécessaires ; la
  première reste un confort, la seconde est abandonnée.
- **Un annuaire local change d'adresse sans rien redéclarer** : il publie
  lui-même ses locateurs sur sa voie (décision 57, proposé), et le `421` suit.
- **La preuve de possession à la couche HTTP ne disparaît pas.** Les défis
  (`POST /v1/defi`, genre `n`, `POST /v1/pair/preuve`) prouvent déjà l'identité
  au-dessus de TLS ; TLS la prouve maintenant AUSSI au-dessous. Les deux
  restent : le défi lie la preuve au canal (`protocole.md` §2.1 bis), et un
  client qui n'attendrait qu'un annuaire sans savoir lequel (un premier
  contact par locateur) garde la preuve HTTP comme juge.
- **Hors du cœur, des dépendances au DNS restent, et sont nommées** (C20) :
  les réveils UnifiedPush vers `ntfy.sh` (périphérie : une notification
  manquée se rattrape à la relecture), le téléchargement des applications, et
  tout nom qu'un utilisateur choisit de publier. Ce qui ne doit JAMAIS en
  dépendre : joindre une racine, la croire, s'enrôler, s'annoncer, résoudre,
  fédérer.

---

## 3. Ce qui se synchronise ENTRE LES RACINES, et ce qui ne s'y synchronise pas

**C'est la décision qui rend tout le reste tenable.** Elle porte ici sur les deux
racines, qui ont la même autorité ; la réplication entre pairs de confiance est
sélective et relève du §5.

| | Se synchronise ? |
|---|---|
| Comptes, alias publics, clés publiques des appareils | Oui |
| Descriptions d'appareils, points de poussée, révocations | Oui |
| Machines, leurs capacités, leur clé publique | Oui |
| **Codes d'enrôlement en attente** | Oui |
| Services **déclarés** (nom, machine, propriétaire) | Oui |
| Autorisations accordées, et leurs révocations | Oui |
| **Le bail — la connexion tenue, l'état `annoncé`** | **NON** |
| **La joignabilité mesurée, les candidats d'adresse** | **NON** |
| **Le journal** | **NON** |
| **Domaines, leurs alias, leur hébergeur ; le rattachement des machines ; les groupes, leurs membres, les droits** (2026-09-26) | Oui |
| **Inscriptions d'annuaires locaux, leurs décisions** (2026-09-26) | Oui |
| **L'état vivant des services fédérés** — adresse, port, vivant (§5.4) | **NON** entre racines : chaque racine le reçoit **de l'annuaire local**, qui les tient toutes les deux |

**Le COMMENT a son propre document : [`replication.md`](replication.md)** — le
transport, les deux racines qui écrivent et la règle de conflit, l'horloge, le
rattrapage, ce que le client voit pendant la propagation, et ce que chaque
contrainte devient. Ce tableau y est repris ligne à ligne, avec la raison de
chaque ligne.

### Pourquoi l'état vivant ne se réplique pas

Un daemon tient une connexion QUIC vers *un* annuaire, avec un keepalive à
quelques dizaines de secondes (`modele.md` §4.1). Répliquer cet état, c'est
répliquer un flux qui change en permanence, pour une information qui est fausse
dès qu'elle arrive.

**Et c'est inutile, parce que l'état se reconstruit tout seul.** Si l'annuaire
qui portait la connexion tombe, le daemon se reconnecte — à l'autre racine — et
réannonce. Au bout d'un keepalive, l'état est reconstitué, sans qu'une ligne de
protocole de réplication ait servi.

**La reprise que le client fait déjà EST le mécanisme de bascule.** Il n'y en a
pas d'autre à écrire, et c'est ce qui rend la haute disponibilité abordable
ici : ce qui est cher à répliquer est justement ce qui n'a pas besoin de l'être.

Ce que cela coûte, et qui se dit : **pendant la reconnexion, le service apparaît
`parti`.** Une bascule d'annuaire produit donc une fausse alerte de quelques
secondes. C'est le prix, il est borné, et il est préférable à un état répliqué
qui serait faux plus longtemps sans que rien ne le signale.

---

## 2 ter. À qui appartient un annuaire local, et sa paire de secours

**Décidé le 2026-09-27 (Thierry ; `replication.md` décisions 48 et 49).**

**Un annuaire local appartient à UN compte, et n'héberge que les domaines de ce
compte — de un à n.** Jamais le domaine d'un autre : l'inscription lie le
compte à l'annuaire (§4.1), et confier un domaine (`PUT /v1/domaines/{d}/hebergeur`)
n'est permis qu'à son propriétaire, vers un annuaire que ce même compte a fait
inscrire. Un domaine qu'un autre compte administre — son groupe
d'administrateurs, un droit reçu — ne se confie pas pour autant à l'annuaire de
cet administrateur : l'hébergement suit la propriété, pas la gestion. Le cas
réel qui a fixé la règle : le domaine « air-desktop-dictator » de Thierry,
hébergé chez lui. Que ce compte soit aussi le propriétaire des racines n'y
change rien — le code ne connaît aucun compte, et le domaine racine n'est
hébergé par aucun annuaire local (§2 bis).

**Un annuaire local peut être tenu par DEUX machines — une paire de secours.**
Le même mécanisme qu'entre nitrogen et argon (`replication.md` §2) : chacune a
**sa** clé d'identité et son `n-…`, chacune nomme l'autre par `--peer` et
`--peer-key`, et elles se répliquent tout ce que l'annuaire local écrit — les
services déclarés de ses domaines. Le cas réel : speedy tient l'annuaire du
domaine « air-desktop-dictator », helium le seconde.

**Aux racines, la paire est UN SEUL annuaire local, à deux membres** (décision
49, et c'est l'objet qui a été tranché) :

| | Ce que c'est | Pourquoi |
|---|---|---|
| **L'annuaire** | Une inscription, **nommée par le `n-…` de son premier membre** — le titulaire. C'est ce `n-…` que `heberge_par` porte, que `GET /v1/annuaires` rend, que `DELETE /v1/annuaires/{n}` retire. | Un nom de plus (un genre d'identifiant pour « l'annuaire logique ») n'apporterait rien que le titulaire ne donne déjà, et les verbes de la spec nomment déjà l'annuaire par un `n-…`. |
| **Ses membres** | Un ou deux `n-…` : le titulaire, et au plus un second. Chacun est **approuvé à son tour** par un administrateur des racines. | Une clé de plus est un annuaire de plus qui parle pour les mêmes domaines : ce que les racines servent en son nom, elles doivent pouvoir le refuser (décision 32). Le propriétaire est de confiance pour ses domaines ; une clé qu'on n'a pas vue ne l'est pas. |
| **Remplacer une machine** | La clé d'identité est un fichier : la machine qui remplace le titulaire **reprend son fichier**, et garde son `n-…`. Retirer le second membre et en inscrire un autre se fait sans toucher au titulaire. | L'identité est la clé, pas la machine — comme pour une racine. Perdre le fichier du titulaire, c'est perdre l'annuaire : ses domaines se rendent aux racines et une nouvelle inscription recommence (§7). |

**Chaque membre ouvre SA voie vers chaque racine** (`protocole.md` §3 ter), et
reporte les services que **lui** voit — un daemon s'annonce à l'un des deux, pas
aux deux. Les racines tiennent l'état de chaque service **par membre**, en
mémoire (§5.4) ; **décidé** (2026-09-27, Thierry ; décision 52) : un service est vivant tant qu'au moins un membre
le dit vivant, et son adresse et son port sont ceux du dernier rapport vivant
reçu **par cette racine** — l'état vivant ne se réplique pas entre racines, et
chacune tranche avec ce qu'elle reçoit. Un membre qui se tait ne fait tomber
que ce que lui seul disait.

## 4. S'enregistrer, puis se faire connaître

**Deux étapes distinctes, et la première ne donne accès à rien.**

### 4.1 L'enregistrement auprès d'une racine

~~1. Une entreprise ou un particulier **déploie son annuaire**.~~
~~2. Il **s'enregistre auprès d'au moins une racine** — les deux adresses IPv6
   sont dans le code, les deux clés publiques aussi (§2).~~
~~3. La racine le recense : identifiant, clé publique, comment le joindre.~~

~~C'est tout. **Aucune donnée n'est échangée, aucune confiance n'est accordée.**
S'enregistrer, c'est figurer dans un annuaire d'annuaires.~~

**Renversé le 2026-09-26 pour l'annuaire local (Thierry ; `replication.md`
décision 32) — l'inscription est APPROUVÉE.** Ce qui était écrit supposait un
annuaire qui ne demandait aux racines que d'être recensé ; l'annuaire local leur
demande de **servir l'état de ses services** (§5.4). La marche devient :

1. L'utilisateur **déploie son annuaire local** et lui fait frapper sa clé
   d'identité (`asl-server --new-identity-key`, comme une racine) — son `n-…`
   s'en déduit (`modele.md` §2.7).
2. Depuis l'application, il **déclare** cet annuaire à son compte ; l'annuaire
   se présente aux racines avec sa clé et le code que l'application lui a
   donné — le geste de l'enrôlement d'une machine (`protocole.md` §2.2,
   décidé le 2026-09-26, Thierry).
3. L'inscription est **en attente**. **Un administrateur des racines l'accepte
   ou la refuse** (`modele.md` §2.12), depuis son application ; un seul
   suffit.
4. Acceptée, l'annuaire peut **héberger** les domaines de son propriétaire —
   que celui-ci lui confie un par un depuis l'application — et la voie de §5.4
   s'ouvre.
5. **Pour une paire** (§2 ter) : le propriétaire déclare un second membre à
   l'annuaire accepté (`POST /v1/annuaires/{n}/membres`), obtient un second
   code, que la seconde machine présente avec **sa** clé ; ce membre-là est en
   attente à son tour, et un administrateur l'accepte ou le refuse comme le
   premier.

**Retirer une inscription** — par son propriétaire, par un administrateur, ou
par l'effacement du compte — ferme la voie ; ses domaines reviennent aux
racines, et leurs daemons, qui s'annonçaient chez lui, apparaissent `parti`
jusqu'à ce qu'ils s'annoncent aux racines (§7). Un retrait est une révocation :
il gagne toujours (`replication.md` §3.2).

Pour un annuaire `ordinaire` — qui ferait autorité sur des comptes —, le
recensement libre de l'ancien texte reste la proposition (§8).

**Une seule racine suffit** — les deux se répliquent (§1). S'enregistrer auprès
des deux ne fait qu'accélérer la propagation.

### 4.2 L'entremise

Un administrateur qui veut parler à un autre annuaire le trouve par la racine,
et lui fait porter la demande. **La racine transporte, elle ne tranche pas.**

C'est ce qui la rend utile sans la rendre centrale : sans elle, deux
administrateurs devraient s'échanger clés et adresses hors bande, et un réseau
qui exige un canal hors bande pour chaque nouvelle relation ne grandit pas.

### 4.3 La relation de confiance

**Ce sont les DEUX administrateurs qui l'acceptent**, et personne d'autre. Le
propriétaire des racines n'arbitre rien.

Une fois la relation établie, **chaque administrateur décide de ce qu'il veut
voir se répliquer chez lui** (§5). La relation n'est pas symétrique : X peut
tout prendre de Y sans que Y prenne quoi que ce soit de X.

### 4.4 Rompre une relation

**Un administrateur d'annuaire décide seul de rompre.** Il n'a besoin de
l'accord de personne, et surtout pas du pair qu'il coupe.

**Quand la relation est rompue, TOUT enregistrement dont l'origine est cette
relation disparaît.** Pas suspendu, pas marqué : effacé.

**Une seule exception : le JOURNAL** ([`journal.md`](journal.md) §5 bis). Ce qui
motive une rupture est souvent ce que le journal a enregistré ; l'effacer en
rompant détruirait la preuve au moment où l'on s'en sert. L'exception est bornée
par la rétention — quatre-vingt-dix jours — donc elle dure le temps d'une
enquête, pas le temps d'une archive.

Cela exige que **chaque enregistrement répliqué porte son ORIGINE** — la relation
par laquelle il est entré. C'est un champ du modèle, pas une commodité
d'implémentation, et c'est ce qui rend la rupture complète plutôt
qu'approximative : on n'a pas à deviner ce qui venait de qui, on le sait.

#### Ce que cette règle règle d'un coup

**Le cas de la clé compromise.** Si la clé d'un pair est volée, tout ce qu'il a
jamais affirmé devient suspect. Avec une révocation par origine, on n'a rien à
trier : on rompt, et tout ce qui venait de lui s'en va. Il n'y a pas de « valide
avant telle date, forgé après » à départager.

**C'EST PLUS SIMPLE QUE CE QUI ÉTAIT ENVISAGÉ ICI, et il faut le dire** : une
version antérieure de ce document réclamait des assertions horodatées et une
révocation à date d'effet, pour pouvoir garder le passé légitime. Effacer par
origine rend cette machinerie inutile.

#### L'horodatage reste nécessaire, mais pour autre chose

Pas pour révoquer — pour **empêcher le rejeu à l'intérieur d'une relation
vivante**. Sans marqueur monotone, une assertion signée et capturée peut être
rejouée plus tard et ressusciter un enregistrement qu'on avait retiré. Il faut
donc un numéro de séquence ou un horodatage **par relation**, et le récepteur
refuse ce qui recule.

C'est une exigence du flux de synchronisation, pas du modèle de confiance. Elle
est plus faible que celle qu'on croyait avoir, et elle est réelle.

#### Pas de cascade, et C11 l'explique déjà

Si Y a répliqué des enregistrements de X, Y peut-il les ré-exporter vers Z — et
une rupture X↔Y doit-elle alors cascader jusqu'à Z ?

**Non, et la question ne se pose même pas** : C11 interdit déjà d'accepter d'un
pair ce dont il n'est pas l'autorité. Y n'est pas l'autorité des comptes de X, et
ne peut donc rien en dire à Z. **Il n'y a pas de réplication transitive, donc pas
de cascade.**

#### La limite honnête

Rompre **arrête le flux ; cela n'efface rien chez le pair**. On applique la règle
chez soi, il l'applique chez lui — et s'il ne l'applique pas, on n'a aucun moyen
de le savoir.

Ce que d'autres ont appris, ils l'ont appris. C'est une raison de plus de ne
répliquer que ce qu'on a délibérément choisi de répliquer : moins on distribue,
moins on a à regretter.

#### Ce que l'utilisateur voit

L'effacement est complet, donc **une machine de B qui résolvait un service d'A ne
trouve plus rien** — et l'application ne pourrait rien expliquer, puisque
l'enregistrement a disparu.

**La relation elle-même laisse donc une trace** : « relation avec l'annuaire X
rompue le … ». Pas les données, juste le fait. Sans cela, un accès disparaît sans
raison lisible, et personne ne saura jamais s'il s'agit d'une rupture ou d'une
panne.

---

## 5. La réplication sélective

### 5.1 Ce sur quoi la sélection porte

La possession est une chaîne, et la sélection la suit :

```
utilisateur  ──possède──▶  machines  ──possèdent──▶  services
```

Un administrateur souscrit **à un niveau de cet arbre**, et tire ce qui pend en
dessous :

| Ce qu'il choisit | Ce qu'il obtient |
|---|---|
| Tout l'annuaire distant | Tous les utilisateurs, donc toutes leurs machines et tous leurs services |
| Quelques utilisateurs | Leurs machines et leurs services |
| Quelques machines de quelques utilisateurs | Ces machines et leurs services seulement |

**La sélection ne descend jamais sous la machine.** On ne souscrit pas à « trois
services d'une machine » : les services d'une machine vont et viennent, un daemon
peut en déclarer un nouveau à tout moment, et une souscription qui prétendrait les
filtrer serait fausse dès le premier démarrage. La machine est la plus petite
unité stable.

### 5.2 Les deux côtés : l'administrateur expose, l'utilisateur retire

**Il y a deux côtés, et ils appartiennent à deux personnes différentes.**

| | Qui décide | Ce qu'il décide |
|---|---|---|
| **Exposer** | L'administrateur de l'annuaire qui donne | Ce qu'il rend disponible à un pair donné |
| **Prendre** | L'administrateur de l'annuaire qui reçoit | Ce qu'il souscrit parmi ce qui est exposé |
| **Retirer** | **L'utilisateur** | Ses propres enregistrements, hors d'une exposition |

**L'utilisateur voit ce qui est exposé de lui, par relation, et peut le
retirer.** Le retrait suit la même chaîne que la sélection : tout son compte, ou
telle de ses machines.

#### Pourquoi ce partage plutôt qu'un autre

Deux positions plus simples étaient possibles, et chacune casse quelque chose.

**« L'administrateur décide seul »** se défend en entreprise, où les machines
appartiennent à l'entreprise. Mais les racines hébergent des particuliers, et
`modele.md` affirme qu'un utilisateur POSSÈDE ses machines. Un administrateur qui
livrerait la liste des machines de tous ses utilisateurs sans qu'aucun le sache
traiterait cette possession comme une fiction.

**« L'utilisateur consent d'abord »** respecte la possession, et rend le produit
inutilisable en entreprise : chaque nouvelle relation exigerait de réunir des
centaines d'accords avant que quoi que ce soit circule.

**Le partage retenu tranche autrement : rien ne bloque, mais rien n'est
invisible.**

#### CE QUE CELA COÛTE, ET IL FAUT LE DIRE ICI

**C'est un retrait, pas un consentement.** L'exposition prend effet quand
l'administrateur la décide ; le retrait, quand l'utilisateur le décide. **Entre
les deux, les données ont circulé.**

Il y a donc une fenêtre — celle qui sépare l'exposition du moment où l'utilisateur
regarde — pendant laquelle un pair a reçu, et gardé, ce qu'il a reçu. **Retirer
arrête le flux et demande l'effacement ; cela ne défait pas ce qui a déjà été
copié.** C'est exactement la limite énoncée pour la rupture (§4.4), et elle vaut
ici pour la même raison.

**Ce qui réduit cette fenêtre, et devrait être fait :** notifier l'utilisateur
quand une exposition nouvelle le couvre. La machinerie existe déjà — c'est celle
qui l'avertit d'une autorisation reçue (`modele.md` §2.6). Sans elle, « voir »
suppose qu'il pense à regarder, et un droit de retrait qu'on ignore n'en est pas
un.

#### Le retrait est une rupture partielle

Techniquement, il fait la même chose que §4.4, sur un sous-ensemble : le pair
doit effacer les enregistrements concernés. Le flux de synchronisation porte donc
un **retrait** aussi bien qu'un ajout, et le récepteur l'applique comme il
applique une rupture.

**On ne peut pas l'y forcer.** On cesse d'affirmer, on demande l'effacement, et un
pair qui n'obéirait pas ne se distinguerait de rien. Une raison de plus de
n'exposer que ce qu'on a délibérément choisi d'exposer.

### 5.3 L'état vivant ne traverse PAS la fédération — l'hybride

**Renversé le 2026-09-26 pour l'annuaire local — voir §5.4.** Ce qui suit reste
le raisonnement pour des annuaires `ordinaires` qui feraient autorité sur des
comptes (§8) ; il ne décrit plus la v1.

~~**Décidé.**~~ On réplique l'arbre durable ; l'état vivant se demande à l'annuaire
d'autorité au moment de résoudre.

| | |
|---|---|
| **La souscription dit** | ce qui existe, et qui y a droit |
| **La résolution dit** | où c'est, maintenant |

**Pourquoi.** Répliquer un port qui change à chaque redémarrage de daemon, c'est
distribuer une information fausse dès qu'elle arrive — l'argument exact du §3, et
il ne devient pas meilleur en franchissant une frontière d'annuaire. Il empire :
la donnée traverse un lien plus lent, entre deux autorités distinctes.

#### Ce que cela coûte, nommé

**Si l'annuaire d'autorité est tombé, la résolution échoue.** Un pair ne peut pas
répondre à sa place.

Mais la perte est plus petite qu'il n'y paraît, pour deux raisons :

- Si l'annuaire d'A est tombé, **les daemons d'A n'y sont plus connectés** : leurs
  baux sont tombés avec. Il n'y avait rien de juste à répondre.
- **L'arbre durable est répliqué, lui.** L'annuaire de B sait donc que le service
  EXISTE et que B y a droit — il peut répondre « annuaire d'autorité injoignable »
  au lieu de « service inconnu ». **Ces deux réponses n'appellent pas le même
  geste** de la part de celui qui les lit, et les confondre enverrait un
  administrateur chercher une faute de configuration là où il y a une panne
  distante.

#### Et cela décide qui détient le graphe d'usage

Toutes les requêtes sont journalisées ([`journal.md`](journal.md)). Celui qui sert
la résolution est celui qui accumule l'historique : **avec l'hybride, c'est
l'annuaire du propriétaire du SERVICE**, pas celui du demandeur.

A voit donc qui consulte ses services — ce qui est cohérent avec le fait que son
propre daemon verra la connexion. Et **l'annuaire de B n'accumule rien** sur ce
que B va chercher ailleurs, ce qui est le meilleur des deux côtés.

#### Une optimisation nommée et repoussée

Les annuaires pairs pourraient tenir une connexion QUIC entre eux, et l'annuaire
d'autorité **pousser** les changements de candidats pour les services auxquels un
pair a des abonnés. On aurait la fraîcheur sans la dépendance à la résolution.

Ce n'est pas de la v1 : cela suppose de savoir qui s'intéresse à quoi, donc de
tenir un état de plus — et cet état-là, lui, dirait à A quels de ses services
intéressent qui, en permanence.

### 5.4 L'état vivant des domaines hébergés TRAVERSE les racines

**Décidé le 2026-09-26 (Thierry ; `replication.md` décision 34).** L'annuaire
local transmet aux racines, pour chaque service des machines rattachées à ses
domaines : **l'identifiant du service, l'adresse IP de la machine, le port de
connexion, et s'il est vivant ou non.** Les racines le **servent aux clients**
qui les interrogent — pas aux autres annuaires locaux —, et **seulement aux
comptes à qui un accès a été accordé** : la règle de `GET /v1/ou` aujourd'hui,
inchangée (C10).

**Pourquoi on renverse §5.3.** L'hybride supposait que le client joigne
l'annuaire d'autorité au moment de résoudre. **Un annuaire à la maison est
souvent injoignable de l'extérieur** — derrière un NAT, un CGNAT, une box qui
redémarre, une coupure de courant —, et le téléphone ou la machine d'un ami qui
cherche un service n'est pas chez lui. Les applications ne parlent qu'aux
racines, qui sont joignables ; c'est donc aux racines d'avoir la réponse.
L'annuaire local, lui, joint toujours les racines : c'est **lui qui ouvre la
connexion**, comme un daemon, et un NAT laisse sortir.

**Ce que cela coûte, nommé.**

- **Les racines apprennent l'adresse, le port et l'état de TOUS les services
  fédérés** — ce que §5.3 voulait éviter. C'est un amendement de C13
  (`contraintes.md`) : ces données vivent **en mémoire, comme un bail**, jamais
  dans l'entrepôt, ne se répliquent pas entre racines (§3), et tombent quand la
  voie de l'annuaire local tombe.
- **Le graphe d'usage passe aux racines** pour ces services : c'est elles qui
  résolvent, donc elles qui journalisent (`journal.md`, C18), et non plus
  l'annuaire du propriétaire.
- **Ce qu'un annuaire local affirme, les racines le répètent.** D'où
  l'approbation (§4.1), et C11 dans sa forme nouvelle (§2 bis) : il n'est cru
  que sur les machines de ses domaines.
- **L'adresse est celle que l'annuaire local voit.** Sur IPv6, c'est l'adresse
  globale de la machine, joignable. **Sur IPv4 derrière un NAT, c'est une
  adresse privée**, qui ne dit rien à qui est dehors : le problème de la
  traversée reste celui de `modele.md` §6.3, et il n'est pas résolu ici (§7).

**Comment ça circule** (décidé le 2026-09-26, Thierry, `protocole.md` §3 ter) : la
connexion de l'annuaire local vers **chaque** racine, authentifiée par sa clé
d'identité comme entre racines ; dans un sens, les machines de ses domaines et
leurs révocations ; dans l'autre, ses services et leur état. Chaque racine le
reçoit directement : il n'y a rien à répliquer entre elles, et rien d'observé
ne passe par la voie entre racines (`replication.md` §1).

---

## 6. Les deux racines et le témoin

**Deux répliques n'ont pas de majorité.** Un consensus par quorum exige plus de
la moitié des votants : à deux, cela fait deux, et la panne d'une seule bloque
toute écriture. On obtiendrait exactement ce qu'on voulait éviter — un point de
panne unique, avec deux machines au lieu d'une.

**La solution est un TÉMOIN : un troisième votant qui ne porte aucune donnée.**

| | |
|---|---|
| Ce qu'il fait | Il vote. Rien d'autre. |
| Ce qu'il détient | Rien — ni comptes, ni machines, ni services, ni baux. |
| Ce qu'il coûte | Presque rien : ni disque, ni bande passante. |
| Ce qu'il apporte | Une majorité de deux sur trois, donc **une panne tolérée** et une bascule automatique sans risque de double primaire. |

Les deux racines restent les **seules porteuses de données**, ce qui préserve
l'intention : elles sont deux, pas trois.

**Le témoin doit être indépendant**, et c'est la seule exigence qui compte à son
sujet : autre machine, autre hébergeur, autre chemin réseau. Un témoin qui tombe
en même temps que la racine qu'il devait départager n'arbitre rien — il ajoute
une pièce sans ajouter de garantie.

### L'enjeu est bien plus faible qu'il n'y paraît

Ce n'est pas une conception distribuée à mener de bout en bout, et c'est le
découpage du §3 qui le réduit :

| Ce qui s'écrit | Fréquence | Demande un ordre ? |
|---|---|---|
| Créer un compte, déclarer une machine, accorder, nouer une relation | Rare, déclenché par un humain | **Oui** |
| Annonces, baux, joignabilité | En permanence | **Non** — local à chaque racine, non répliqué |

**Le chemin chaud ne passe pas par le quorum du tout.** Un daemon reconnecté sur
la seconde racine y annonce, et cette écriture n'a à être ordonnée avec rien. Le
quorum ne sert qu'à des écritures rares et humaines — ce qui rend son coût
négligeable et sa latence sans importance.

### Le témoin n'est PAS la v1 — c'est une suite nommée

**[`replication.md`](replication.md) §3.4 s'en passe, et dit pourquoi** : les
écritures rares n'ont pas besoin d'un ordre — un identifiant à 128 bits les
rend indépendantes —, et les seules qui touchent une unicité (l'alias, le
couple `(machine, nom)`, la clé d'une machine) reçoivent un PERDANT plutôt
qu'une attente, par une règle que les deux racines calculent pareil. Ce que le
témoin achèterait est qu'un `204` sur un alias soit définitif à la seconde ; ce
qu'il coûterait est une racine seule qui ne crée plus de compte. Le tableau
ci-dessus reste juste sur ce qui demande un ordre ; ce qui a changé est qu'on
le DÉPARTAGE au lieu de l'attendre. Le témoin redevient la réponse le jour où
une unicité devra être garantie plutôt que départagée. **Proposé, à
confirmer** (`replication.md` §10).

---

## 7. Ce qui n'est pas décidé

Rassemblé, plutôt que dispersé.

1. **L'index des annuaires est-il énumérable ?** Les racines recensent tous les
   annuaires. Peut-on en demander la liste, ou seulement en résoudre un dont on
   connaît l'identifiant ? C'est la même question que celle de l'alias
   (`modele.md` §2.1), à l'échelle des annuaires.
2. **Les racines sont-elles joignables en IPv4 ?** Deux adresses IPv6 dans le
   code excluent un annuaire sur un réseau IPv4 (§2).
3. **Le transport de la synchronisation.** ~~QUIC comme le reste,
   probablement.~~ **Fermé entre les racines** ([`replication.md`](replication.md)
   §2) : HTTP/3 sur QUIC, sur le même port, deux connexions dont chacune est
   ouverte par la racine qui tire, authentifiées par les clés d'identité des
   deux. Reste ouvert entre pairs de confiance (§5), où l'autorité diffère et
   où la sélection s'ajoute au flux.
4. **La migration d'un compte d'un annuaire à un autre.**
5. **L'utilisateur est-il notifié d'une exposition nouvelle qui le couvre ?**
   (§5.2) — proposé, parce qu'un droit de retrait qu'on ignore n'en est pas un.
6. **Le passage d'un domaine des racines vers un annuaire local, et retour**
   (2026-09-26). Pendant la bascule, les daemons s'annoncent encore à
   l'ancien hébergeur : ils apparaissent `parti` jusqu'à ce qu'ils se
   ré-annoncent au nouveau. **Décidé (2026-09-27, Thierry), codé en 0.28.0** : une racine qui reçoit
   l'annonce d'une machine dont le domaine est confié à un annuaire local la
   **refuse en `421`** (« mauvais destinataire », RFC 9110) en donnant
   l'adresse déclarée de l'annuaire ; le daemon la suit, comme une redirection.
   Au retour aux racines, l'annuaire local ferme ses sessions de ce domaine, et
   les daemons se retournent vers les racines par leur tournée ordinaire.
7. **Ce qui se passe quand l'annuaire local disparaît** — éteint, cassé,
   jamais revenu. Ses services apparaissent `parti` dès que sa voie tombe ; au
   bout de combien de temps ses domaines reviennent-ils d'eux-mêmes aux
   racines, et le faut-il ? **Décidé (2026-09-27, Thierry)** : ce qu'un membre
   rapportait tombe **quand sa voie tombe** — au plus l'inactivité de la
   connexion, trente secondes, comme un bail (`modele.md` §4.1) ; avec une
   paire, seulement ce que ce membre-là était seul à dire. **Les domaines ne
   reviennent pas d'eux-mêmes** : c'est au propriétaire de les rendre
   (`DELETE /v1/domaines/{d}/hebergeur`) ; une panne longue n'est pas une
   décision, et un domaine qui changerait d'hébergeur tout seul ferait
   basculer ses daemons sans que personne l'ait voulu.
8. ~~**La latence acceptable de « vivant »** propagé par un annuaire local~~
   — **tranchée par le code (0.28.0, décision 52)** : un daemon qui s'en va
   se dit à la racine dans le tour, parce que l'annuaire local pousse tout
   changement tout de suite ; un annuaire local qui se TAIT fait tomber ce
   qu'il disait au bout de l'expiration d'un rapport, trente secondes. Reste
   le cas du daemon muet sans fermer : c'est le bail entre lui et l'annuaire
   local (`modele.md` §4.1), trente secondes de plus au pire.
9. **IPv4 derrière un NAT** (§5.4) : l'adresse qu'un annuaire local transmet
   n'est joignable que si la traversée est résolue (`modele.md` §6.3).
   **Précisé (2026-09-27)** : la voie entre l'annuaire local et les racines
   **n'exige aucun port entrant** — c'est l'annuaire qui ouvre. Un port entrant
   (UDP 6630 sur la box, en IPv6 vers l'adresse publique de chaque membre)
   n'est nécessaire que pour les daemons de ses domaines qui sont **hors de la
   maison** : ce sont eux qui doivent joindre l'annuaire. **Décidé (2026-09-27, Thierry)** :
   l'adresse que le propriétaire déclare (`POST /v1/annuaires`) est celle que
   ces daemons emploient ; les racines ne s'en servent que pour la dire (le
   `421` de la question 6).
10. **Le certificat de l'annuaire local.** **Renversé le 2026-09-27 (Thierry,
    décision 53)** : il est **auto-signé par la clé d'identité `n-…` du membre**,
    et les daemons l'attendent par cet identifiant, que le `421` leur donne
    (§2 quater). Ce qui était décidé le matin même, et pourquoi on en change :
    une autorité propre au propriétaire, un fichier frappé une fois chez lui,
    épinglée par `--roots` — mais elle exigeait un NOM dans chaque certificat,
    donc un DNS, et « ASL doit pouvoir fonctionner SANS DNS ». L'argument
    « pas la clé `n-…`, qui ne tourne pas » tombe avec le modèle : la clé qui
    ne tourne pas est justement ce qu'on veut épingler.
    ~~**Le certificat de l'annuaire local.** Les daemons de la maison le
    joignent en TLS : sous quelle autorité, et comment ils l'épinglent — sans
    appeler de tiers (C19). **Décidé (2026-09-27, Thierry)** : une **autorité propre au
    propriétaire**, un fichier qu'il frappe une fois chez lui, qui signe le
    certificat de chaque membre (le même nom pour les deux, pour qu'un daemon
    bascule de l'un à l'autre sans rien changer) et que ses daemons épinglent
    par `--roots`, comme ils épinglent aujourd'hui celle des racines. **Pas
    l'autorité des racines** : elles frapperaient des certificats pour les
    maisons de tout le monde, ce qui ferait d'elles l'autorité de noms
    qu'elles ne tiennent pas. Et **pas la clé `n-…`** : elle prouve l'annuaire
    aux racines, elle ne tourne pas, et la garder distincte du TLS est la règle
    des racines (`modele.md` §2.7).~~
13. **Le paquet pour les deux architectures.** Un membre peut être un PC ou
    un Raspberry Pi — helium est `aarch64`, sous Ubuntu 26.04. **Le paquet
    `asl-server` doit exister en `amd64` ET en `arm64`** avant qu'une paire
    se déploie ; rien dans le code ne l'empêche (C4 : pas une ligne de C), mais
    `scripts/paquet.sh` ne fabrique aujourd'hui que le premier.
11. ~~**Les groupes généraux.**~~ **Décidé le 2026-09-26** : dès la v1, avec
    les droits (`modele.md` §2.12, §2.13). Restent ouverts les droits
    négatifs, l'imbrication des groupes et leurs bornes (`modele.md` §6).
12. **Ce qu'un annuaire local sait des droits.** Il ne résout rien : c'est aux
    racines que `GET /v1/ou` se pose, et ce sont elles qui tiennent les
    groupes et les droits. S'il devait un jour répondre lui-même aux machines
    de la maison — sans passer par les racines —, il lui faudrait les droits
    qui visent ses domaines, et il ne les reçoit pas.

## 8. L'annuaire `ordinaire` et la confiance bilatérale — une suite nommée

**Depuis le 2026-09-26, la fédération de la v1 est celle de l'annuaire local**
(§2 bis, §4.1, §5.4) : il fait autorité sur des DOMAINES, pas sur des comptes ;
ses comptes restent aux racines ; il ne parle qu'aux racines.

Ce que ce document décrivait d'autre — un annuaire **`ordinaire`** où l'on crée
des comptes, qui fait autorité sur eux, qui se relie à d'autres par une
**confiance bilatérale** (§4.2–§4.4) et choisit ce qu'il réplique d'eux (§5.1–
§5.3) — **n'est pas contredit, et n'est pas la v1.** C'est la forme qu'une
entreprise voudrait peut-être, avec ses propres comptes ; elle reste écrite
ci-dessus, avec ses raisons, pour le jour où ce besoin se présentera. Les deux
formes sont compatibles : un annuaire `ordinaire` n'est pas un annuaire
local, et C11 les tient chacun à son périmètre.

