# La réplication entre les deux racines

`annuaires.md` §3 dit CE QUI se synchronise entre `nitrogen` et `argon`, et
§7 laissait le COMMENT ouvert. Ce document le ferme.

**Pourquoi maintenant.** L'alias `asl-root.air-desktop.org` a été posé le
2026-09-15, et `asl` fait tourner les deux adresses qu'il rend. C'est là que ça
s'est vu : un compte créé chez `nitrogen` n'existait pas chez `argon`, et une
requête sur deux tombait en `401`. `annuaires.md` promettait deux racines qui se
répliquent ; il y en avait deux qui s'ignoraient. En attendant, l'alias ne
pointe que sur `nitrogen`, et `argon` ne reçoit aucun trafic — ce qui est
exactement le point de panne unique que la seconde racine existait pour éviter.

**Ce document est une spécification, pas un compte rendu.** Rien n'est codé.
Chaque point porte une décision, sa raison, et ce qu'elle coûte ; la table de
§10 dit lesquelles sont tranchées et lesquelles attendent une confirmation.

---

## 1. Le périmètre — ce qui se réplique, à la ligne

Le principe qui tient tout le tableau : **une racine réplique ce qu'elle a
ÉCRIT sur demande d'un humain ou d'une machine, et rien de ce qu'elle
OBSERVE.** Ce qu'elle observe — une connexion tenue, une sonde qui aboutit, une
adresse vue — se reconstruit tout seul à la reconnexion (`annuaires.md` §3), et
serait faux dès son arrivée chez l'autre.

| | Se réplique ? | Pourquoi |
|---|---|---|
| Comptes | **Oui** | Un compte se crée sur l'une ou l'autre selon le tirage de l'alias ; il doit exister sur les deux. |
| Alias publics | **Oui** | Un alias est une promesse d'unicité ; deux racines qui ne se les diraient pas la tiendraient chacune de son côté, c'est-à-dire pas du tout (§3). |
| Appareils — clé publique, attestation, révocation | **Oui** | C'est l'appareil qui signe (`modele.md` §2.2) ; une racine qui ne connaît pas la clé refuse tout. |
| Descriptions d'appareils, jetons de poussée | **Oui** | Une autorisation accordée chez l'une notifie les appareils du bénéficiaire ; le jeton doit être là où la notification part. La description suit l'appareil qu'elle décrit. |
| Machines — nom, capacités, propriétaire, clé publique | **Oui** | Une machine enrôlée chez l'une annonce chez l'autre à la première bascule. |
| **Codes d'enrôlement en attente** | **Oui** | L'application émet le code chez une racine ; `asl enroll` le présente à celle que l'alias lui donne. Sans réplication, un code sur deux serait « inconnu ». Le code est un secret partagé, court, à usage unique (`modele.md` §2.3) — c'est son EMPREINTE qui circule, comme sur le disque, et le disque de l'autre racine n'est pas moins sûr que le nôtre. |
| **Invitations en attente** (posture `invitation`, `protocole.md` §2.2) | **Oui** | Même raison, mot pour mot, que les codes d'enrôlement : l'alias donne une racine au hasard, et un code qui ne vaudrait que chez celle qui l'a émis serait inconnu une fois sur deux. C'est l'empreinte qui circule. **Mais la conséquence d'une double consommation n'est pas la même, et elle est traitée en §3.2 : deux comptes, qu'on ne départage pas.** |
| Services **déclarés** — identifiant, machine, nom | **Oui** | Un service est identifié par `(machine, nom)` et son `s-…` est attribué à la première annonce ; le client qui a mémorisé un `s-…` doit le retrouver après bascule. |
| Autorisations, et leurs révocations | **Oui** | C'est l'arête qui ouvre la résolution ; elle doit être vue de la racine qui résout. |
| **L'effacement d'un compte** — par son titulaire, par la règle des orphelins, ou par l'exploitant (`modele.md` §2.1) | **Oui** | Un compte effacé chez l'une doit l'être chez l'autre, avec tout ce qu'il tenait ; et c'est la marque « effacé » qui circule, pour que l'autre refuse ce qui arriverait en retard (§3.2). |
| Le bail, l'état `annoncé`, les points d'écoute annoncés | **NON** | `annuaires.md` §3 : l'état vivant se reconstruit en un keepalive. |
| La joignabilité, les candidats, `vu_depuis` | **NON** | Mesurés par une racine, depuis elle. Vrais là, et nulle part ailleurs. |
| **Le journal** (`journal.md`) | **NON** | Il dit ce que CETTE racine a servi. Le répliquer doublerait un actif que C18 veut le plus petit possible, et le doublerait au moment où l'on s'apprête à le jeter. |

**Ce que le journal non répliqué coûte, et il faut le dire.** `journal.md` §4
promet à un utilisateur de voir « qui a résolu ses services » ; avec deux
racines, il voit ce que celle qu'il interroge a servi. Le jour où ce verbe
s'écrira, l'application devra interroger les deux, ou accepter de dire « vu
depuis cette racine » — comme `joignable` dit « depuis l'annuaire ». Ce n'est
pas résolu ici, et c'est nommé (§11).

**Les codes d'enrôlement sont la seule ligne qui a fait hésiter.** Un code
vaut dix minutes, et la réplication prend moins d'une seconde quand la voie est
ouverte : dans le cas nominal, le code est chez l'autre avant que l'humain ait
fini de le taper. Ce qui a tranché est la coupure : pendant qu'elle dure, un
code émis chez l'une n'existe pas chez l'autre, et l'enrôlement par l'alias
réussit une fois sur deux. Ne pas répliquer aurait fait de ce cas le cas
normal.

---

## 2. Le transport — chacune TIRE chez l'autre

**HTTP/3 sur QUIC, sur le même port que tout le reste.** Une racine n'écoute
qu'une fois ; la voie entre racines est une ressource de plus sous `/v1`, avec
sa propre exigence, et non un second serveur. Ce qui distingue un pair d'un
client est ce qu'il a prouvé, pas où il frappe.

### 2.1 Deux connexions, une par sens, et c'est le lecteur qui ouvre

**Chaque racine ouvre une connexion vers l'autre, et y LIT sans fin ce que
l'autre a écrit.** Deux connexions, chacune ne portant qu'un sens.

L'autre forme — une seule connexion, tenue, où les deux poussent — obligeait à
décider qui ouvre, à départager deux ouvertures simultanées, et à faire passer
un sens par des `POST` et l'autre par un flux, puisqu'en HTTP/3 seul le client
demande. Deux connexions symétriques n'ont rien de tout cela : **le code est le
même dans les deux sens**, et c'est le lecteur qui tient son curseur, parce que
c'est lui qui sait ce qu'il a appliqué (§5).

**Tirer plutôt que pousser, pour la même raison.** Celui qui sait où il en est
est celui qui applique ; le faire demander « tout depuis là » rend le
rattrapage (§5) et le flux courant une seule et même requête. Un pair qui
pousserait devrait tenir le curseur de l'autre, c'est-à-dire un état sur ce
qu'un autre a fait.

Le prix : deux connexions au lieu d'une, entre deux machines qui en tiennent
des milliers. Il ne se mesure pas.

### 2.2 Authentifiée par LEURS clés — et par rien d'autre

`annuaires.md` §2 : ce qui est épinglé, ce sont les CLÉS PUBLIQUES des deux
racines, et l'adresse n'est qu'un moyen de les joindre. La voie entre racines
tient cette ligne à la lettre.

**Chaque racine détient une clé d'identité Ed25519**, distincte de sa clé TLS.
La clé TLS tourne avec le certificat ; l'identité, elle, est ce que l'autre
racine épingle et ce que les estampilles nomment (§4) — elle ne tourne pas.
L'identifiant `n-…` d'une racine SE DÉDUIT de sa clé d'identité (les seize
premiers octets d'un SHA-256 à domaine séparé) : épingler la clé épingle
l'identifiant, et il n'y a pas de table à tenir d'accord avec un fichier.

**Les deux prouvent, un défi par sens** :

1. La racine qui tire prouve sa clé exactement comme une machine prouve la
   sienne — `GET /v1/defi`, puis `POST /v1/defi` avec un genre `n`, son
   identifiant et sa signature, liée au canal (`protocole.md` §2.1 bis). Le
   verbe existe, la preuve existe ; il y a un genre de plus.
2. La racine tirée prouve la sienne en retour : le tireur lui pose un défi
   (`POST /v1/pair/preuve`), elle le signe sous un domaine propre. Sans ce
   second temps, la racine tirée ne serait authentifiée que par son certificat
   — c'est-à-dire par l'autorité de certification, qui n'est pas l'ancre.

La racine tirée compare ce qu'on lui prouve à LA clé qu'elle a en réglage
(`--peer-key`, §8) ; le tireur fait de même. **Il n'y a aucune liste de pairs,
aucune découverte, aucun certificat de plus** : deux clés, connues d'avance,
chacune de l'autre. Un tiers qui parle depuis la bonne adresse avec un
certificat valide n'est pas une racine.

### 2.3 Tenue comme la voie du daemon

**Le keepalive et le délai d'inactivité sont ceux du daemon** (`modele.md`
§4.1) : 10 s et 30 s, lus des mêmes réglages `--keepalive` et `--idle`. Deux
racines dans le même centre d'hébergement n'ont pas besoin de dix secondes,
mais une troisième valeur serait une troisième chose à mesurer, et rien ici ne
souffre d'un keepalive trop fréquent.

**La reconnexion est celle d'`asl-client`** (`protocole.md` §1.5) : recul
exponentiel, plafonné, avec un bruit de ±20 %, et **on n'abandonne jamais**.
Une racine qui a perdu l'autre la rappelle jusqu'à ce qu'elle revienne, et
reprend là où son curseur s'était arrêté. La voie coupée se voit dans le
journal d'exploitation (§8) ; elle n'empêche rien de servir.

---

## 3. Les deux écrivent — et la règle de conflit

**Une écriture est acquittée par UNE racine.** Elle n'attend pas l'autre :
l'application reçoit son `201` ou son `204` quand l'entrepôt local a écrit, et
l'autre racine l'apprend ensuite, par le flux. C'est ce qui fait qu'une racine
seule — l'autre en panne, ou la voie coupée — continue de créer des comptes,
d'enrôler et d'accorder. Un quorum l'interdirait, et c'est le sujet de §3.4.

**Un identifiant à 128 bits ne collisionne pas.** Créer un compte, un appareil,
une machine, une autorisation chez l'une ou chez l'autre ne peut donc jamais
entrer en conflit : deux créations sont deux enregistrements, et chacun ne
s'écrit qu'une fois. Les conflits possibles sont ailleurs — là où deux
écritures visent LE MÊME enregistrement, ou LA MÊME unicité.

### 3.1 L'invariant, avant les cas

**La règle de chaque cas donne le même résultat dans les deux ordres
d'arrivée.** C'est ce qui rend les deux racines identiques une fois qu'elles ont
tout vu — quelle que soit la façon dont elles l'ont vu —, et c'est le seul
énoncé qui se vérifie mécaniquement : un essai qui applique un même jeu
d'opérations dans tous ses ordres et compare les deux entrepôts. Une règle qui
dépendrait de qui a reçu quoi en premier ferait deux annuaires qui se croient
d'accord.

Toute règle ci-dessous s'énonce donc sur des ESTAMPILLES (§4), jamais sur
l'heure d'arrivée.

### 3.2 Les cas, un par un

| Le conflit | La règle | Ce qui est perdu |
|---|---|---|
| **Une révocation d'un côté, une écriture de l'autre** — appareil, clé de machine, autorisation | **La révocation l'emporte toujours.** Elle nomme ce qu'elle révoque — CET appareil, CETTE clé, CETTE autorisation — et s'applique quel que soit l'ordre. Une écriture sur l'objet révoqué arrivée après est refusée comme elle le serait localement ; arrivée avant, la révocation la couvre. | Un jeton de poussée déposé pendant la fenêtre, une capacité changée. Rien qu'on regrette : une révocation est irréversible par construction, et ce qu'on écrivait sur l'objet ne valait plus. |
| **L'effacement d'un compte d'un côté, une écriture du même compte de l'autre** — un appareil enrôlé, une machine déclarée, un alias réclamé, une autorisation accordée à lui ou par lui (décidé le 2026-09-18) | **L'effacement l'emporte toujours** : c'est une révocation, qui nomme le compte entier. Arrivée avant, l'écriture est couverte — l'effacement retire ce qu'elle avait posé ; arrivée après, elle est **refusée, le compte est effacé**, et le curseur avance : c'est le refus local d'une écriture sur un objet révoqué, pas une opération illisible. Deux effacements du même compte — les deux racines passent le délai des orphelins à la même minute — n'en font qu'un : le second ne trouve plus rien à retirer, et la marque porte la date et la cause du premier appliqué. **Un effacement ne se défait pas**, comme une révocation. | Un appareil enrôlé sur l'autre racine pendant la fenêtre : son porteur a reçu son `a-…`, et sa prochaine connexion rend `401`. Une autorisation accordée à un compte qui s'effaçait : l'autre partie ne la voit jamais. Un alias réclamé : la réclamation tombe avec le compte. C'est le prix exact d'une révocation, sur un objet plus large. |
| **Un alias pris des deux côtés** | **Un alias est une RÉCLAMATION, et la plus ancienne tient.** Chaque compte porte au plus une réclamation courante (son dernier `PUT`/`DELETE /v1/alias`, le plus récent gagne). Pour un alias donné, le titulaire est le compte dont la réclamation courante porte la plus petite estampille. Les deux racines calculent le même titulaire, parce que c'est une fonction de l'ensemble des réclamations, pas de leur ordre. | Le perdant a reçu `204` et n'a pas l'alias. Il l'apprend en lisant `GET /v1/alias/{alias}` — l'application le fait après un `PUT` par l'alias, et le dit. Sa réclamation reste en file : si le titulaire lâche l'alias, il le tient. |
| **Un `PATCH` de machine des deux côtés** | **Le plus récent gagne, CHAMP PAR CHAMP** — le nom a son estampille, les capacités ont la leur. `PATCH` est champ par champ (`protocole.md` §2.2) ; une règle par enregistrement ferait perdre un nom parce qu'une capacité a gagné. | Un renommage, ou un jeu de capacités, écrit dans la fenêtre. Il se réécrit. |
| **Un code d'enrôlement consommé d'un côté, présenté de l'autre** | Un code consommé est **supprimé partout dès que la consommation est répliquée** — c'est la même opération que la liaison de la clé (§5.2). Entre-temps, l'autre racine n'a pas encore vu la consommation et **l'accepte** : elle ne peut pas refuser ce qu'elle ne sait pas. D'où le cas suivant. | Rien, dans le cas nominal : la consommation arrive en moins d'une seconde. |

**Cette ligne est une FENÊTRE, pas un conflit réordonnable** — et la PR de code
(3/4) l'a nommé en l'éprouvant. Un code se consomme sur la racine où il a été
émis, et la consommation SUIT l'émission sur cette même racine : les deux ne
peuvent pas arriver dans l'ordre inverse chez un pair, contrairement à un alias
que deux racines réclament chacune de son côté. L'invariant de §3.1 s'éprouve
donc sur les cas VRAIMENT réordonnables (les huit autres lignes — l'effacement
d'un compte compris, depuis le 2026-09-18, et l'attestation d'un appareil
révoqué, depuis le 2026-09-21), et ce cas-ci
par une régression dirigée qui rejoue « émettre, consommer, présenter ailleurs
avant la propagation » — la fenêtre —, non par les permutations. Ce qui la
ferme reste la règle du cas suivant : à code égal, la première consommation
gagne.
| **Le même code consommé des deux côtés** — deux clés pour une machine | **La liaison qui gagne est celle du code le plus récemment ÉMIS ; à code égal, la PREMIÈRE consommation.** La liaison porte l'estampille d'émission de son code et la sienne ; c'est un ordre total, donc le plus grand gagne quel que soit l'ordre d'arrivée. | La machine perdante s'est crue enrôlée — elle a reçu son `m-…` — et sa prochaine connexion rend `401`. Elle se ré-enrôle avec un nouveau code. Cela ne se produit que si le même code a été tapé sur deux machines pendant une coupure entre racines : une faute de l'humain, ou un code intercepté — et dans ce second cas, la règle vaut mieux que « le dernier gagne ». |
| **Deux codes émis pour la même machine** | Le plus récent gagne, l'autre meurt — c'est déjà la règle locale (« le code précédent meurt à l'émission du suivant »). | Un code affiché sur un écran ne marche plus. Il se réémet. |
| **Le même code d'INVITATION consommé des deux côtés** — deux comptes pour une invitation (2026-09-24) | **Aucune règle de conflit : les deux comptes vivent.** Rien ne les départage — deux comptes distincts ne se disputent ni identifiant, ni alias, ni machine, et chacun porte l'appareil de celui qui l'a ouvert. Effacer le second serait détruire un compte au motif qu'un autre est arrivé d'abord, sur une course d'une seconde ; l'annuaire ne le fait pas. **Le journal dit que le même code a servi deux fois, avec les deux `u-…`** ; l'exploitant tranche s'il le veut, hors ligne (`--forget`, décision 24). | Deux personnes entrent là où l'exploitant en attendait une. Il faut une faute ou un code intercepté pour y arriver — et dans ce second cas, celui qui intercepte aurait obtenu un compte en arrivant le premier. |
| **Le même service déclaré des deux côtés** — un daemon bascule pendant une coupure et réannonce `(machine, nom)` chez l'autre, qui lui attribue un second `s-…` | **Le plus ancien gagne, l'autre s'efface.** Un service ne bouge jamais et ne se retire jamais ; les deux racines finissent donc avec le même, dans tous les ordres. | Un `s-…` qu'un client a pu voir disparaît. Les clients résolvent par le NOM (`protocole.md` §3), et l'identifiant n'est qu'attribué à la première annonce : la perte est un identifiant, pas un service. |
| **Une description ou un jeton déposés des deux côtés** | Le plus récent gagne — la règle locale, « le neuf remplace l'ancien ». | Une étiquette. |
| **Un appareil attesté d'un côté, révoqué de l'autre** — le nouveau téléphone prouve chez `argon` pendant que l'ancien le révoque chez `nitrogen` (2026-09-21) | **Les deux s'appliquent, quel que soit l'ordre.** L'attestation est un fait sur la clé — elle ne va que d'`aucune` ou `attendue` vers une valeur prouvée, jamais en arrière — et la révocation un fait sur l'appareil ; ils ne se contredisent pas, et les deux racines finissent avec `android, révoqué`. Ne pas poser l'attestation sur un appareil révoqué aurait fait diverger la valeur selon l'ordre d'arrivée. | Rien : l'appareil est révoqué, et sa connexion fermée par la révocation (§3.3). Que sa clé ait été attestée est ce que l'écran d'après une perte montre, comme le modèle. |

**Ce que les règles ont en commun, et qui les rend explicables** : ce qui est
irréversible chez soi (une révocation, une consommation, un effacement de
compte) est irréversible partout ; ce qui se remplace chez soi (un nom, un
jeton, un code) se remplace partout, par le plus récent ; ce qui est unique
chez soi (un alias, un couple `(machine, nom)`, une clé par code) va au plus
ancien. **Trois règles, et
chacune est celle qu'on aurait devinée** — c'est le critère.

### 3.3 Les effets d'une opération appliquée

Appliquer une opération venue de l'autre racine **produit les mêmes effets sur
l'état VIVANT qu'une écriture locale** : révoquer une clé de machine ferme les
connexions de cette machine ICI aussi, retirer `annonce` fait tomber ses baux
ICI aussi (`protocole.md` §2.1 quater). Sans cela, une machine révoquée chez
`nitrogen` continuerait de servir chez `argon` jusqu'à ce que sa connexion
tombe d'elle-même — la fenêtre exacte que « effet immédiat » ferme.

**L'effacement d'un compte se rejoue de la même façon** (2026-09-18) : la
racine qui l'applique ferme ICI les connexions de toutes les machines et de
tous les appareils de ce compte — un daemon du compte qui tenait son bail chez
`argon` pendant que le titulaire effaçait chez `nitrogen` part par le chemin
ordinaire, à la seconde où l'opération arrive. Et **elle ne le journalise pas
comme un effacement à elle** : une ligne du journal d'exploitation, avec
l'identifiant, la cause portée par l'opération et « appliqué » — pas
« effacé ». Qui a effacé est dit par l'estampille.

**Et AUCUN effet vers l'extérieur.** La notification d'une autorisation part de
la racine qui a pris l'écriture ; celle qui l'applique ne notifie pas. Un
utilisateur ne doit pas recevoir deux fois « vous a accordé l'accès », et le
principe est général : **ce qui est vivant se rejoue, ce qui est parti ne
repart pas.**

### 3.4 Pas de témoin, et ce que cela change à `annuaires.md` §6

`annuaires.md` §6 posait un TÉMOIN — un troisième votant sans donnée — pour
donner aux écritures rares un ordre par quorum. Ce document **s'en passe, et
c'est proposé, à confirmer** (§10).

**Pourquoi.** Le quorum servait à ordonner « créer un compte, déclarer une
machine, accorder ». Or ces écritures n'ont pas besoin d'ordre : un identifiant
à 128 bits les rend indépendantes. **Les seules écritures qui demandent un
ordre sont celles qui touchent une unicité** — l'alias, le couple
`(machine, nom)`, la clé d'une machine —, et pour celles-là, §3.2 donne un
PERDANT plutôt qu'une attente. Le perdant est nommé, ce qu'il perd est dit, et
il reste borné à la fenêtre de propagation — des secondes quand la voie est
ouverte, la durée de la coupure sinon.

**Ce que le témoin aurait acheté, et qu'on n'a pas** : la garantie qu'un `204`
sur `PUT /v1/alias` est définitif. Ici, il l'est sauf pendant une fenêtre, et
l'application relit pour s'en assurer (§6). **Ce que le témoin aurait coûté** :
une troisième machine chez un troisième hébergeur, et une écriture qui échoue
quand deux des trois ne se parlent pas — donc une racine seule qui ne crée plus
de compte, alors qu'elle en est parfaitement capable.

Le témoin reste la suite naturelle si un jour une unicité exige d'être
garantie plutôt que départagée. §6 d'`annuaires.md` le dit désormais ainsi.

---

## 4. L'horloge — une estampille de Lamport, pas l'heure

**Chaque racine tient un compteur, et chaque écriture locale porte
`(compteur, racine)`.** Le compteur avance de un à chaque écriture locale, et
**se hisse au-dessus de tout ce que la racine reçoit** — quand elle applique
une opération estampillée `h`, son compteur devient `max(compteur, h)`. C'est
une horloge de Lamport, et rien de plus.

Deux estampilles se comparent par le compteur, puis par l'identifiant de la
racine. **C'est un ordre total, et les deux racines le calculent pareil** — ce
que §3.1 exigeait.

### Pourquoi pas l'heure murale

Les deux racines n'ont pas la même horloge. Elles sont à quelques millisecondes
l'une de l'autre les bons jours, et un NTP qui décroche les met à des minutes.
Une règle qui dirait « la plus ancienne gagne » à l'heure murale donnerait
alors, pendant une coupure, la victoire à celle dont l'horloge retarde — et un
exploitant qui recale une horloge changerait le titulaire d'alias sans avoir
touché à rien.

**Une horloge logique ne dit pas qui a été premier à la pendule.** Elle dit un
ordre sur lequel les deux racines sont d'accord, et c'est tout ce que la règle
de conflit demande. Le prix se dit : pendant une coupure, « le plus ancien »
est celui dont le compteur est le plus bas, et la racine qui a le moins écrit
gagne les alias. C'est arbitraire, et c'est stable — deux choses qu'une pendule
n'offre pas ensemble.

### Un seul nombre, deux emplois

Le compteur d'une racine est strictement croissant sur ses propres écritures.
Il sert donc aussi de **curseur** (§5) : « tout ce que tu as écrit après `h` »
est une question qui a un sens, sans second numéro de séquence à tenir
d'accord avec le premier.

### Ce que porte chaque enregistrement

**L'estampille de sa dernière écriture** — et, là où §3.2 juge champ par champ,
une par champ : le nom et les capacités d'une machine ; la réclamation d'alias
d'un compte ; la clé d'une machine, avec l'estampille d'émission du code qui
l'a liée. Une colonne de plus, sur le modèle de l'origine (`modele.md` §2.9) :
ce n'est pas une commodité, c'est ce qui rend la règle calculable après coup.

**Elle ne dit pas l'heure, et c'est une qualité de plus.** Un compteur n'est
pas une date : répliquer n'ajoute aucune ligne de temps à ce que l'entrepôt
porte déjà (C13, C18). Les dates que le modèle porte — `enrôlé le`,
`révoqué le`, `expire à` — restent celles de la racine qui a écrit, et se
répliquent telles quelles.

---

## 5. Le journal des opérations, et le rattrapage

### 5.1 Chaque racine tient le journal de SES écritures

**Toute écriture locale ajoute une opération à un journal d'opérations, dans la
même transaction.** C'est ce que l'autre racine tire. Il ne contient que ce que
cette racine a écrit ELLE-MÊME : ce qu'elle a appliqué de l'autre n'y est pas
réécrit. Il n'y a pas de réplication transitive (`annuaires.md` §4.4), et à
deux, rien ne l'exige.

Une opération est un cadre d'octets à champs fixes, comme tout ce qui porte des
clés (`protocole.md` §2.1 bis) :

```
genre (1) ‖ compteur (8) ‖ racine (17) ‖ charge (taille fixée par le genre)
```

**La charge est l'enregistrement dans le format de l'entrepôt** — le codec
d'`asl-registre`, couvert à 100 % et fuzzé, qui sert déjà à le ranger. Le genre
fixe la taille de la charge, donc **aucune longueur ne vient du réseau**, et il
n'y a pas de second décodeur : ce qui se lit sur le fil est ce qui se lit sur
le disque.

### 5.2 Les genres d'opération

| Genre | Charge | Règle d'application |
|---|---|---|
| `compte` | identifiant ‖ compte | Insérer si absent. |
| `alias` | compte ‖ alias ou rien | Réclamation courante du compte : le plus récent. Le titulaire d'un alias se recalcule (§3.2). |
| `appareil` | identifiant ‖ appareil | Insérer si absent. |
| `appareil-revoque` | identifiant | Marquer, retirer le jeton. Toujours. |
| `appareil-atteste` | identifiant ‖ attestation (1) | **Toujours**, révoqué ou non (§3.2) — poser la valeur si l'appareil est `aucune` ou `attendue` ; s'il porte déjà une valeur prouvée, rien : une clé ne s'atteste qu'une fois, et deux racines ne peuvent en avoir vu qu'une. Un appareil `attendue` qui devient `android` ou `apple` est désormais vivant ici aussi : sa prochaine preuve est servie. Décidé le 2026-09-21. |
| `description` | appareil ‖ description | Le plus récent. |
| `poussee` | appareil ‖ jeton | Le plus récent ; refusé si l'appareil est révoqué. |
| `machine` | identifiant ‖ machine, sans clé | Insérer si absent. |
| `machine-modifiee` | identifiant ‖ champs présents ‖ nom ‖ capacités | Le plus récent, champ par champ. Retirer `annonce` ferme les connexions ici aussi. |
| `enrolement` | empreinte ‖ enrôlement | Le code courant de la machine : le plus récent ; le précédent s'efface. |
| `cle-machine` | machine ‖ clé ‖ empreinte du code ‖ estampille d'émission du code | Supprimer le code s'il est là ; lier la clé selon §3.2 — code le plus récent, puis première consommation. |
| `cle-machine-revoquee` | machine ‖ clé révoquée | Retirer la clé si c'est bien celle-là ; fermer les connexions. |
| `invitation` | empreinte ‖ expire le (8) | Insérer si absente. Une invitation n'a pas de « plus récente » à départager : chaque code est le sien, et deux codes émis coexistent — contrairement au code d'enrôlement, qui appartient à UNE machine et remplace le précédent. |
| `invitation-consommee` | empreinte | **Toujours.** Supprimer l'empreinte, présente ou non — inconnue, la supprimer d'avance ferme la porte à une opération d'émission qui arriverait en retard. Le compte créé en face voyage par ses propres opérations (`compte`, `appareil`) : celle-ci ne porte que la disparition du code. |
| `service` | identifiant ‖ service | Insérer ; si `(machine, nom)` est déjà tenu, le plus ancien reste. |
| `autorisation` | identifiant ‖ autorisation | Insérer si absent. |
| `autorisation-revoquee` | identifiant | Marquer. Toujours. |
| `compte-efface` | identifiant ‖ effacé le (8) ‖ cause (1) | **Toujours.** Retirer tout ce que le compte tient — appareils, jetons, descriptions, machines et leurs clés, codes, services, autorisations dans les deux sens, réclamation d'alias — et marquer le compte effacé avec la date et la cause portées. Fermer les connexions de ses machines et appareils ici aussi (§3.3). Sur un compte déjà effacé : rien. Sur un compte inconnu : poser la marque quand même — ce qui arriverait ensuite pour lui est refusé (§3.2). Décidé le 2026-09-18. |

**Il n'y a pas d'opération d'effacement d'une machine ou d'un service** :
l'API n'en a pas. **Il y en a une pour un compte, depuis le 2026-09-18, et
c'est la seule qui efface physiquement des enregistrements** — tout ce que le
compte tenait part, et seul le compte reste, marqué (`modele.md` §2.1). C'est
ce qui rend cette opération compatible avec l'instantané (§5.4) : un compte
effacé y figure par sa marque, une seule opération `compte-efface`, et rien de
ce qu'il tenait n'a besoin d'être dit puisque l'autre racine, en l'appliquant,
retire ce qu'elle en avait. Sans la marque, l'instantané serait muet sur ce
compte, et une racine qui l'aurait gardé ne le saurait jamais. Les autres
disparitions physiques restent celles d'avant : un code — consommé par
`cle-machine`, ou expiré par chaque racine à sa propre horloge, sans
opération — et un jeton, qui suit la révocation de son appareil. Tout le
reste est marqué, jamais effacé.

**`appareil-revoque` porte désormais la date** — `identifiant ‖ révoqué le
(8)` —, parce que la règle des orphelins la lit (`modele.md` §2.1, §2.2) et
que les deux racines doivent lire la même. C'est la date de la racine qui a
révoqué, répliquée telle quelle (§4) ; l'autre ne pose pas la sienne.

**Le décompte des orphelins se fait à l'horloge de chaque racine**, comme
l'expiration des codes : chacune regarde, à son rythme, les comptes sans
appareil vivant dont le `révoqué le` le plus récent a plus de `--orphans`
jours, et écrit `compte-efface` avec la cause `orphelin` pour chacun. Elles
lisent la même date, donc arrivent à la même échéance à quelques secondes
près, et la première qui écrit fait appliquer l'autre ; si les deux écrivent,
la seconde opération ne trouve rien à retirer (§3.2). Un compte est « sans
appareil vivant » quand tous ses appareils sont révoqués — jamais quand ils se
taisent (C6).

**Une opération illisible arrête le flux ; elle ne se saute pas.** La racine
qui la reçoit ferme, journalise (§8), et ne fait pas avancer son curseur. Sauter
une opération, c'est diverger en silence — la faute que ce document existe pour
ne pas commettre. C'est à l'exploitant de regarder, et c'est ce que le journal
d'exploitation lui montre.

### 5.3 Le curseur, et le rattrapage qui n'est pas un mode à part

```
GET /v1/pair/operations?apres=<compteur>
        (dans la connexion authentifiée par la clé de la racine qui tire)
```

**La réponse ne se termine jamais**, sur le modèle exact de `GET /v1/poussees`
(`protocole.md` §1.4) : la racine tirée écrit d'abord tout ce que son journal
porte après `apres`, puis chaque opération nouvelle à mesure qu'elle l'écrit.
Le tireur applique chaque opération et **avance son curseur dans la même
transaction** : une coupure entre les deux relivre l'opération, et la règle
d'application est idempotente, donc c'est sans effet.

**Le rattrapage EST cette requête.** Une racine qui revient après deux heures
de coupure rouvre la connexion avec le curseur où elle s'était arrêtée, et lit
ce qu'elle a manqué, puis ce qui suit, sans qu'un « mode rattrapage » existe
nulle part. La reconnexion d'`asl-client` (§2.3) fait le reste.

**Le tireur refuse ce qui recule.** Une opération dont le compteur n'est pas
supérieur à son curseur pour cette racine est refusée et journalisée : c'est
l'anti-rejeu de C17, un numéro de séquence par relation, et il vaut ici entre
racines comme il vaudra entre pairs.

### 5.4 La rétention du journal, et l'amorçage

**Le journal d'opérations est gardé TRENTE JOURS** (proposé, à confirmer —
§10). Il porte la même chose que l'entrepôt, sans une donnée de plus ; sa
rétention n'est donc pas une question de C18, c'est une question de place et de
ce qu'on fait d'une racine partie plus longtemps.

Ce qui a fixé le chiffre : une racine absente un mois n'est plus une racine en
retard, c'est une racine à reconstruire — et la reconstruire est exactement
l'opération qu'exige une racine NEUVE. Une seule procédure pour les deux, et
elle s'appelle l'amorçage :

```
GET /v1/pair/operations?apres=<compteur>    →  410 si le journal ne remonte plus jusque-là
GET /v1/pair/instantane                     →  l'état entier, puis le compteur de coupe
```

**Un instantané est une suite d'opérations, pas un second format.** La racine
tirée lit son entrepôt dans une seule transaction et émet, pour chaque
enregistrement, les opérations qui le reconstituent — avec LEURS estampilles,
celles de l'écriture d'origine, qui peuvent être de l'une ou l'autre racine.
Puis un cadre de fin porte le compteur auquel l'instantané a été coupé, et le
tireur reprend `GET /v1/pair/operations` à partir de là.

**Il part en PLUSIEURS trames, sur plusieurs flux, et non en une seule
(décidé par la PR de code, 4/4).** La pile QUIC greffée d'`air-mail-server`
annonce une fenêtre par flux — seize kibioctets — et ne la relève jamais : un
corps plus grand émis en une trame `DATA` se tairait au-delà de cette fenêtre,
sans que rien ne le dise. La racine tirée coupe donc chaque flux quand il a
porté sa PART — douze kibioctets, à une frontière d'opération, jamais au milieu
d'un cadre —, et le tireur en rouvre un : `operations` reprend depuis son
curseur, `instantane` continue le reste que la connexion tient jusqu'au cadre
de fin. **La borne qui reste est l'instantané entier**, tenu en mémoire le
temps d'une lecture par la racine tirée — à l'échelle où ce produit vit,
quelques mégaoctets —, et c'est le prix d'une reprise, pas d'une routine. Le
flux d'opérations courant se coupe et se rouvre de la même façon ; ce qui ne
change pas est qu'il ne se termine JAMAIS de lui-même — seul son curseur avance.
Le tireur applique chaque part par LOT, dans une transaction, et non une
opération à la fois : un amorçage de plusieurs milliers d'enregistrements est
alors une affaire de secondes.

**Parce qu'il s'applique avec les mêmes règles, un instantané FUSIONNE au lieu
d'écraser.** Une racine qui a continué d'écrire pendant quarante jours de
coupure applique l'instantané de l'autre comme un flux : ce qu'elle a de plus
récent reste, ce qui est unique va au plus ancien, et rien de ce qu'elle a écrit
seule n'est perdu — sauf ce que §3.2 nomme.

**Et une racine qui repart d'un entrepôt vide hisse son compteur au-dessus de
tout ce qu'elle lit** — y compris de ses propres opérations d'avant la perte,
que l'instantané lui rend. Sans cela, elle réémettrait des estampilles déjà
vues, que l'autre refuserait comme un rejeu.

Ce que cela coûte : un instantané transporte tout l'annuaire. À l'échelle où
ce produit vit — des comptes et des machines, pas des messages —, c'est
quelques mégaoctets, et c'est une opération de reprise, pas de routine.

---

## 6. Ce que voit le client pendant la propagation

**Un compte créé chez `nitrogen` puis lu chez `argon` avant que l'opération y
soit arrivée n'existe pas** : `404` sur un identifiant, `401` sur une clé
inconnue, « code inconnu » sur un enrôlement. Voie ouverte, la fenêtre est
d'une fraction de seconde ; voie coupée, elle dure la coupure. **Il faut le
dire aux applications, parce qu'elles le verront** — c'est précisément ce qui a
été vu le 15.

Ce que chaque client doit en faire, et c'est court :

| Qui | La règle |
|---|---|
| **Les applications mobiles** | Elles parlent aujourd'hui à `nitrogen` par son nom, et ne voient rien. Le jour où elles passent par l'alias : **la connexion tenue est la session** — tant qu'elle tient, elles parlent à la même racine, et rien de ce qu'elles écrivent ne leur manque à la lecture suivante. Une reconnexion peut tomber sur l'autre ; ce qui a été écrit plus de quelques secondes avant y est. Après un `PUT /v1/alias`, elles relisent `GET /v1/alias/{alias}` et disent si le titulaire n'est pas elles (§3.2). |
| **`asl enroll`** | Un code refusé sur une racine **s'essaie une fois sur l'autre** avant de dire « code inconnu » — le refus est le même pour un code inconnu et pour un code pas encore arrivé, par construction (`protocole.md` §2.0), et seul le client sait qu'il y a une autre racine. Deux tentatives, bornées, sur un secret de cinquante bits que le second essai n'affaiblit pas. |
| **`asl-client`, le daemon** | La reprise de `protocole.md` §1.5 est déjà le bon geste — essayer les racines dans l'ordre, reculer, ne jamais abandonner —, à une nuance : **un `401` sur une racine n'est pas définitif.** Une machine tout juste enrôlée peut ne pas encore être connue de l'autre ; on essaie l'autre, puis on recule. |
| **`asl`, une commande, une connexion** | Elle tient la racine que l'alias lui a donnée pour toute la commande. Entre deux commandes, la fenêtre est passée. |

**Il n'y a pas de « lis chez celle qui a écrit » à porter dans le protocole.**
Une réponse ne dit pas de quelle racine elle vient, et n'a pas à le dire : le
client qui a besoin de cohérence après écriture tient sa connexion, et c'est
tout ce que le transport tenu lui demande.

---

## 7. La sécurité — ce que chaque contrainte devient

**C9 — temps constant.** La réplication est HORS du chemin de réponse : l'ajout
au journal d'opérations se fait dans la transaction qui écrit déjà, et n'ajoute
aucune branche qu'un refus n'aurait pas ; l'envoi est une tâche à part. Le seul
chemin d'autorisation qui écrit — l'enrôlement — écrivait déjà sur succès et
non sur refus, et l'écart qui reste porte sur une empreinte de 256 bits que
personne ne sait approcher. Rien ne change.

**C10 — rien ne se lit sans autorisation.** Le flux n'est pas une lecture : il
est une relation entre les deux racines, sous une exigence que seule une clé
d'identité de racine satisfait, et il transporte TOUT, sans que le lecteur
choisisse. Aucune clé de machine ni d'appareil ne peut l'atteindre.
`decider_resolution` continue de calculer depuis le propriétaire de la machine
qui demande, et ne voit pas d'où un enregistrement est venu.

**C11 — un pair n'affirme que sur son autorité.** Ici les deux racines ONT la
même autorité, et C11 se réduit à une seule vérification, peu coûteuse et exacte :
**la voie entre racines ne transporte que des enregistrements de provenance
`locale`.** Ce qu'une racine aura un jour reçu d'un annuaire rattaché (§5
d'`annuaires.md`) n'est pas à elle, et ne passe pas — pas de réplication
transitive. Une opération qui porterait une autre provenance est refusée et
journalisée, exactement comme une assertion hors périmètre.

**C13 — rien de plus que l'entrepôt ne porte.** Une opération est un
enregistrement, dans son format, plus un compteur et un identifiant de racine.
Pas d'adresse, pas d'heure d'arrivée, pas de « qui a demandé ». Le journal
d'opérations n'est pas un journal de requêtes : c'est la donnée, avec un
numéro.

**C17 — l'origine.** Un enregistrement répliqué depuis l'autre racine porte la
provenance **`locale`**, pas `Annuaire(n-…)` (proposé, à confirmer — §10).
`Annuaire(…)` désigne une RELATION de confiance, qui se rompt et dont la rupture
efface ; entre racines il n'y a pas de relation à rompre, il y a une autorité en
deux exemplaires. Qui a écrit est dit par l'estampille (§4), et c'est là que
cette information sert.

**Rompre la réplication, donc, N'EFFACE RIEN** — et c'est la réponse à la
question. Ce qui a été répliqué est à nous autant qu'à l'autre ; l'effacer
fermerait les comptes de gens qui n'ont rien fait. Couper `--peer` arrête le
flux, et les deux racines divergent à partir de là, sans autre conséquence ; les
rebrancher rattrape (§5.3) ou amorce (§5.4), et la fusion fait le reste.

**Ce que cela coûte, et qu'il faut regarder en face : la clé d'identité d'une
racine est la clé de l'autorité entière.** Qui la détient écrit dans les deux
entrepôts en moins d'une seconde. Ce n'est pas nouveau — qui détient une racine
détient déjà tout ce qu'elle sert — mais la réplication le propage. Il n'y a
pas de parade dans ce document, et il ne faut pas en prétendre une : la clé vit
sur la racine, nulle part ailleurs, et la remplacer est le problème de l'ancre
(`annuaires.md` §2, troisième issue). Ce que la seconde racine apporte est
l'inverse : un entrepôt perdu se reconstruit depuis l'autre.

---

## 8. La configuration et l'exploitation

```
asl-server … --identity-key <fichier>        # la clé d'identité Ed25519 de cette racine
              --peer <hôte:port>             # l'autre racine
              --peer-key <fichier>           # sa clé d'identité publique
              --peer-ca <fichier>            # l'autorité qui valide son certificat TLS (PEM)
```

**Ils vont ensemble** : `--peer` sans `--peer-key` refuse de démarrer, parce
qu'une adresse seule n'est pas une racine (`annuaires.md` §2). Sans `--peer`, la
racine tourne seule et le journal d'exploitation le dit au démarrage — ce n'est
pas un défaut, c'est un banc.

**`--peer-ca` a été ajouté par la PR de code (0.7.0), et §8 ne l'avait pas
prévu.** La clé d'identité (`--peer-key`) est l'ancre de l'AUTHENTIFICATION —
le pair prouve la clé qu'on tient de lui, liée au canal (§2.2). Mais pour
OUVRIR la connexion TLS, le tireur doit valider le certificat que le pair
présente, et la chaîne qu'un serveur montre (`--certificate`) ne porte pas la
racine qui l'a signée (`scripts/ca.sh` : « le certificat, puis rien »).
`--peer-ca` est cette racine-là — le `racine.crt` de la cérémonie, celui-là
même que le client épingle. C'est le certificat de plus que §2.2 disait ne pas
vouloir ; ce n'en est pas un « par pair », c'est l'autorité commune, et
l'authentification reste la clé d'identité, pas lui.

**`--identity-key` ne se génère pas tout seul.** `asl-server --new-identity-key
<fichier>` écrit la clé privée dans `<fichier>` (0600) et la publique dans
`<fichier>.pub`, imprime la clé publique et l'identifiant `n-…` qu'elle donne,
et s'arrête ; c'est `<fichier>.pub` qu'on porte chez l'autre racine, en
`--peer-key`. **Les deux fichiers portent trente-deux octets bruts** — ce
qu'`asl-cle` sait lire, ni PEM ni hexadécimal — et un fichier d'une autre
taille est refusé en le disant. Une clé générée en silence au premier démarrage serait une clé que
personne n'a copiée nulle part, et deux racines qui ne se connaissent pas.
`--identity-key` et non `--identity` : c'est une clé PRIVÉE, et son nom le
dit — comme `--key` le dit pour celle de TLS.

```
asl-server … --orphans <days>                # efface un compte sans appareil vivant
                                             # après tant de jours ; 0 = jamais
                                             # (default: 30)
asl-server --forget <u-…> --store <fichier>  # efface CE compte, hors ligne, et s'arrête
```

**Deux réglages de plus, depuis le 2026-09-18** (`modele.md` §2.1). `--orphans`
est la règle : une racine sans `--orphans` efface à trente jours ; `--orphans
0` n'efface jamais, et le journal d'exploitation le dit au démarrage, comme il
dit « sans pair ». Ce n'est pas un réglage de réplication, mais il vit ici
parce que **les deux racines doivent porter la même valeur** : deux racines à
délais différents feraient effacer par l'une ce que l'autre garderait encore
un mois — la règle de conflit tranche en faveur de l'effacement, donc c'est
la plus courte qui gagne, et l'autre n'a pas eu son mot. Ce n'est pas vérifié
sur la voie — une racine ne lit pas les réglages de l'autre —, c'est une
consigne de déploiement, et le drop-in des bancs la porte une fois pour les
deux.

**`--forget` est un verbe hors ligne, comme `--new-identity-key`** : il ouvre
l'entrepôt — et refuse, en le disant, si le daemon le tient —, écrit
`compte-efface` avec la cause `exploitant` dans la même transaction que le
retrait de tout ce que le compte tenait, ajoute l'opération au journal
d'opérations pour que l'autre racine l'applique au prochain rattrapage,
imprime l'identifiant et ce qui a été retiré (des nombres : tant d'appareils,
tant de machines, tant d'autorisations), et s'arrête. Un `u-…` inconnu est
refusé ; un `u-…` déjà effacé est dit tel, sans rien écrire. **Un identifiant
à la fois, et pas de liste** : c'est un geste qu'on fait en regardant, pas un
nettoyage. L'entrepôt étant arrêté, les effets vivants n'ont rien à fermer ;
au redémarrage, la clé d'un appareil ou d'une machine de ce compte n'existe
plus, et sa connexion rend `401`.

**Ce qui se journalise, dans le journal d'exploitation (`stderr`)** :
l'ouverture et la fermeture de chaque sens, avec l'identifiant du pair ; un
rattrapage, avec le nombre d'opérations ; un amorçage, avec sa taille ; chaque
refus — opération illisible, qui recule, hors provenance — avec son genre et
son compteur ; l'état, à chaque changement ; **et chaque effacement de compte,
avec l'identifiant et la cause** — `titulaire`, `orphelin`, `exploitant` —,
qu'il soit écrit ici ou appliqué de l'autre racine (« appliqué », alors, et
non « effacé »). Un `u-…` seul n'est pas une donnée personnelle
(`modele.md` §2.1), et la ligne ne porte rien d'autre. **Jamais une opération par
ligne** : le journal d'opérations est déjà la trace, et une ligne par écriture
répétée sur `stderr` doublerait ce que C18 veut voir jeté.

**Comment l'exploitant voit l'état** :

```
GET /v1/replication
{"pair": "n-…", "voie": "ouverte", "compteur": 4812, "applique": 4790}
```

**La forme exacte, décidée par la PR de code (4/4).** Le corps est du JSON, et
le champ `voie` prend l'une de trois valeurs — un mot qu'on lit d'abord, dont
les autres champs découlent :

- `"ouverte"` — la connexion sortante vers le pair est ouverte et prouvée dans
  les deux sens en ce moment ;
- `"coupée"` — il y a un pair réglé, mais la connexion n'est pas établie (le
  pair est parti, ou la voie est rompue et la reprise rappelle) ;
- `"seule"` — **aucun pair n'est réglé** : la racine tourne seule, et le corps
  est alors `{"voie": "seule", "compteur": 4812}`, **sans `pair` ni
  `applique`** — il n'y a personne dont on applique quoi que ce soit, et un
  champ nul aurait l'air d'une valeur.

`compteur` est l'horloge de Lamport de cette racine (§4) ; `applique` est le
curseur qu'elle tient pour le pair (§5.3) — l'estampille de la dernière
opération ÉCRITE PAR LE PAIR qu'elle a appliquée. Les deux nombres et le mot
se lisent de l'entrepôt et du tireur au moment de la requête — rien n'est
recopié, donc rien ne vieillit.

**Les deux nombres ne se soustraient pas, et ce document l'a d'abord dit de
travers** (« `applique` rejoint `compteur` du pair en moins d'une seconde »,
corrigé le 2026-09-21, sur le banc). L'horloge d'une racine se hisse aussi
sur ce qu'elle REÇOIT (§4) ; le curseur que l'autre tient pour elle ne suit
que ce qu'elle ÉCRIT. Après l'amorçage du 19/09, `nitrogen` a écrit douze
fois et `argon` rien : les deux horloges disent 35, `nitrogen` tient pour
`argon` un curseur à 23 — et rien n'est en retard. Ce qui se lit à coup sûr :
`applique` ne dépasse jamais l'horloge du pair ; **s'il l'égale, tout ce que
le pair a écrit est appliqué** ; s'il est en dessous, on ne sait pas — le pair
a peut-être écrit, ou seulement reçu. La preuve de l'état, c'est la voie :
`ouverte` de chaque côté, le flux de §5.3 applique chaque écriture dans la
seconde ; `coupée`, ce que le pair écrit attend, et le curseur dira combien
quand la voie rouvrira. **À faire, pour que le client conclue depuis les
nombres** : rendre aussi la dernière estampille que CETTE racine a écrite
(`Entrepot::derniere_operation` n'en est qu'un majorant après un
redémarrage, et le journal ne la porte plus après un amorçage — il faut la
ranger) ; alors `applique` de l'une égale `ecrit` de l'autre, ou il manque
quelque chose.

**Sur la voie machine (`Exigence::Machine`), et non sans exigence.** La
vérification de déploiement — « un compte créé chez l'une est lu chez
l'autre » — demande une réponse au présent, qu'un journal ne donne qu'au
passé ; l'exploitant la pose depuis une machine enrôlée, ce qu'il a toujours
sous la main. **Elle ne se rend pas à un inconnu**, et la raison a tranché :
dire à qui le demande que la voie est coupée, c'est lui dire l'heure exacte où
une unicité — un alias — se gagne sur une racine isolée (§3.2). Une réclamation
en file n'est pas rien quand c'est un inconnu qui la pose. Le journal
d'exploitation dit la même chose, à qui sait lire la machine.

---

## 9. Ce que cela change ailleurs

| Document | Ce qui change |
|---|---|
| `annuaires.md` §3 | Renvoie ici pour le comment. Le tableau gagne les lignes que §1 ajoute — codes, descriptions, jetons, alias. |
| `annuaires.md` §6 | Le témoin devient une suite nommée, pas la v1 (§3.4). |
| `annuaires.md` §7 | Le point 3 — le transport — se ferme. |
| `protocole.md` | Une voie de plus, « la voie entre racines » : quatre verbes, un genre de défi, et un renvoi ici. |
| `modele.md` §2.7 | Un annuaire porte une clé d'identité, et son identifiant s'en déduit. |
| `modele.md` §2.9 | Entre racines, la provenance reste `locale`. |
| `modele.md` §2.10 (neuf) | L'estampille — une colonne de plus, sur le modèle de l'origine. |
| `journal.md` §2.2 | Ce qui se journalise d'une réplication entre racines. |
| `contraintes.md` C11, C17 | Ce que chacune devient entre racines (§7). |
| L'entrepôt (2026-09-18) | `révoqué le` sur l'appareil ; `effacé le` et la cause sur le compte ; le retrait de tout ce qu'un compte tient, dans une transaction — le balayage par compte que `oublier_ce_qui_vient_de` fait déjà par origine (C17). Un changement de format de plus, cran mineur, à porter par la PR de code du chantier « effacer mon compte ». |
| L'entrepôt | Trois choses de plus : l'estampille sur les enregistrements, le journal d'opérations, le curseur par pair. **C'est un changement de format d'enregistrement** — une rupture, et en 0.x une rupture est un cran MINEUR, comme la grammaire des outils l'a été ; le cran majeur est réservé au jour où la version dira « prêt ». À porter par la PR de code, avec la reprise des entrepôts existants (§11.4), pas par celle-ci. |

---

## 10. La table des décisions

| # | Décision | Statut |
|---|---|---|
| 1 | Le périmètre de §1 — y compris les codes d'enrôlement, les descriptions et les jetons ; le journal exclu. | **Décidé** |
| 2 | HTTP/3 sur QUIC, même port ; deux connexions, chacune ouverte par la racine qui tire. | **Décidé** |
| 3 | Une clé d'identité Ed25519 par racine, distincte de la clé TLS ; l'identifiant `n-…` se déduit de la clé. | **Décidé** (2026-09-15) |
| 4 | Les deux prouvent — `POST /v1/defi` avec un genre `n` dans un sens, `POST /v1/pair/preuve` dans l'autre. | **Décidé** (2026-09-15) |
| 5 | Keepalive et inactivité du daemon, reconnexion d'`asl-client`. | **Décidé** |
| 6 | Une écriture est acquittée par une racine, sans attendre l'autre. | **Décidé** |
| 7 | Les règles de conflit de §3.2 : révocation toujours, remplaçable au plus récent, unique au plus ancien. | **Décidé** |
| 8 | L'alias est une réclamation, et la file reste — plutôt qu'un perdant effacé. **Les applications relisent l'alias après un `PUT` et disent si le titulaire n'est pas elles.** | **Décidé** (2026-09-15) |
| 9 | Les effets vivants se rejouent, les notifications ne repartent pas. | **Décidé** |
| 10 | **Pas de témoin en v1** ; `annuaires.md` §6 devient une suite nommée. | **Décidé** (2026-09-15) |
| 11 | Horloge de Lamport `(compteur, racine)`, et non l'heure murale ; un seul nombre pour l'estampille et le curseur. | **Décidé** |
| 12 | Une estampille par enregistrement, et par champ là où `PATCH` est champ par champ. | **Décidé** |
| 13 | Le journal d'opérations dans l'entrepôt, dans la transaction d'écriture ; le format d'`asl-registre` sur le fil. | **Décidé** |
| 14 | Rétention du journal d'opérations : trente jours. | **Décidé** (2026-09-15) |
| 15 | `410` puis instantané pour l'amorçage ; l'instantané est une suite d'opérations et fusionne. **Émis par PARTS — un flux par part, borné à la fenêtre d'un flux —, appliquées par lots** (PR de code, 4/4). | **Décidé** |
| 16 | Les règles client de §6 — la connexion est la session ; `asl enroll` et le daemon essaient l'autre racine avant de conclure. | **Décidé** |
| 17 | La provenance d'un enregistrement répliqué entre racines reste `locale`. | **Décidé** (2026-09-15) |
| 18 | Rompre la réplication n'efface rien. | **Décidé** |
| 19 | `--identity-key`, `--peer`, `--peer-key` ; `--new-identity-key` pour générer. **`--peer-ca` ajouté par la PR de code (0.7.0)** : valider le certificat TLS du pair demande son autorité, que sa chaîne ne porte pas. | **Décidé** (2026-09-15) — `--identity-key`, parce que c'est une clé privée ; `--peer-ca` amendé (2026-09-16) |
| 20 | `GET /v1/replication`, **sur la voie machine** — pas sans exigence : l'état de la voie dit à un inconnu quand une unicité se gagne. **La réponse : `voie` vaut `ouverte`, `coupée` ou `seule` ; `seule` n'a ni `pair` ni `applique`** (PR de code, 4/4). | **Décidé** (2026-09-15), amendé |
| 21 | **La reprise d'un entrepôt sans identité : ré-estampillage sous l'identité réelle au premier démarrage avec une clé, une fois, dans une transaction** (§11.4). | **Décidé** (2026-09-16) |
| 22 | **L'effacement d'un compte se réplique, comme une révocation** : l'opération `compte-efface` (identifiant, date, cause) gagne sur toute écriture concurrente du même compte, se rejoue comme effet vivant chez l'autre, sans notification ; une écriture arrivée après est refusée, le curseur avance. C'est la seule opération qui efface physiquement ; la marque du compte reste, et c'est elle qui figure dans l'instantané. `appareil-revoque` porte désormais `révoqué le`. | **Décidé** (2026-09-18, Thierry) |
| 23 | **La règle des orphelins** : un compte sans aucun appareil vivant — tous révoqués, jamais « silencieux » (C6) — est effacé par la racine **trente jours** après la révocation du dernier, cause `orphelin`, journalisé ; `--orphans <days>`, `0` = jamais, même valeur sur les deux racines ; chacune peut écrire, la première fait appliquer l'autre. | **Décidé** (2026-09-18, Thierry) — la règle plutôt qu'un verbe d'exploitant |
| 24 | **`asl-server --forget <u-…>`**, hors ligne, entrepôt arrêté, un identifiant à la fois, cause `exploitant`, journalisé : l'exception pour « la clé est perdue et l'on le sait », pas un outil de modération. Couvre les trois orphelins de `nitrogen` que la règle n'attrape pas. | **Décidé** (2026-09-18) |
| 25 | **L'attestation d'un appareil qui rejoint se réplique comme un fait sur la clé** : l'opération `appareil-atteste` (identifiant, attestation) ne va que d'`aucune` ou `attendue` vers une valeur prouvée, s'applique toujours — révoqué ou non, pour converger quel que soit l'ordre —, et rend vivant chez l'autre racine un appareil qu'elle tenait `attendue`. `attendue` est une valeur d'`attestation` portée par l'opération `appareil` (format, cran mineur à la PR de code) ; elle ne s'expire pas. Le défi de la chaîne n'est pas répliqué : il vit dans la connexion du nouvel appareil, et la preuve se fait là. | **Décidé** (2026-09-21) |
| 26 | **La posture `invitation` est servie, et son code se réplique comme celui d'un enrôlement** : opérations `invitation` (empreinte, expiration) et `invitation-consommee` (empreinte, toujours appliquée). L'émission passe par `POST /v1/invitations`, sur l'annuaire EN MARCHE, sous la clé de `--operator-key` (genre `o`, preuve dans le corps, sans identifiant) — un outil hors ligne aurait exigé d'arrêter le service à chaque arrivant, l'entrepôt n'ayant qu'un écrivain. **Un même code consommé des deux côtés de la fenêtre donne deux comptes, et on ne les départage pas** : deux comptes ne se disputent rien, et un effacement automatique sur une course serait une arme. Le journal le dit ; l'exploitant tranche. | **Décidé** (2026-09-24) |

---

## 11. Ce qui reste ouvert

1. **Le journal des requêtes vu d'un utilisateur, à deux racines** (§1) : « qui
   a résolu mes services » est une réponse par racine. À trancher quand le
   verbe s'écrira.
2. **Le débit du flux.** Rien ne borne ce qu'une racine peut faire lire à
   l'autre. Entre deux machines de la même autorité, ce n'est pas une attaque ;
   ce sera une question le jour où la voie servira entre pairs (§5
   d'`annuaires.md`).
3. **Une troisième racine.** Rien ici ne suppose qu'elles sont deux — l'ordre
   des estampilles et les curseurs par pair s'étendent —, mais rien ne l'a
   éprouvé, et « pas de réplication transitive » demanderait alors que chacune
   tire chez chacune.
4. **La reprise d'un entrepôt existant — DÉCIDÉ (PR de code, 4/4).** Les bancs
   tournent en 0.4.x avec des bases sans estampille ni journal. La reprise a
   deux temps, et les deux sont dans `asl-store` :

   - **À la première ouverture d'une base ancienne** (PR 1), chaque
     enregistrement reçoit une estampille en séquence, sous la racine qui
     ouvre ; les index absents à l'époque — `AUTORISATIONS_ACCORDEES`,
     `MACHINES_PAR_COMPTE`, `APPAREILS_PAR_COMPTE` — sont reconstruits, et le
     journal d'opérations démarre vide, marqué retiré jusqu'au compteur (une
     base reprise s'amorce chez l'autre par instantané, jamais par
     rattrapage). Tout cela dans une transaction : une reprise interrompue n'a
     pas eu lieu.
   - **Tant qu'un banc n'a pas de `--identity-key`**, il estampille sous
     `RACINE_SANS_IDENTITE` — `n-` seize zéros, qui ne se déduit d'aucune clé
     et ne sera jamais celui d'une racine réelle. **Au premier démarrage AVEC
     une clé**, tout ce qui portait cette racine — enregistrements, champs,
     réclamations d'alias, opérations du journal — passe sous l'identité
     réelle, le compteur gardé, une fois, dans une transaction ; le journal
     d'exploitation le dit avec le nombre. Sans cela, seize zéros partiraient
     sur la voie, et l'autre racine les ré-estampillerait sous SON identité au
     redémarrage suivant — deux estampilles pour un même fait, et la règle de
     conflit ne calculerait plus la même chose des deux côtés.

   - **La reprise au format des dates (0.11.0, PR de code « effacer mon
     compte »)** suit le même modèle : à la première ouverture d'une base de
     0.5.0 à 0.10.1, le compte et l'appareil sont réécrits sous leur forme
     nouvelle dans une transaction — `effacé le` vide partout, `révoqué le`
     posé à la date de la reprise sur les appareils déjà révoqués
     (`modele.md` §2.2, C6) —, les estampilles et le curseur du pair ne
     bougent pas, **et le journal d'opérations est vidé, marqué retiré
     jusqu'au compteur** : ce qu'il portait est de la forme d'hier, que
     l'autre racine ne saurait plus lire, et elle s'amorce par instantané au
     rattrapage suivant. Le temps que les deux bancs soient à la même
     version, la voie est coupée — une opération du nouveau format ne se
     décode pas avec l'ancien, et c'est dit, jamais sauté (§5.2) ; elle se
     rouvre d'elle-même au second déploiement.

   **Ce que l'exploitant verra, et qui n'est pas un défaut.** Les deux bancs
   ont créé des comptes chacun de son côté, avec des identifiants tirés
   indépendamment : ce sont des comptes DIFFÉRENTS pour les mêmes personnes. La
   réplication ne les fusionne pas — un identifiant à 128 bits ne collisionne
   pas —, elle les additionne. Après la première synchronisation, une personne
   inscrite sur les deux bancs a deux comptes, chacun avec ses machines. Ce qui
   est départagé est l'unicité : un alias réclamé des deux côtés va au plus
   ancien (§3.2), et le perdant garde sa réclamation en file. Aucune donnée
   n'est perdue ; c'est une information pour le déploiement, pas un blocage.
