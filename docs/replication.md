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
| Descriptions d'appareils, points de poussée | **Oui** | Une autorisation accordée chez l'une — un droit accordé, ou un ajout à un groupe qui en porte, depuis le 2026-09-26 — réveille les appareils du bénéficiaire depuis celle-là (décision 9) ; le point doit être là où la notification part. La description suit l'appareil qu'elle décrit. Ce qu'une racine apprend d'un point à l'envoi — qu'il est mort, qu'il a trop reçu — ne se réplique pas (décision 27). |
| Machines — nom, capacités, propriétaire, clé publique | **Oui** | Une machine enrôlée chez l'une annonce chez l'autre à la première bascule. |
| **Codes d'enrôlement en attente** | **Oui** | L'application émet le code chez une racine ; `asl enroll` le présente à celle que l'alias lui donne. Sans réplication, un code sur deux serait « inconnu ». Le code est un secret partagé, court, à usage unique (`modele.md` §2.3) — c'est son EMPREINTE qui circule, comme sur le disque, et le disque de l'autre racine n'est pas moins sûr que le nôtre. |
| **Invitations en attente** (posture `invitation`, `protocole.md` §2.2) | **Oui** | Même raison, mot pour mot, que les codes d'enrôlement : l'alias donne une racine au hasard, et un code qui ne vaudrait que chez celle qui l'a émis serait inconnu une fois sur deux. C'est l'empreinte qui circule. **Mais la conséquence d'une double consommation n'est pas la même, et elle est traitée en §3.2 : deux comptes, qu'on ne départage pas.** |
| Services **déclarés** — identifiant, machine, nom | **Oui** | Un service est identifié par `(machine, nom)`, et **son `s-…` en est dérivé** (0.37.0, décisions 66 et 72 ; `modele.md` §2.4) : le client qui a mémorisé un `s-…` le retrouve après bascule, dans une paire d'annuaire local comme entre racines. Jusqu'à la 0.36.0, un aléa attribué à la première annonce, que la paire ne tenait pas (constaté le 2026-09-28 : `annuaires.md` §2 ter). |
| Autorisations, et leurs révocations — **des droits depuis le 2026-09-26** (décision 41) | **Oui** | C'est ce qui ouvre la résolution ; il doit être vu de la racine qui résout. |
| **L'effacement d'un compte** — par son titulaire, par la règle des orphelins, ou par l'exploitant (`modele.md` §2.1) | **Oui** | Un compte effacé chez l'une doit l'être chez l'autre, avec tout ce qu'il tenait ; et c'est la marque « effacé » qui circule, pour que l'autre refuse ce qui arriverait en retard (§3.2). |
| **Domaines** — propriétaire, alias, hébergeur ; **le rattachement des machines** ; **les groupes, leurs membres, les droits** (2026-09-26) | **Oui** | Écrits aux racines depuis les applications (`annuaires.md` §2 bis) : ce sont des décisions du compte, et l'une ou l'autre racine les reçoit selon le tirage de l'alias. |
| **Inscriptions d'annuaires locaux**, leur code, leur décision, leur retrait (2026-09-26) — le groupe des administrateurs des racines est désormais celui du domaine racine, et voyage comme les autres groupes | **Oui** | Un administrateur accepte chez l'une une inscription déclarée chez l'autre ; l'annuaire local se connecte aux deux, et les deux doivent le reconnaître. |
| **L'état vivant des services fédérés** — adresse, port, vivant (`annuaires.md` §5.4) | **NON** | Chaque racine le reçoit **directement de l'annuaire local**, qui tient une connexion vers chacune. C'est de l'observé : il vit en mémoire, comme un bail, et la règle de tête de ce tableau s'applique. |
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

**Depuis le 2026-09-27 (décision 53), le certificat lui-même est celui de la
clé d'identité**, auto-signé : le second temps (`POST /v1/pair/preuve`) reste,
mais la poignée de main TLS ne passe plus par une autorité — `--peer-ca`
est devenu superflu, et a été retiré en 0.34.0 (décision 63).

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
| **Une révocation d'un côté, une écriture de l'autre** — appareil, clé de machine, autorisation | **La révocation l'emporte toujours.** Elle nomme ce qu'elle révoque — CET appareil, CETTE clé, CETTE autorisation — et s'applique quel que soit l'ordre. Une écriture sur l'objet révoqué arrivée après est refusée comme elle le serait localement ; arrivée avant, la révocation la couvre. | Un point de poussée déposé pendant la fenêtre, une capacité changée. Rien qu'on regrette : une révocation est irréversible par construction, et ce qu'on écrivait sur l'objet ne valait plus. |
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
| **Le même service déclaré des deux côtés** — un daemon bascule pendant une coupure et réannonce `(machine, nom)` chez l'autre, qui lui attribue un second `s-…` | **Le plus ancien gagne, l'autre s'efface.** Un service ne bouge jamais et ne se retire jamais ; les deux racines finissent donc avec le même, dans tous les ordres. | Un `s-…` qu'un client a pu voir disparaît. Les clients résolvent par le NOM (`protocole.md` §3), et l'identifiant n'est qu'attribué à la première annonce : la perte est un identifiant, pas un service. **« Le plus ancien » est la plus petite estampille de Lamport**, et entre deux écritures qui ne se sont pas vues elle ne dit rien du temps : le 2026-09-28, dans la paire speedy/helium, le `s-…` servi depuis la veille a perdu contre celui d'un membre au compteur presque vierge (`annuaires.md` §2 ter). **Décidé (2026-09-28, Thierry ; décision 66), fait en 0.37.0** : un `s-…` dérivé de `(machine, nom)` — pour tous les services (décision 72) —, **et ce conflit disparaît** : les deux côtés écrivent le même `s-…`, et l'enregistrement garde la plus petite estampille ; une opération d'un pair encore en 0.36.0 se range sous le dérivé (§11, point 5). **Depuis la 0.36.0 (décision 69)**, la session vivante d'un daemon connecté sous le perdant passe sous le gagnant — il n'est plus rapporté `parti` —, et chez un membre d'annuaire local, l'opération d'une machine pas encore reçue des racines attend sa machine au lieu d'être perdue. |
| **Une description ou un jeton déposés des deux côtés** | Le plus récent gagne — la règle locale, « le neuf remplace l'ancien ». | Une étiquette. |
| **Un appareil attesté d'un côté, révoqué de l'autre** — le nouveau téléphone prouve chez `argon` pendant que l'ancien le révoque chez `nitrogen` (2026-09-21) | **Les deux s'appliquent, quel que soit l'ordre.** L'attestation est un fait sur la clé — elle ne va que d'`aucune` ou `attendue` vers une valeur prouvée, jamais en arrière — et la révocation un fait sur l'appareil ; ils ne se contredisent pas, et les deux racines finissent avec `android, révoqué`. Ne pas poser l'attestation sur un appareil révoqué aurait fait diverger la valeur selon l'ordre d'arrivée. | Rien : l'appareil est révoqué, et sa connexion fermée par la révocation (§3.3). Que sa clé ait été attestée est ce que l'écran d'après une perte montre, comme le modèle. |
| **Les domaines** (2026-09-26) — un alias posé des deux côtés ; une machine rattachée à deux domaines des deux côtés ; un hébergeur changé des deux côtés | **Le plus récent gagne** : l'alias de domaine n'est pas unique (`modele.md` §2.11), il se remplace comme un nom ; le rattachement d'une machine est UN champ de la machine, et le dernier dit où elle est ; l'hébergeur aussi. **Ni l'alias ni le rattachement ne regardent si le domaine visé est mort** (décision 42) : ils restent rangés selon leur seule règle, et c'est le LECTEUR qui écarte ce qui vise un domaine supprimé ou effacé. Une suppression n'écrit donc rien sur les machines ni sur l'alias — une écriture sous son estampille dépendrait de laquelle des deux racines l'a voulue la première. | Un alias, un déplacement ou une bascule d'hébergeur écrits dans la fenêtre. Ils se réécrivent. |
| **Un membre retiré d'un côté, ajouté de nouveau de l'autre** — ou retiré pendant qu'il rattache sa machine (2026-09-26) | **Chaque ajout est un fait, et un retrait nomme l'ajout qu'il retire** : l'opération de retrait porte l'estampille de l'ajout visé. Elle s'applique toujours à CET ajout, et jamais à un ajout plus récent — un compte retiré puis réajouté est membre, dans tous les ordres. Retirer celui qui tenait `rattacher` détache ses machines du domaine (décidé : Thierry). | Un rattachement fait dans la fenêtre, défait. |
| **Un droit retiré d'un côté** (2026-09-26) | **Toujours**, comme une révocation. Un droit ne se modifie pas : on le retire et on en accorde un autre, avec un nouveau `g-…`. | Rien qu'on regrette. |
| **Un groupe supprimé d'un côté pendant qu'on y ajoute un membre ou qu'on lui accorde un droit de l'autre** | **La suppression l'emporte**, et emporte ce qui est arrivé pour lui, dans tous les ordres : un groupe supprimé est marqué, et ce qui le vise ensuite est refusé (§3.2). | Un ajout ou un droit dans la fenêtre. |
| **Une inscription acceptée d'un côté, refusée de l'autre** — deux administrateurs, deux racines, la même minute | **Le refus l'emporte** (décidé le 2026-09-26, Thierry). Accepter donne aux racines une parole à répéter ; refuser ne coûte qu'une nouvelle demande. Dans le doute, on ne sert pas. **Une décision est donc définitive pour CETTE inscription** : un refus, où qu'il arrive, l'emporte sur toute acceptation, dans tous les ordres ; redemander, c'est déclarer une nouvelle inscription, avec un nouveau code. | Une acceptation, qui se redemande par une nouvelle inscription. |
| **Une inscription retirée, ou un administrateur retiré, d'un côté** | **Toujours** : ce sont des révocations. Une inscription retirée ferme la voie de l'annuaire local sur les deux racines (§3.3). | Rien qu'on regrette. |
| **Le dernier domaine d'un compte supprimé d'un côté pendant qu'un autre l'est de l'autre** | Chaque racine refuse localement de supprimer le dernier ; mais deux suppressions de deux domaines différents, chacune acceptée là où il en restait deux, laisseraient le compte sans domaine. **« Refuser la seconde arrivée » dépendrait de l'ordre, et les deux racines garderaient chacune un domaine différent** — l'écueil exact de §3.1. La règle est donc une fonction de l'ENSEMBLE des suppressions : **si elles laissaient le compte sans domaine, celui des domaines supprimés dont l'estampille de création est la plus petite reste**, et sa suppression est sans effet. Les deux racines calculent le même survivant, dans tous les ordres (décidé le 2026-09-26, Thierry). **Il se CALCULE à la lecture, et ne s'écrit jamais** (décision 42, PR de code) : une marque ne s'efface pas, et un domaine est vivant s'il n'est pas marqué, ou si tous ceux de son compte le sont et qu'il est le plus ancien. « Ranimer » le survivant en effaçant sa marque n'était pas une fonction de l'ensemble — un domaine né de l'autre côté pendant la fenêtre, arrivé avant ou après la réanimation, laissait deux états. Deux suppressions du MÊME domaine gardent la plus petite estampille, comme deux effacements d'un compte. | Une suppression, qui se refera ; l'application relit ses domaines après un `DELETE` et voit lequel est resté. |

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
| `poussee` | appareil ‖ jeton | **Plus écrite depuis la 0.19.0** (décision 27) : lue encore, pour un journal qui la porterait ; le plus récent, refusé si l'appareil est révoqué. |
| `point-de-poussee` | appareil ‖ point ‖ clé et secret facultatifs | Le plus récent ; refusé si l'appareil est révoqué. Genre **20**. |
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

**Les genres du 2026-09-26 — les domaines, les groupes, les droits** (décidés ;
les numéros se fixent aux PR de code, après le genre 20 — **`domaine` 21,
`domaine-supprime` 22, `domaine-alias` 23, `machine-domaine` 24**, fixés par la
PR du socle, 0.23.0 ; **`groupe` 25, `groupe-etiquette` 26, `groupe-membre` 27,
`groupe-membre-retire` 28, `groupe-supprime` 29**, fixés par la PR des groupes,
0.24.0 ; **`droit` 30, `droit-retire` 31**, fixés par la PR des droits, 0.25.0 ;
**`machine-alias` 32**, fixé par la PR des alias, 0.26.0 ; **`inscription` 33,
`inscription-presentee` 34, `inscription-decision` 35, `inscription-retiree`
36, `domaine-hebergeur` 37**, fixés par la PR de l'inscription, 0.27.0 ;
**`inscription-locateurs` 38**, fixé par la PR des locateurs, 0.30.0) :

| Genre | Charge | Règle d'application |
|---|---|---|
| `domaine` (21) | identifiant ‖ domaine (provenance ‖ naissance ‖ propriétaire ‖ marque) | Insérer si absent ; refusé pour un compte effacé. **Le premier domaine d'un compte ne voyage PAS par elle** (décision 42) : son identifiant se déduit du `u-…`, et chaque racine le fait naître en appliquant l'opération `compte`, sous l'estampille du compte — le même enregistrement des deux côtés, sans opération de plus. L'instantané l'émet quand même, avec les autres : il rend l'état. |
| `domaine-alias` (23) | domaine ‖ alias posé (provenance ‖ estampille ‖ alias NFC ou rien) | Le plus récent, **mort ou vif** ; ignoré pour un domaine inconnu — effacé avec son compte, il ne revient pas par son alias. Un alias qui n'est pas son propre NFC est refusé à la relecture (`Faute::NonNormalise`). |
| `domaine-supprime` (22) | domaine | **Toujours** : marquer supprimé, ou garder la plus petite marque. Rien d'autre ne s'écrit. **La vie se lit** (décision 42) : vivant s'il n'est pas marqué, ou si tous les domaines du compte le sont et qu'il est le plus ancien — la plus petite estampille de naissance. Une fonction de l'ensemble, pas de l'ordre (§3.1, §3.2). |
| `groupe` (25) | `e-…` ‖ groupe (provenance ‖ naissance ‖ sorte ‖ domaine ‖ estampille de l'étiquette ‖ étiquette) | Insérer si absent, l'étiquette au plus récent. **Seulement un groupe créé**, dans un domaine connu — mort ou vif : un domaine effacé avec son compte ne revient pas par ses groupes. Le groupe d'administrateurs d'un domaine et le groupe personnel d'un compte ne voyagent PAS : leurs identifiants se déduisent (`modele.md` §2.12), et chaque racine les fait naître avec le domaine ou le compte, sous son estampille (décision 43). |
| `groupe-etiquette` (26) | `e-…` ‖ étiquette | Le plus récent ; ignoré pour un groupe inconnu ou déduit. |
| `groupe-membre` (27) | `e-…` ‖ compte | Insérer l'ajout, **nommé par l'estampille de l'opération**. Refusé pour un compte effacé, un groupe marqué, inconnu ou personnel. Le propriétaire d'un domaine est membre d'office de son groupe d'administrateurs, sans opération. |
| `groupe-membre-retire` (28) | `e-…` ‖ compte ‖ estampille de l'ajout | **Toujours** — l'ajout nommé, et lui seul (§3.2) : la plus petite estampille de retrait ; **un retrait arrivé avant son ajout se range quand même**, et l'ajout, quand il arrive, trouve sa place prise. ~~Si le compte n'a plus `rattacher` sur un domaine où il a des machines, les détacher.~~ **Le détachement se LIT** (décision 43). Refusé pour le propriétaire dans son groupe d'administrateurs. |
| `groupe-supprime` (29) | `e-…` | **Toujours** : la marque, la plus petite, jamais effacée — **posée même pour un groupe encore inconnu** —, et ses adhésions retirées ; ce qui arrive ensuite pour lui est refusé. Refusé pour un groupe d'administrateurs ou un groupe personnel, qui ne partent qu'avec leur domaine ou leur compte. |
| `droit` (30) | `g-…` ‖ droit (provenance ‖ estampille ‖ accordé par ‖ groupe ‖ élément ‖ droits (1, un bit par droit) ‖ retrait ‖ étiquette) | Insérer si absent. **Refusé pour ce qui ne revient jamais** : un donneur effacé, un groupe marqué ou inconnu, un élément inconnu — compte effacé, domaine, machine ou service absent — et le domaine racine (décision 44). Un ensemble vide, ou `administrer`/`rattacher` ailleurs que sur un domaine, est refusé à la relecture. **Remplace `autorisation`** (décision 41) ; `autorisation` (13) reste lue, pour un journal d'avant la conversion, et **convertie à l'application** par la fonction de la reprise. |
| `droit-retire` (31) | `g-…` | **Toujours** : la plus petite estampille de retrait ; rien pour un droit inconnu. **Remplace `autorisation-revoquee`** (14), lue de même. |
| `machine-alias` (32) | machine ‖ alias posé (provenance ‖ estampille ‖ alias NFC ou rien) | Le plus récent — un champ de la machine, rangé à part comme le rattachement ; ignoré pour une machine inconnue (effacée avec son compte). Décision 47. |
| `machine-domaine` (24) | machine ‖ rattachement (provenance ‖ estampille ‖ domaine ou rien) | Le plus récent — un champ de la machine, avec son estampille, comme le nom et les capacités ; ignoré pour une machine inconnue. **Le domaine visé n'est pas regardé** : mort, inconnu ou vif, c'est le lecteur qui en décide. |
| `inscription` (33) | empreinte du code ‖ déclaration (provenance ‖ estampille ‖ propriétaire ‖ titulaire ou rien ‖ expire le (8) ‖ adresse) | Insérer si absente. **Rien d'autre ne se juge à l'application** : un propriétaire effacé, un titulaire refusé se LISENT (décision 51). |
| `inscription-presentee` (34) | empreinte du code ‖ présentation (provenance ‖ estampille ‖ `n-…` ‖ clé d'identité) | **La plus petite estampille** : deux clés qui présentent le même code dans la fenêtre, la première gagne, des deux côtés ; la perdante n'est membre de rien. |
| `inscription-decision` (35) | `n-…` ‖ accepte ou refuse (1) ‖ administrateur | **Toujours** : la plus petite estampille de sa sorte, acceptation et refus rangés à part. **Le refus l'emporte à la lecture** (décision 51). |
| `inscription-retiree` (36) | `n-…` ‖ par | **Toujours** : la plus petite estampille. Le retrait l'emporte sur tout ; retirer le titulaire retire l'annuaire entier, son second avec lui, **à la lecture** — et ses domaines reviennent aux racines, à la lecture aussi. |
| `domaine-hebergeur` (37) | domaine ‖ hébergement (provenance ‖ estampille ‖ `n-…` ou rien) | Le plus récent, **quel que soit l'annuaire nommé** : qu'il soit accepté, vivant et du même propriétaire que le domaine se lit (décisions 48, 51). |
| `inscription-locateurs` (38) | `n-…` ‖ locateurs (provenance ‖ estampille ‖ combien (1) ‖ quatre adresses, les inutilisées nulles) | Le plus récent, **par membre, quel que soit son état** : qu'il soit accepté se lit, et un membre retiré n'est plus rendu nulle part (décision 57). **Vide, c'est un retrait**, qui garde son estampille : l'adresse déclarée à l'inscription sert de nouveau, à la lecture. Une publication identique à la rangée n'écrit rien. |
| ~~`administrateur` / `administrateur-retire`~~ | ~~compte~~ | **Remplacés** par `groupe-membre` / `groupe-membre-retire` sur le groupe d'administrateurs du domaine racine, dont l'identifiant se déduit ; acceptés seulement sous la clé d'exploitant (décision 37). |

**`compte-efface` en retire davantage** : ses domaines et leurs groupes, son
groupe personnel, son appartenance aux autres groupes, les droits qu'il a
accordés et ceux que ses groupes recevaient, ses inscriptions ; les machines
d'autres comptes rattachées à ses domaines sont **détachées**, pas retirées
(`modele.md` §2.11) — **à la lecture** (décision 42) : leur rattachement reste
rangé et désigne un domaine qui n'existe plus, que le lecteur écarte. Un
détachement écrit sous l'estampille de l'effacement dépendrait de laquelle des
deux racines l'a voulu la première ; le premier essai de convergence l'a
montré.

**Les comptes d'avant les domaines** reçoivent leur premier domaine à la
reprise de l'entrepôt, avec un identifiant **déduit** du `u-…` : les deux
racines font la reprise chacune de son côté et arrivent au même `d-…`, sans
opération à échanger (décidé le 2026-09-26, Thierry, `modele.md` §2.11). **Sous
l'estampille du compte**, pas une neuve : c'est ce qui fait que les deux
enregistrements sont les mêmes octet pour octet. **Cette reprise-là ne vide
pas le journal** (PR du socle, 0.23.0) : elle n'écrit rien qu'une opération
reçue ferait autrement, et les deux racines la font à l'identique. **Les deux
racines se déploient ensemble** : une racine d'avant refuserait les genres 21
à 24, et fermerait la voie en le disant (comme pour le genre 20, décision 27).
**La reprise des groupes déduits** (0.24.0) fait naître le groupe personnel de
chaque compte vivant et le groupe d'administrateurs de chaque domaine rangé —
identifiants déduits, sous leur estampille —, une fois, et **elle ne vide pas
le journal** non plus, pour la même raison ; les genres 25 à 29 demandent de
même que les deux racines se déploient ensemble. **La conversion des
autorisations en droits** (0.25.0), sous le même `g-…` (`modele.md` §2.13), est
une fonction des seuls octets de chaque autorisation, et les deux racines
arrivent au même enregistrement ; **elle ne vide pas le journal** non plus
(décision 44) — ce qui était prévu ici, par prudence, ne sert à rien : une
opération `autorisation` encore au journal de l'autre racine se convertit à
l'application par la même fonction. Les genres 30 et 31 demandent, eux aussi,
que les deux racines se déploient ensemble.

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

**Une opération que l'on ne peut pas encore appliquer ne retient pas le
curseur** (0.36.0, décision 69). Entre les deux membres d'une paire, une
opération `service` peut arriver avant sa machine, que chaque membre tire des
racines par sa propre voie. Retenir le curseur jusqu'à ce que la machine
arrive figerait tout le flux derrière une opération qui, si la machine ne
vient jamais (sortie de nos domaines), ne s'appliquerait jamais. Elle est donc
**gardée à part** (`services-en-attente`, une par `(machine, nom)`), le curseur
avance, et elle est **rejouée** quand la machine arrive. Le curseur dit ainsi
« appliqué ou gardé » — jamais « perdu ». Chez une racine, la machine d'un
service arrive toujours avant lui dans le journal du pair ; une machine
inconnue y est une machine effacée, et l'opération s'ignore, comme avant.

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

**La racine tirée le lit HORS de sa boucle (décision 28).** La lecture reste
une seule transaction, mais elle se fait sur un fil à part : la réponse `200`
part aussitôt, le flux reste ouvert et vide le temps de la lecture, puis porte
ses parts comme ci-dessus. Pendant ce temps, la boucle continue de servir
toutes les autres connexions. Une lecture qui échoue ferme le flux vide, et le
tireur reprend ; une connexion tombée entre-temps voit sa lecture jetée.

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
```

**Ils vont ensemble** : `--peer` sans `--peer-key` refuse de démarrer, parce
qu'une adresse seule n'est pas une racine (`annuaires.md` §2). Sans `--peer`, la
racine tourne seule et le journal d'exploitation le dit au démarrage — ce n'est
pas un défaut, c'est un banc.

**`--peer-ca` a vécu de 0.7.0 à 0.34.0** — gardé ici comme histoire. **Il
avait été ajouté par la PR de code (0.7.0), et §8 ne l'avait pas prévu.** La clé d'identité (`--peer-key`) est l'ancre de l'AUTHENTIFICATION —
le pair prouve la clé qu'on tient de lui, liée au canal (§2.2). Mais pour
OUVRIR la connexion TLS, le tireur doit valider le certificat que le pair
présente, et la chaîne qu'un serveur montre (`--certificate`) ne porte pas la
racine qui l'a signée (`scripts/ca.sh` : « le certificat, puis rien »).
`--peer-ca` est cette racine-là — le `racine.crt` de la cérémonie, celui-là
même que le client épingle. C'est le certificat de plus que §2.2 disait ne pas
vouloir ; ce n'en est pas un « par pair », c'est l'autorité commune, et
l'authentification reste la clé d'identité, pas lui. **Depuis la décision 53,
la clé d'identité fait AUSSI la poignée de main**, et `--peer-ca` n'avait plus
rien à valider : il est refusé depuis 0.34.0 (décision 63).

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
{"pair": "n-…", "voie": "ouverte", "compteur": 4812, "ecrit": 4801, "applique": 4790}
```

**La forme exacte, décidée par la PR de code (4/4).** Le corps est du JSON, et
le champ `voie` prend l'une de trois valeurs — un mot qu'on lit d'abord, dont
les autres champs découlent :

- `"ouverte"` — la connexion sortante vers le pair est ouverte et prouvée dans
  les deux sens en ce moment ;
- `"coupée"` — il y a un pair réglé, mais la connexion n'est pas établie (le
  pair est parti, ou la voie est rompue et la reprise rappelle) ;
- `"seule"` — **aucun pair n'est réglé** : la racine tourne seule, et le corps
  est alors `{"voie": "seule", "compteur": 4812, "ecrit": 4801}`, **sans `pair`
  ni `applique`** — il n'y a personne dont on applique quoi que ce soit, et un
  champ nul aurait l'air d'une valeur. **`ecrit`, lui, est rendu dans les deux
  formes** : une racine seule écrit comme une autre, et ce qu'elle a écrit est
  précisément ce qu'un futur pair devra rattraper.

`compteur` est l'horloge de Lamport de cette racine (§4) ; `ecrit` est la
dernière estampille qu'elle a écrite ELLE-MÊME ; `applique` est le curseur
qu'elle tient pour le pair (§5.3) — l'estampille de la dernière opération
ÉCRITE PAR LE PAIR qu'elle a appliquée. Les trois nombres et le mot se lisent
de l'entrepôt et du tireur au moment de la requête — rien n'est recopié, donc
rien ne vieillit.

**`compteur` et `applique` ne se soustraient pas, et ce document l'a d'abord
dit de travers** (« `applique` rejoint `compteur` du pair en moins d'une
seconde », corrigé le 2026-09-21, sur le banc). L'horloge d'une racine se
hisse aussi sur ce qu'elle REÇOIT (§4) ; le curseur que l'autre tient pour
elle ne suit que ce qu'elle ÉCRIT. Après l'amorçage du 19/09, `nitrogen` a
écrit douze fois et `argon` rien : les deux horloges disaient 35, `nitrogen`
tenait pour `argon` un curseur à 23 — et rien n'était en retard. **C'est
précisément l'écart que `ecrit` comble** : `argon` disait `compteur: 35` et
n'avait rien écrit ; il dit désormais `ecrit: 23`, et le curseur de `nitrogen`
l'égale. La même journée se lit maintenant sans qu'il faille connaître
l'histoire des deux bancs.

**Ce qui se conclut, des deux côtés** : `applique` de l'une égale `ecrit` de
l'autre ⇒ **tout ce que l'autre a écrit est appliqué ici** ; en dessous, il
manque exactement la différence, et on peut enfin la nommer. `applique` ne
dépasse jamais `ecrit` du pair — le dépasser voudrait dire qu'on a appliqué ce
qui n'a pas été écrit. La voie reste ce qui dit l'ALLURE : `ouverte` des deux
côtés, le flux de §5.3 applique chaque écriture dans la seconde, et un écart
se referme tout seul ; `coupée`, ce que le pair écrit attend, et l'écart dit
combien attend.

`ecrit` est **rangé, et non déduit** — c'est ce qui le rend juste quand on en
a le plus besoin. Le compteur de la dernière opération journalisée
(`Entrepot::derniere_operation`) repart de l'horloge à chaque ouverture et
n'en est qu'un majorant ; le journal, lui, s'expire à trente jours (§5.4) et
ne porte plus rien après un amorçage par instantané. La valeur est donc écrite
dans la transaction même qui écrit ce qu'elle compte, et un instantané qui
nous rend NOS PROPRES estampilles la hisse aussi — sans quoi une racine
amorcée dirait n'avoir jamais rien écrit, et son pair chercherait une panne
qui n'existe pas. Une base d'avant la retrouve à l'ouverture, depuis son
journal et sa borne d'expiration ; ce n'est pas une reprise de format.

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
| `modele.md` §2.11, §2.12 ; `annuaires.md` §2 bis, §4.1, §5.4, §8 ; `protocole.md` §2.2, §3 ter ; `contraintes.md` C11, C13 (2026-09-26) | Les domaines, le groupe des administrateurs, l'annuaire local : décisions 30 à 36. |
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
| 20 | `GET /v1/replication`, **sur la voie machine** — pas sans exigence : l'état de la voie dit à un inconnu quand une unicité se gagne. **La réponse : `voie` vaut `ouverte`, `coupée` ou `seule` ; `seule` n'a ni `pair` ni `applique`** (PR de code, 4/4). **Et `ecrit`, la dernière estampille que cette racine a écrite elle-même, rendu dans les deux formes** (2026-09-24) : sans lui, `applique` ne se conclut pas — le compteur d'une racine se hisse aussi sur ce qu'elle reçoit, et rien ne disait ce qu'elle avait écrit. `applique` de l'une égale `ecrit` de l'autre ⇒ tout est appliqué. | **Décidé** (2026-09-15), amendé deux fois |
| 21 | **La reprise d'un entrepôt sans identité : ré-estampillage sous l'identité réelle au premier démarrage avec une clé, une fois, dans une transaction** (§11.4). | **Décidé** (2026-09-16) |
| 22 | **L'effacement d'un compte se réplique, comme une révocation** : l'opération `compte-efface` (identifiant, date, cause) gagne sur toute écriture concurrente du même compte, se rejoue comme effet vivant chez l'autre, sans notification ; une écriture arrivée après est refusée, le curseur avance. C'est la seule opération qui efface physiquement ; la marque du compte reste, et c'est elle qui figure dans l'instantané. `appareil-revoque` porte désormais `révoqué le`. | **Décidé** (2026-09-18, Thierry) |
| 23 | **La règle des orphelins** : un compte sans aucun appareil vivant — tous révoqués, jamais « silencieux » (C6) — est effacé par la racine **trente jours** après la révocation du dernier, cause `orphelin`, journalisé ; `--orphans <days>`, `0` = jamais, même valeur sur les deux racines ; chacune peut écrire, la première fait appliquer l'autre. | **Décidé** (2026-09-18, Thierry) — la règle plutôt qu'un verbe d'exploitant |
| 24 | **`asl-server --forget <u-…>`**, hors ligne, entrepôt arrêté, un identifiant à la fois, cause `exploitant`, journalisé : l'exception pour « la clé est perdue et l'on le sait », pas un outil de modération. Couvre les trois orphelins de `nitrogen` que la règle n'attrape pas. | **Décidé** (2026-09-18) |
| 25 | **L'attestation d'un appareil qui rejoint se réplique comme un fait sur la clé** : l'opération `appareil-atteste` (identifiant, attestation) ne va que d'`aucune` ou `attendue` vers une valeur prouvée, s'applique toujours — révoqué ou non, pour converger quel que soit l'ordre —, et rend vivant chez l'autre racine un appareil qu'elle tenait `attendue`. `attendue` est une valeur d'`attestation` portée par l'opération `appareil` (format, cran mineur à la PR de code) ; elle ne s'expire pas. Le défi de la chaîne n'est pas répliqué : il vit dans la connexion du nouvel appareil, et la preuve se fait là. | **Décidé** (2026-09-21) |
| 26 | **La posture `invitation` est servie, et son code se réplique comme celui d'un enrôlement** : opérations `invitation` (empreinte, expiration) et `invitation-consommee` (empreinte, toujours appliquée). L'émission passe par `POST /v1/invitations`, sur l'annuaire EN MARCHE, sous la clé de `--operator-key` (genre `o`, preuve dans le corps, sans identifiant) — un outil hors ligne aurait exigé d'arrêter le service à chaque arrivant, l'entrepôt n'ayant qu'un écrivain. **Un même code consommé des deux côtés de la fenêtre donne deux comptes, et on ne les départage pas** : deux comptes ne se disputent rien, et un effacement automatique sur une course serait une arme. Le journal le dit ; l'exploitant tranche. | **Décidé** (2026-09-24) |
| 27 | **Les notifications sans Apple ni Google** (`protocole.md` §2.2, « Les notifications ») : un point de poussée UnifiedPush remplace le jeton APNs/FCM, qui n'est plus accepté ; il se réplique par l'opération `point-de-poussee` (genre 20 ; table à part, pas de reprise de format), le plus récent gagne, refusée pour un appareil révoqué. **Seule une autorisation accordée réveille**, depuis la racine qui l'a écrite (décision 9), d'un message **vide**. Ce que l'envoi apprend — point mort sur `404`/`410`, limites de débit — reste en mémoire, par racine : ce sont des freins, et chaque racine voit son propre réseau. **Les deux racines se déploient avant qu'un appareil dépose un point** : une racine d'avant refuserait l'opération inconnue. | **Décidé** (2026-09-25) |
| 28 | **L'instantané se lit hors de la boucle qui sert** (§5.4) : `GET /v1/pair/instantane` lance la lecture — toujours UNE transaction — sur un fil bloquant, répond `200` sans l'attendre, tient le flux ouvert et vide, et le remplit quand la lecture revient. La lecture dans la boucle coûtait une dizaine de microsecondes par enregistrement (29 ms pour six mille cadres, mesuré le 2026-09-25), donc des secondes vers le million, pendant lesquelles plus aucune connexion n'était servie — le défaut que la 0.18.0 a corrigé côté tireur. Un second `GET` pendant la lecture rend `409` (le flux est tenu) ; une lecture qui échoue ferme le flux VIDE — la réponse est déjà partie —, ce que le tireur lit comme un instantané tronqué, avec sa reprise ; une connexion tombée entre-temps voit sa lecture jetée ; une panique de l'entrepôt remonte dans la boucle, comme avant. **Le rattrapage `operations?apres=` reste lu dans la boucle** : son statut (`200` ou `410`) dépend de la lecture, et il ne porte que ce qui a été écrit pendant la coupure. **Tout ce qui arrive à la boucle par canal la RÉVEILLE en arrivant** (`Application::reveil`, un seul `Notify` pour tous, signalé après le dépôt) : la lecture revenue, et depuis la 0.21.0 le verdict d'une sonde et la fermeture que le tireur demande (`Fermetures::fermer`). La boucle ne se réveille sinon que sur une échéance QUIC ou un datagramme : un verdict attendait le keepalive du daemon, une connexion à fermer celui du tireur d'en face — dix secondes par défaut, et sans limite sur une racine où rien ne parle. | **Décidé** (2026-09-26) |
| 29 | **Ce qu'une requête écrit part avec sa réponse** : une autorisation qui réveille son bénéficiaire (ligne sur `GET /v1/nouvelles`, compte au réveilleur UnifiedPush), une opération journalisée que le pair suit sur son flux tenu, un pair révoqué (clé retirée, capacité retirée, compte effacé) dont les connexions doivent tomber. Jusqu'à la 0.21.0, `au_tour` passait AVANT la lecture du datagramme, et ce que la requête déposait attendait le tour suivant : en pratique l'acquittement de celui qui avait écrit (un aller-retour), et, s'il se taisait, la retransmission de la réponse — 1,5 s mesurées sur le banc, jamais moins que les 25 ms de `max_ack_delay`. Un second rendez-vous, `Application::apres_la_lecture`, passe désormais après la lecture et avant l'émission : **le même lot** de datagrammes porte la réponse et ce qu'elle a déclenché (0,25 à 1,1 ms mesurés). Écartée, l'autre voie — signaler son propre `Notify` et refaire un tour — coûtait un `au_tour` entier (verdicts, vivier, balayages) et une émission de plus par écriture, pour arriver après. `apres_la_lecture` ne recueille QUE ce qu'une requête dépose, et rend sans rien parcourir si rien n'a bougé (journal, comptes à réveiller, pairs révoqués) : il passe à chaque datagramme. **La connexion qui a porté la requête n'est pas fermée dans ce tour** : sa réponse — le `204` d'« Effacer mon compte » — n'est pas encore partie, et une connexion qu'on ferme n'émet plus un octet de flux ; elle tombe au tour suivant, comme avant, et les autres connexions du même pair tout de suite. | **Décidé** (2026-09-26) |

| 30 | **Le domaine** (`modele.md` §2.11) : `d-…`, possédé par UN compte ; **un compte en a toujours au moins un** — le premier créé avec le compte, dans sa transaction ; supprimer le dernier rend `409`, seul l'effacement du compte les emporte tous. Plat, sans sous-domaine. Une machine dans un seul domaine à la fois, rattachée par son propriétaire seulement, et le domaine n'est pas obligatoire pour une machine. | **Décidé** (2026-09-26, Thierry) |
| 31 | ~~**La délégation** : le propriétaire délègue la gestion d'un domaine à des comptes existants ; un délégué voit le domaine, rattache et détache SES machines, pose l'alias ; un seul niveau ; seul le propriétaire délègue. Rattacher ne donne aucun droit de lecture (C10).~~ | **Renversée** le 2026-09-26 par la décision 39 |
| 32 | **L'inscription d'un annuaire local est APPROUVÉE par un administrateur des racines** — un seul suffit, pour accepter comme pour refuser. **Renverse** `annuaires.md` §1 et §4.1 (l'enregistrement libre, « s'enregistrer ne donne accès à rien ») et `modele.md` §2.7 (« le propriétaire des racines n'arbitre rien ») **pour l'annuaire local** : il ne demande pas d'être recensé, il demande que les racines servent l'état de ses services, et ce qu'elles servent en son nom, elles doivent pouvoir le refuser. | **Décidé** (2026-09-26, Thierry) |
| 33 | **Le groupe des administrateurs des racines** (`modele.md` §2.12) ~~, seul groupe de la v1~~ — **amendé le même jour : c'est le groupe d'administrateurs du domaine racine** (décision 37), dans une notion de groupe devenue générale (décision 38) ; premier membre le compte de Thierry ; membres nommés et retirés **sous la clé d'exploitant**, et sous elle seule. **Renverse** l'argument de la décision 26 — « pas de `u-…` qui vaut plus que les autres » — pour ce seul jugement ; un administrateur des racines ne peut rien d'autre qu'accepter ou refuser une inscription, et le domaine racine ne transmet aucun droit aux domaines du niveau 1. | **Décidé** (2026-09-26, Thierry), amendé le même jour |
| 34 | **L'état vivant des domaines hébergés TRAVERSE les racines** (`annuaires.md` §5.4) : identifiant du service, adresse IP, port, vivant ou non ; servi **aux clients** — pas aux autres annuaires locaux — et **aux seuls comptes autorisés** (C10), comme `GET /v1/ou`. **Renverse** `annuaires.md` §3 et §5.3 (« l'état vivant ne traverse pas la fédération », l'hybride) : un annuaire à la maison est souvent injoignable de l'extérieur, les racines le sont. Le coût est nommé : les racines apprennent adresses et état de tous les services fédérés (C13 amendée : en mémoire, jamais dans l'entrepôt, pas répliqué entre racines), et le graphe d'usage passe aux racines. | **Décidé** (2026-09-26, Thierry) |
| 35 | **L'alias de domaine** : facultatif, **non unique**, UTF-8 de 1 à 64 octets aux règles du nom de machine, rangé en **NFC** ; recherche **exacte** après NFC ~~et **pliage simple de casse** d'Unicode~~ — **sensible à la casse depuis 0.26.0 (décision 45)** —, réservée aux comptes authentifiés, sans préfixe ni énumération ; la réponse est la liste de tous les domaines qui le portent, avec l'annuaire qui fait autorité. Donnée publique choisie : exception de C13. Le plus récent gagne entre racines. | **Décidé** (2026-09-26, Thierry), y compris la version d'Unicode épinglée ; **amendé par la décision 45** |
| 36 | **La voie de l'annuaire local** (`protocole.md` §3 ter) : l'annuaire local OUVRE vers chaque racine (il est derrière un NAT), prouve sa clé d'identité `n-…` comme une racine, reçoit les machines de ses domaines et leurs révocations, pousse ses services et leur état ; C11 vérifié à chaque cadre. Les domaines, les délégations, le rattachement et les inscriptions s'écrivent aux racines depuis les applications ; les services et leur état, chez l'annuaire local. | **Décidé** (2026-09-26, Thierry) — la forme sur le fil et le partage de l'autorité |
| 37 | **Le domaine racine** (`modele.md` §2.11) : un seul, au **niveau 0**, tenu par les deux racines, propriétaire Thierry ; les domaines des utilisateurs sont au niveau 1, **jamais de niveau 2**. Identifiant déduit d'une étiquette fixe ; vide en v1 ; ~~naît au premier démarrage sous `--operator-key`~~ **calculé, jamais écrit**, son propriétaire étant le premier administrateur nommé encore vivant (0.24.0, décision 43). **Son groupe d'administrateurs est celui des administrateurs des racines**, et ne change que sous la clé d'exploitant. **Il n'est pas un ancêtre pour les droits** : rien de ce qu'on accorde sur lui ne descend dans les domaines du niveau 1. | **Décidé** (2026-09-26, Thierry) ; amorçage amendé par la décision 43 (0.24.0) |
| 38 | **Les groupes, notion générale dès la v1** (`modele.md` §2.12) : `e-…` ; un groupe appartient à un domaine, ses administrateurs le gèrent, ses membres sont des comptes quelconques ; un compte est membre d'un ou plusieurs groupes. **Chaque domaine a son groupe d'administrateurs, le propriétaire membre d'office et non retirable** ; **chaque compte a son groupe personnel**, sans domaine, qui ne contient que lui. Identifiants de ces deux-là déduits, nés avec leur domaine ou leur compte sous son estampille (0.24.0). Pas d'imbrication, pas de groupe « tout le monde ». | **Décidé** (2026-09-26, Thierry) ; codé en 0.24.0 |
| 39 | **La délégation disparaît** : déléguer, c'est ajouter au groupe d'administrateurs du domaine. **Renverse** la décision 31 : une notion à part — un rôle, une liste, des opérations — que les groupes et les droits font pour tout. Retirer un compte du groupe qui lui donnait `rattacher` détache ses machines. | **Décidé** (2026-09-26, Thierry) |
| 40 | **Les droits s'accordent à des GROUPES, jamais à un compte seul** (`modele.md` §2.13) : `administrer`, `rattacher`, `voir`, `localiser` ; sur un domaine, une machine, un service. Un droit sur un domaine vaut pour ses machines et ses services ; le propriétaire d'une machine a tous les droits sur elle et accorde sur elle quel que soit son domaine. **Résolution : l'UNION des droits reçus par tous les groupes du compte, sur l'élément et ce qui le contient, sans droit négatif** (proposé) — une réunion ne dépend d'aucun ordre, et deux racines qui reçoivent les droits dans deux ordres répondent pareil. Rattacher sa machine à un domaine, c'est confier à ses administrateurs le droit de la partager, et l'application le dit. | **Décidé** (2026-09-26, Thierry) ; la règle d'union : décidée (2026-09-27, Thierry), codée en 0.25.0 (décision 44) |
| 41 | **Les autorisations deviennent des droits** : une arête compte→compte devient un droit `voir` + `localiser` accordé au groupe personnel du bénéficiaire, **sous le même `g-…`**, à la reprise de l'entrepôt, sur les deux racines, au même résultat. « Tout mon compte » devient un droit sur **l'élément compte** (proposé), la seule conversion qui ne change pas en silence ce qui avait été accordé. **Les verbes d'hier restent servis** — `POST`, `GET`, `DELETE /v1/autorisations` — comme une vue des droits (proposé), pour que les applications déployées ne cassent pas ; un droit accordé réveille les membres du groupe, et un ajout à un groupe qui porte des droits réveille le compte ajouté ; la ligne des nouvelles garde son genre `autorisation`. **Renverse** `modele.md` §2.5. | **Décidé** (2026-09-26, Thierry) ; élément compte et vue de compatibilité : décidés (2026-09-27, Thierry), codés en 0.25.0 (décision 44) |
| 42 | **Le socle des domaines, tel qu'il se code** (PR 1/4, 0.23.0) : **le premier domaine se déduit du compte pour TOUS les comptes** — nés avant ou après —, et naît sous l'estampille du compte, à la création locale comme à l'application de `compte` et à la reprise ; aucune opération ne le porte. **La vie d'un domaine se lit, et ne s'écrit jamais** : une marque de suppression ne s'efface pas (la plus petite estampille la tient) ; un domaine est vivant s'il n'est pas marqué, ou si tous ceux de son compte le sont et qu'il est le plus ancien. **L'alias et le rattachement suivent leur seule règle — le plus récent —, mort ou vif** ; la suppression d'un domaine et l'effacement d'un compte n'écrivent rien sur eux, le lecteur écarte ce qui vise un domaine mort. Ranimer par écriture et détacher sous l'estampille de la suppression dépendaient de l'ordre d'arrivée : l'essai de convergence (`asl-store`, `l_invariant_de_convergence`) les a pris en défaut. **Genres 21 à 24.** **Unicode 17.0.0** pour le NFC (`unicode-normalization` épinglée à `=0.1.25`) et le pliage simple (`CaseFolding-17.0.0.txt`, table engendrée par `scripts/plis-unicode.sh`). | **Décidé** (2026-09-26) — le code en fixe la forme |
| 43 | **Les groupes, tels qu'ils se codent** (PR 1b, 0.24.0) : **qui est membre, qui administre un domaine, où une machine est rangée — tout se LIT, rien ne s'écrit par réparation**, la discipline de la décision 42 étendue. (1) Une adhésion par AJOUT, nommée par son estampille, dans la clé ; un retrait la marque et ne l'efface pas ; un retrait arrivé avant l'ajout qu'il nomme se range déjà retiré — un ensemble où chaque ajout a son nom, que deux racines tiennent pareil dans tous les ordres. (2) La marque d'un groupe supprimé ne s'efface jamais, garde la plus petite estampille, se pose même pour un groupe encore inconnu, et retire ses adhésions. (3) **Le groupe d'administrateurs d'un domaine et le groupe personnel d'un compte naissent avec lui, sous son estampille**, identifiants déduits — à la création, à l'application de l'opération, à la reprise —, et aucune opération ne les porte ; le propriétaire et le titulaire en sont membres d'office, **sans que cela s'écrive**. (4) **Le domaine racine n'est écrit nulle part** : son groupe d'administrateurs se déduit, ses membres sont les nominations vivantes, **son propriétaire le premier nommé encore vivant** — l'amorçage « au premier démarrage » de la décision 37 aurait écrit deux domaines racines de propriétaires différents si les deux racines nommaient leur premier administrateur dans la même fenêtre. (5) **Un rattachement ne vaut que tant que le propriétaire de la machine administre le domaine** : retirer un compte du groupe détache ses machines À LA LECTURE (`modele.md` §2.11), et le rajouter les lui rend. (6) Dans cette tranche, sans les droits (PR 2), **ranger dans un domaine, c'est l'administrer** ; le propriétaire seul le supprime. | **Décidé** (2026-09-27) |
| 44 | **Les droits, tels qu'ils se codent** (PR 2, 0.25.0) : la discipline des décisions 42 et 43 appliquée au partage. (1) **Un droit s'écrit tel qu'on l'accorde, et son retrait le marque** — la plus petite estampille, jamais effacée ; ce qu'un compte peut se CALCULE à la lecture : l'union des droits vivants reçus par les groupes vivants dont il est membre, sur l'élément et ce qui le contient — service, machine, domaine où elle est rangée, compte qui la possède. (2) **`administrer` emporte `rattacher` et `voir`** ; `localiser` emporte `voir`. Le groupe d'administrateurs d'un domaine tient `administrer`, sans que cela s'écrive. (3) **Un droit sur une machine ou un service ne vaut que tant que celui qui l'a accordé en a encore le pouvoir** — il en est le propriétaire, ou il administre le domaine où elle est rangée : sortir sa machine d'un domaine retire, à la lecture, ce que ses administrateurs en avaient partagé, et l'y remettre le rend. Un rattachement vaut tant que le propriétaire peut ranger (décision 43, point 5, étendue à `rattacher`). (4) **Un droit reçu se refuse seulement pour ce qui ne revient jamais** — donneur effacé, groupe marqué ou inconnu, élément inconnu, domaine racine — et ce qui les efface emporte aussi les droits déjà là : les deux ordres arrivent au même. (5) **La conversion ne vide pas le journal** : une fonction des seuls octets de l'autorisation, faite une fois à la première ouverture, sur chaque racine ; les genres 13 et 14 restent lus et convertis à l'application. (6) **La vue de compatibilité rend les octets d'hier**, sans champ `groupe` : ce qu'une application déployée lit de `GET /v1/autorisations` est, pour un droit converti, identique à l'octet (essai de bout en bout). (7) **Un droit accordé réveille les membres du groupe, le donneur excepté ; l'ajout à un groupe qui porte des droits réveille le compte ajouté** — de la racine qui écrit, dans le tour de la réponse (décisions 9 et 29). | **Décidé** (2026-09-27) — le code en fixe la forme |
| 45 | **Les alias sont SENSIBLES À LA CASSE** (Thierry, 2026-09-27 : « un alias : chaîne UTF-8 sensible à la casse ») — ceux de domaine, de machine et de compte. **Renverse la décision 35 sur ce point** : elle cherchait après NFC et pliage simple de casse (« maison » trouvait « Maison ») ; désormais la recherche est exacte après NFC, octet pour octet. Le NFC reste — une même chaîne saisie composée ou décomposée est une seule chaîne ; ce n'est pas la casse. **La table de pliage est retirée** (`plis.rs`, `scripts/plis-unicode.sh`) ; seule la version d'Unicode du NFC reste épinglée. **La reprise** : l'index local des alias de domaine rangeait la clé pliée ; il se refait une fois, depuis les alias rangés — qui n'ont jamais changé : ils étaient déjà rangés tels que posés, en NFC, la casse gardée —, marqué dans la table de la racine. L'index ne se réplique pas, chaque racine le refait de son côté, et **le journal n'est pas touché**. | **Décidé** (2026-09-27, Thierry) |
| 46 | **L'alias de compte : UTF-8, NFC, sensible à la casse, et toujours UNIQUE** (Thierry, 2026-09-27). Trois à trente-deux octets rangés, les caractères refusés de l'alias de domaine, et **pas de tiret en deuxième caractère** — il ne doit pas ressembler à un `u-…`. « Thierry » et « thierry » sont deux alias ; deux réclamations qui ne différaient que par la casse, jusqu'ici impossibles (l'alphabet était en minuscules), sont désormais deux alias distincts. Les alias d'avant, en minuscules ASCII, sont déjà dans leur forme : **aucune reprise**. `GET /v1/alias/{alias}` garde la forme ASCII du chemin (majuscules admises) ; **`GET /v1/alias?alias=…`**, pourcent-encodé, résout un alias UTF-8. **Le coût, nommé** : un alias unique et sensible à la casse n'empêche ni « thierry » à côté de « Thierry » ni un sosie typographique ; c'est l'identifiant `u-…`, montré à côté, qui fait foi (`modele.md` §2.1, §6). | **Décidé** (2026-09-27, Thierry) |
| 47 | **Une machine a un NOM qui peut servir de nom d'hôte, et un ALIAS en plus** (Thierry, 2026-09-27). **Le nom** : une étiquette RFC 1123 — lettres ASCII, chiffres, tiret, 1 à 63 octets, ni tiret en tête ni en queue —, **rangée en minuscules** (le DNS compare sans casse, RFC 4343) ; un nom qui ne le peut pas rend `400`. **Les noms d'avant 0.26.0 restent tels quels** — relus, rendus et répliqués sans changer ; seuls les nouveaux noms et les renommages passent par la règle (à valider par Thierry). **L'alias** : UTF-8, NFC, sensible à la casse, 1 à 253 octets — la longueur d'un nom complet, puisqu'il est fait pour pouvoir en servir —, **indépendant du nom et du domaine par définition**, **non unique**, posé et retiré par le propriétaire seul (`PUT`/`DELETE /v1/machines/{m}/alias`), rendu par les verbes qui rendent la machine quand il existe. Il se range à part de la machine, comme le rattachement, et se réplique par **`machine-alias` (32)** : le plus récent ; ignoré pour une machine inconnue ; dans l'instantané après les machines ; ré-estampillé ; retiré avec la machine à l'effacement du compte ; regardé par C17. **Chercher une machine par son alias n'est pas décidé** (`modele.md` §6). | **Décidé** (2026-09-27, Thierry) |
| 48 | **Un annuaire local appartient à UN compte et n'héberge que les domaines de ce compte, de un à n** (Thierry, 2026-09-27) — jamais le domaine d'un autre, même administré : l'hébergement suit la propriété, pas la gestion. `PUT /v1/domaines/{d}/hebergeur` vers l'annuaire d'un autre compte rend `404`. | **Décidé** (2026-09-27, Thierry) |
| 49 | **La paire de secours** (Thierry, 2026-09-27 : speedy et helium pour le domaine « air-desktop-dictator ») : un annuaire local peut avoir **deux membres**, chacun sa clé `n-…`, qui se répliquent entre eux comme deux racines (§2, `--peer`) ; aux racines, **un seul annuaire**, nommé par le `n-…` de son titulaire, à un ou deux membres, **chacun approuvé à son tour**. Chaque membre ouvre sa voie vers chaque racine et reporte ce qu'il voit ; l'état vivant se tient par membre, en mémoire. | **Décidé** (2026-09-27, Thierry) — la paire, son objet et la règle de l'état, validés tels que proposés ; codés en 0.28.0 (décision 52) |
| 50 | **Ce que la spec laissait ouvert sur l'annuaire local** (2026-09-27) : (1) ~~son certificat TLS signé par une **autorité propre au propriétaire**, épinglée par ses daemons, ni celle des racines ni la clé `n-…`~~ — **renversé par la décision 53** le même jour : auto-signé par la clé `n-…`, parce qu'une autorité exigeait un nom, donc un DNS ; (2) la voie vers les racines **sans port entrant** — un port entrant seulement pour les daemons hors de la maison ; (3) ce qu'un membre rapportait tombe quand sa voie tombe (≤ 30 s), et **les domaines ne reviennent jamais d'eux-mêmes** aux racines ; (4) la bascule d'un domaine : une racine refuse en **`421`**, avec l'adresse de l'annuaire, l'annonce d'une machine d'un domaine confié ; (5) le paquet `asl-server` en **`amd64` et `arm64`** avant le premier déploiement d'une paire. | **Décidé** (2026-09-27, Thierry) — les cinq points, tels que proposés ; (3) et (4) codés en 0.28.0 (décision 52) |
| 51 | **L'inscription, telle qu'elle se code** (PR 3, 0.27.0) : la discipline des décisions 42 à 44. (1) **Quatre faits, un état LU** : la déclaration (sous l'empreinte du code, qui la nomme), la présentation (la clé qui a présenté ce code, la plus petite estampille gagne), les marques d'acceptation, de refus et de retrait (la plus petite estampille de chaque sorte, jamais effacées), l'hébergement (le plus récent). L'état d'un membre se calcule : **retiré** s'il est marqué retiré ou que son propriétaire est effacé, sinon **refusé** s'il est marqué refusé, sinon **accepté**, sinon **en attente** ; un refus arrivé après une acceptation la renverse — la seule règle qui ne dépende pas de l'ordre —, et redemander, c'est une inscription neuve. (2) **Un second n'existe que par son titulaire** : du même propriétaire, pas retiré ; sinon il se lit retiré, même refusé. **Au plus un second effectif** par titulaire, celui de la déclaration la plus ancienne parmi ceux qui ne sont ni refusés ni retirés ; un autre se lit refusé. (3) **Un domaine est hébergé** si l'annuaire nommé — son titulaire — est accepté, pas retiré, et du même propriétaire que le domaine (décision 48) ; sinon ce sont les racines, et `heberge_par` le dit. (4) **Le code** : `CodeInscription`, la forme d'un code d'enrôlement sous son propre domaine d'empreinte, valable **vingt-quatre heures** ; le propriétaire déclare (`POST /v1/annuaires`, `POST /v1/annuaires/{n}/membres`), l'annuaire local présente. (5) **La présentation a la forme d'un enrôlement** — code ‖ clé ‖ preuve de possession sur le défi de la connexion, `POST /v1/annuaires/inscription` —, et l'état se relit par clé ‖ preuve (`POST /v1/annuaires/etat`) : **écart de l'esquisse** de `protocole.md` §3 ter (défi de genre `n` puis code), pour réutiliser une preuve déjà éprouvée ; la voie de §3 ter reste la PR 4. Sans exigence de session, freinées comme les invitations. (6) **Les administrateurs** lisent `GET /v1/inscriptions` (en attente) et tranchent `POST /v1/inscriptions/{n}/decision` ; accepter un refusé ou un retiré rend `409` ; qui n'administre pas les racines lit `404`. (7) **Le binaire** : `asl-server --register <code>` et `--registration-status`, avec `--directory`, `--ca`, `--identity-key` — présenter, relire l'état, rien d'autre ; le rôle `local` et la voie sont la PR 4. **Genres 33 à 37** ; les deux racines se déploient ensemble. | **Décidé** (2026-09-27) — le code en fixe la forme ; l'écart (5) validé par Thierry (2026-09-27) |
| 52 | **La voie de l'annuaire local, telle qu'elle se code** (PR 4, 0.28.0). (1) **Des requêtes courtes répétées, et non deux flux sans fin** — écart de l'esquisse de `protocole.md` §3 ter : la pile QUIC ne relève jamais la fenêtre d'un flux (seize kibioctets par flux et par sens), et un flux MONTANT sans fin, que le client écrit, s'y tairait sans recours. L'annuaire local ouvre une connexion vers **chaque** racine, prouve sa clé d'identité (genre `n` sur `POST /v1/defi`, la preuve d'une racine) ; la racine la cherche dans son pair, puis dans les **inscriptions acceptées** — et ce qu'elle ouvre alors n'est pas la voie entre racines (exigence `AnnuaireLocal`, disjointe de `Racine`). (2) **Descendant** : `GET /v1/federation/machines?apres=<rang>`, des `MachineFederee` à la suite — l'identifiant, puis **l'enregistrement `Machine` de l'entrepôt**, taille fixe, rangées par identifiant, une part (douze kibioctets) par réponse ; l'annuaire local redemande tant que la part est pleine, et **remplace en bloc** sa copie. Cette copie vit dans une **table à part, hors du journal** : elle ne part ni dans l'instantané ni vers le second membre — chacun tire la sienne —, et la lecture d'une machine la regarde après la table des machines ; une machine qui en sort ferme les connexions de ses daemons ici. (3) **Montant** : `POST /v1/federation/etat`, des `EntreeDEtat` à la suite — service, machine, nom, et **la réponse d'annonce encodée quand le service est vivant** (l'objet que `GET /v1/ou` rend, VERBATIM : l'adresse et le port y sont, avec ce que l'annuaire local a mesuré) ; tous les services déclarés de ses machines, les partis compris, en parts d'au plus un corps (huit kibioctets), **tout ou rien** par part. Une entrée sur une machine hors de ses domaines refuse la part entière (`403`, C11) et se journalise. (4) **La cadence** : tout se rafraîchit toutes les **dix secondes** ; un changement de ce que la boucle publie (un daemon arrive, s'en va) part **tout de suite** — mesuré en banc : trouvé par la racine 0,2 s après l'annonce faite à l'annuaire local. (5) **Aux racines, en mémoire seulement** (C13) : par `machine ‖ nom`, puis par membre, avec l'heure du rapport ; **vivant si un membre le dit**, la réponse étant celle du rapport vivant le plus récent ; un rapport a **trente secondes** de vie — trois rapports manqués —, et ce qu'aucun membre ne confirme tombe (mesuré : 2,97 s sous une expiration d'essai de trois). La résolution (`GET /v1/ou`, par nom) cherche le service ici, puis dans cet état, sous la **même décision** — `localiser`. Rien n'est écrit dans l'entrepôt des racines. (6) **`421`** : une racine qui reçoit l'annonce d'une machine dont le domaine est confié répond `{"annuaire":"n-…","adresses":["hôte:port",…]}` — l'annuaire, et l'adresse déclarée de chacun de ses membres acceptés. (7) **Le binaire** : `--federation <hôte:port>` (répétable, une racine chacun), `--federation-ca`, et `--identity-key` ; sans eux, un `asl-server` est une racine. (8) **Pas encore** : les services fédérés dans `GET /v1/machines/{m}/services` (l'écran d'une machine) ; le suivi du `421` par le daemon (côté client) ; le paquet `arm64`. | **Décidé** (2026-09-27) — le code en fixe la forme ; l'écart (1) à valider par Thierry |
| 53 | **L'identité par la clé — ASL sans DNS** (`annuaires.md` §2 quater, C20). Thierry, le 2026-09-27 : « ASL doit pouvoir fonctionner SANS DNS. […] un utilisateur crée ses domaines SANS l'avis de qui que ce soit […] et résout ensuite des noms/alias sans dépendre de qui que ce soit. » Tout annuaire — racine ou local — présente en TLS un certificat **auto-signé par sa clé d'identité Ed25519** ; le client l'accepte si la clé se déduit en le `n-…` attendu et que la poignée de main la prouve. Ni autorité, ni nom, ni date jugés. **Renverse** la décision 50 (1) (« certificat sous une autorité propre au propriétaire ») et la règle de `modele.md` §2.7 « clé d'identité distincte de la clé TLS » : une clé TLS distincte servait un certificat sous autorité, qui n'existe plus. **Pile vérifiée** (air-mail-server `6f0ea51`, lecture seule) : ASL construit ses `ClientConfig` (`configuration_tls`), `Connection::connect` prend un `Arc<ClientConfig>`, un `ServerCertVerifier` se branche par `dangerous().with_custom_certificate_verifier` comme le fait déjà `ams_tls::relay::dane_config`, `quic_server_config` accepte un certificat Ed25519 d'un seul maillon ; RFC 7250 (clés brutes) n'est PAS porté par la pile — d'où l'enveloppe auto-signée. C15 tenu : rien à modifier dans `air-mail-server`. | **Décidé** (2026-09-27, Thierry) — le principe, et la clé TLS confondue avec la clé d'identité ; **codé en 0.29.0** (`asl-loop-tokio::confiance` : vérificateur « clé = identité » sur la voie entre racines, la fédération, `--invite`, `--add-admin`, `--register`) |
| 54 | **La validité d'un certificat d'identité n'est pas jugée.** Le vérificateur lit la clé et ignore `notBefore`/`notAfter`, l'émetteur, les extensions de nom. Le certificat est frappé avec une validité maximale (`99991231235959Z`, RFC 5280 §4.1.2.5) pour que les outils ordinaires ne le disent pas expiré. La révocation d'un annuaire n'est pas une date : c'est retirer son inscription (`protocole.md` §3 ter) ou changer une clé épinglée. Conséquence voulue : aucune horloge juste n'est requise pour se croire — un appareil dont l'heure dérive se connecte quand même. | **Décidé** (2026-09-27, Thierry) ; codé en 0.29.0 |
| 55 | **Le certificat se frappe sans dépendance.** Un gabarit DER fixe (un certificat X.509 v3 d'un maillon, sujet et émetteur `CN=n-…`, clé et signature Ed25519), écrit à la main dans une crate de l'étage 2 (pas une ligne de C, C4 ; aucune crate de génération X.509) ; `asl-server --new-identity-key` l'écrit à côté de la clé, et le démarrage le refrappe en mémoire si le fichier manque. `--certificate`/`--key` deviennent facultatifs. | **Décidé** (2026-09-27, Thierry) ; **codé en 0.29.0** : `asl_cle::certificat_d_identite` (271 octets, fuzzé : `fuzz_asl_cle_certificat`), `<clé>.crt` à `--new-identity-key`, `--identity-certificate <clé>` pour une clé d'avant, et le démarrage le frappe en mémoire ; l'unité systemd passe la chaîne d'hier par `$ASL_TLS`, qu'un drop-in vide |
| 56 | **L'ancre des racines : une liste embarquée d'identités, et des locateurs qui se renouvellent.** Le logiciel (`asl`, le binaire) et les applications embarquent, pour chaque racine, `{n-…, clé, locateurs IPv6 et IPv4}`. L'alias `asl-root.air-desktop.org` et les noms des racines restent des locateurs facultatifs. Une racine sert **`GET /v1/racines`** (sans exigence) : l'identité et les locateurs courants des deux ; un client qui en a joint une — par n'importe quel locateur, identité vérifiée — met à jour sa liste. C'est l'issue 3 de `annuaires.md` §2 (« apprendre les nouvelles adresses par un canal signé ») : le canal est la connexion vérifiée par clé. | **Décidé** (2026-09-27, Thierry) ; la liste embarquée est **codée en 0.29.0** (`asl-loop-tokio::racines`, clés relevées sur les bancs et tenues par un essai) ; `GET /v1/racines` **codé en 0.30.0** : la liste embarquée, `[{"annuaire":"n-…","cle":"<hex>","locateurs":[…]}]`, et `asl_loop_tokio::racines::apprendre_les_racines` qui la lit et la vérifie (chaque clé se déduit en son `n-…`, sinon la liste entière est refusée) |
| 57 | **Un annuaire local publie lui-même ses locateurs.** L'adresse déclarée à l'inscription (`POST /v1/annuaires`) n'est que le premier locateur ; chaque membre, sur sa voie (exigence `AnnuaireLocal`), pose ses locateurs courants par **`PUT /v1/federation/locateurs`** `{"locateurs":["[IPv6]:port",…]}` au démarrage et quand ses adresses changent (préfixe IPv6 d'un particulier). Opération répliquée `inscription-locateurs` (le plus récent gagne, par membre) ; le `421` et `GET /v1/annuaires` rendent ces locateurs. Une paire = deux `n-…`, chacun les siens. | **Décidé** (2026-09-27, Thierry) ; **codé en 0.30.0** : quatre locateurs au plus par membre, `--locator` (répétable) sur l'annuaire local, publiés à chaque ouverture de sa voie — aucun `--locator`, c'est un retrait ; **détectés et republiés en service depuis 0.35.0** (décision 64) |
| 58 | **La transition sans rien casser.** (1) Les clients (daemon `asl`, applications, tireur, annuaire local) apprennent **les deux formes** : l'identité attendue, OU — tant qu'un PEM est configuré — la chaîne d'autorité et le nom d'hier. (2) Les racines présentent alors **les deux certificats** : la chaîne d'hier à qui envoie un SNI qui la nomme (les clients d'hier visent un nom), le certificat d'identité à qui vise un locateur IP sans SNI — un `ResolvesServerCert` d'ASL sur `ams_tls::provider_quic()`, sans toucher à la pile. (3) Quand plus aucun client d'hier ne sert — en pratique, les appareils de Thierry mis à jour —, les racines cessent de servir la chaîne. (4) Le retrait des réglages PEM est une rupture : **cran majeur**, annoncé par `GET /v1/version`. (5) L'ABI (C12) : un ajout, `asl_appareil_annuaire_identifie(appareil, locateur, n)` à côté d'`asl_appareil_annuaire` + `asl_appareil_racines` ; le retrait des seconds attendra le même cran majeur. (6) `annuaire.json` des applications : chaque entrée gagne `"annuaire":"n-…"` ; `nom` devient facultatif ; `annuaire-racine.pem` n'est plus lu une fois la bascule faite. (7) L'annuaire local de Thierry (speedy, helium) se déploie **directement** sous la forme nouvelle : il n'a pas de clients d'hier. | **Décidé** (2026-09-27, Thierry) ; **(1) et (2) codés en 0.29.0** côté serveur — le résolveur sert la chaîne à qui envoie un SNI, l'identité sinon ; `--federation <locateur>=<n-…>` dit l'identité d'un locateur hors de la liste ; (5) et (6) sont côté client et applications. **(3) et (4) faits en 0.34.0 : la transition est CLOSE côté serveur** (décision 63) |
| 59 | **L'identité de chaque membre, et une seule copie de la règle** (0.31.0). (1) **Le `421` porte `identites`** : une chaîne de `n-…` séparés d'une espace, le `i`-ème étant l'identité du membre au bout de la `i`-ème adresse. Sans elle, un client sous la forme nouvelle (décision 53) ne pouvait croire que le titulaire de la paire — `annuaire` —, et le second (helium) présente SA clé. **Une chaîne et non une liste d'objets** : le lecteur du client 0.16/0.17 (`asl-client::renvoi`) ne saute une clé inconnue que si sa valeur est une chaîne ; une liste `"membres":[{…}]` lui aurait fait refuser le renvoi entier — un essai d'`asl-api` rejoue sa règle à la lettre sur les deux formes. `GET /v1/annuaires` portait déjà `membre` pour chaque entrée : rien n'y change. (2) **La crate `asl-racines`** (étage 2, `no_std`, 100 % couverte, fuzzée par `fuzz_asl_racines`) porte **la liste embarquée des racines**, **la règle « clé = identité »** (`identite_du_certificat`, `identite_attendue` : un seul maillon, dont la clé se déduit en un `n-…` attendu) et **la vérification d'une liste servie** (`verifier_la_liste` : une clé fausse refuse la liste entière). `asl-loop-tokio::confiance` et `::racines` s'y appuient ; **le client la tire comme `asl-cle` et `asl-api`**, et n'a plus à la réécrire (0.17.0 avait dû recopier la liste et la règle). La preuve de possession — la signature de la poignée de main — reste à l'étage 3 de chaque côté, avec `rustls`. | **Décidé** (2026-09-27, Thierry : « le `421` avec l'identité de chaque membre, et la crate partagée ») |
| 60 | **Les services fédérés à l'écran, et d'où vient leur sonde** (0.32.0). `GET /v1/machines/{m}/services` ne rendait que ce que la racine tient ; une machine d'un domaine confié n'y montrait rien (essai réel du 27/09 : `[]`, alors que `GET /v1/ou` la trouvait). Il y ajoute l'état fédéré, en mémoire (C13), sous la règle de la résolution (décision 49) : vivant si un membre le dit, `parti` sans motif si tous le disent parti, absent passé l'expiration ; un nom tenu ici l'emporte. Ces objets portent `sonde_par` (le membre retenu) et `sonde_locale` (le daemon est venu d'une adresse littérale du membre : sonde de l'intérieur, qui ne dit rien de l'extérieur). La décision d'accès est celle de la vue (le propriétaire seul), inchangée. | **Décidé** (2026-09-27) |
| 61 | **L'alias du domaine racine se relit et se réplique** (0.32.0). La #58 avait ouvert son écriture (`PUT …/alias` → 204), mais deux chemins le taisaient encore — vus sur nitrogen le 27/09 : **la lecture** (`GET /v1/domaines`, `GET /v1/domaines/{d}`) rendait l'alias à `None` en dur pour le domaine racine ; **l'application** de `domaine-alias` ignorait tout alias d'un domaine sans rangée, donc celui du domaine racine, qui n'en a jamais (décision 43) — posé sur une racine, il n'arrivait pas sur l'autre. Les deux lisent désormais l'alias rangé ; seul un domaine inconnu AUTRE que le domaine racine reste ignoré. La recherche `?alias=` l'acceptait déjà. | **Décidé** (2026-09-27) |
| 62 | **Un annuaire local n'a aucun compte, et le fait respecter** (0.33.0 ; `protocole.md` §3 ter). Jusqu'ici la spec le disait (« Il n'a **aucun compte** : ses domaines appartiennent à des comptes qui vivent aux racines ») sans que le code l'impose : speedy, annuaire local 0.32.0, servait `POST /v1/comptes` et annonçait au démarrage « N'IMPORTE QUI peut créer un compte ». Désormais, un annuaire en rôle local (`--federation`) ne sert **lui-même** que la preuve (`/v1/defi`, pour une machine de ses domaines), l'annonce et ses poussées (`/v1/annonce`, `/v1/poussees`), ce qui ne dit rien d'un compte (`/v1/vu`, `/v1/version`, `/v1/racines`) et la voie de sa paire (`/v1/pair/*`, `/v1/replication`, décision 49). **Tout le reste relève des racines et leur est renvoyé par `421`**, avant toute exigence et toute lecture, avec pour corps la liste des racines — celle de `GET /v1/racines`, identités et locateurs : créer un compte ou un appareil, attester, inviter, lire ou écrire un compte, ses machines, ses domaines, groupes, droits, autorisations, alias, les inscriptions, les administrateurs, la résolution (`/v1/ou`, sous des droits qui vivent aux racines), les nouvelles d'un appareil, et la voie de fédération (qu'on sert AUX annuaires locaux). **Pourquoi `421` et pas `403`/`404`** : ce n'est pas un refus de droit ni une absence, c'est « le même service, servi par un autre » (RFC 9110 §15.5.20) — la réponse déjà donnée à une machine d'un domaine confié qui s'annonce à une racine (décision 52), ici dans l'autre sens ; et le corps dit où aller sans DNS (C20). Une route inconnue ou une méthode refusée gardent leur réponse : une faute de chemin ne se corrige pas aux racines. `--attestation`, que l'unité systemd passe toujours, est accepté et **sans effet** sur un annuaire local ; son démarrage le dit (« annuaire LOCAL — aucun compte ne se crée ici … »). Règle pure : `asl_session::servie_par_un_annuaire_local`. | **Décidé** (2026-09-28) |
| 63 | **La fin de la transition** (0.34.0 ; décision 58, étapes (3) et (4)). **Constaté avant** : depuis le 2026-09-28 ~02:30, nitrogen et argon (0.33.0) ne servent plus la chaîne d'autorité (`ASL_TLS` vide), se répliquent par `--peer <adresse> --peer-key` sans `--peer-ca`, speedy fédère par `--federation <adresse>=<n-…>` sans `--federation-ca`, et tous les clients (asl 0.18.1, iOS 0.18/0.19, Android 0.15) passent par l'identité. **Retiré** : (1) **le service de la chaîne d'hier** — `--certificate`, `--key`, le résolveur SNI qui la servait à qui visait un nom ; l'annuaire présente son certificat d'identité, **à tous** (`rustls::sign::SingleCertAndKey`), et `--identity-key` devient **obligatoire** (sans elle, rien à présenter : la faute dit comment la frapper) ; l'unité systemd la lit en ligne fixe, `/etc/asl-server/identite.key`, et perd `$ASL_TLS` — un drop-in `Environment=ASL_TLS=` d'avant n'a plus d'effet, et un `$ASL_REPLICATION` qui redonne la même `--identity-key` non plus (la dernière l'emporte). (2) **L'acceptation de l'ancienne forme côté client** — le repli sur une autorité PEM dans le vérificateur (tireur, fédérateur, `--invite`, `--add-admin`, `--register`) : `--peer-ca`, `--federation-ca`, `--ca`. Seules les identités : la liste embarquée, `--peer-key`, `<locateur>=<n-…>`. Le client vise toujours l'ADRESSE résolue (pas de SNI), et `confiance::Forme` disparaît : il n'y a plus qu'une forme. (3) `scripts/ca.sh` et l'essai qui chargeait ce qu'il frappait. **Refusés, pas ignorés** : chacun de ces drapeaux — et `--certificat`/`--cle`, leurs noms d'avant 0.4.0 — est refusé avec ce qu'il faut faire à la place (`Faute::Retire`), y compris dans les gestes d'exploitant, qui ne lisaient que leurs drapeaux et auraient pris `--ca` en silence ; l'ignorer laisserait croire qu'une autorité protège encore une voie. Aucun banc déployé ne les passe. **Tranché avec C20 : un nom DNS reste un locateur permis** (`--peer`, `--federation`, `--directory`) — il ne dit que où aller, et n'entre dans aucune décision de croire. **Gardé** : `--push-roots` (WebPKI vers les serveurs de poussée, la périphérie, hors du cœur). **Le cran** : la décision (4) disait « majeur » ; en 0.x, la règle du dépôt fait d'une rupture un cran **mineur** — 0.34.0. Le protocole sur le fil ne change pas pour un client par identité ; seul un client d'hier (une autorité, un nom) est refusé à la poignée de main, et c'est ce que les essais éprouvent. Côté client, `--roots` et les symboles d'ABI PEM suivent dans leur dépôt. | **Décidé** (2026-09-28, Thierry) ; **codé en 0.34.0** |
| 64 | **Le localisateur se détecte : l'adresse IPv6 globale stable de la machine** (0.35.0 ; `annuaires.md` §2 quater). **Constaté** : speedy publiait `--locator [2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630` en dur ; le préfixe est délégué par l'opérateur, et un changement aurait fait renvoyer les daemons (`421`) vers une adresse morte, en silence. **La forme** : `--locator auto` ou `--locator auto:<interface>`, une fois, combinable avec des locateurs fixes (l'adresse détectée d'abord, quatre au plus en tout) ; la forme explicite `hôte:port` ne change pas, et sans `--locator` rien ne change (un retrait, décision 57). **Le choix**, une fonction pure d'`asl-registre` (étage 1, 100 %, fuzzée) sur `/proc/net/if_inet6` et `/proc/net/ipv6_route`, sans dépendance : publiable = `2000::/3` hors Teredo et 6to4, ni temporaire (`0x01`), ni refusée par la DAD (`0x08`), ni dépréciée (`0x20`), ni en essai (`0x40`) ; parmi celles de l'interface nommée, sinon de l'interface de la route par défaut de plus petite métrique (si elle en porte), sinon toutes : **la plus petite**, dans l'ordre numérique — déterministe, indépendant de l'ordre du fichier. Le port est celui où l'annuaire écoute. **La cadence** : relue toutes les dix secondes, celle de la fédération ; un changement se dit au journal (`localisateur : A → B`) et **chaque voie le pousse aussitôt** (`PUT /v1/federation/locateurs` dans la session, sans reconnexion) — la racine le prend pour le même membre, prouvé par sa clé à l'ouverture, et remplace l'ancien (le plus récent gagne, répliqué). **Sans adresse candidate, rien n'est publié** et l'absence se dit une fois : la racine garde la dernière publication, meilleure estimation qu'un retrait vers l'adresse déclarée ; au démarrage, la voie s'ouvre sans rien publier tant que rien n'est détecté. Le protocole ne change pas : ni route, ni corps, ni enregistrement nouveaux. | **Décidé** (2026-09-28, Thierry) ; **codé en 0.35.0** |
| 65 | **Un seul `s-…` par service dans une paire, stable** (`annuaires.md` §2 ter, question 14). Constaté le 2026-09-28 : une paire lancée sans `--peer` garde deux `s-…` pour le même `(machine, nom)`, que les racines rendent tour à tour ; une paire qui se réplique converge vers la plus petite estampille de Lamport, pas vers le plus ancien. **I1** : le même `s-…` quel que soit le membre qui tient le daemon ; **I2** : stable à travers bascules, redémarrages et remplacement du second membre. | **Décidé** (2026-09-28, Thierry) — **fait (0.37.0)**, par la décision 66 |
| 66 | **Le `s-…` est dérivé de la machine et du nom (A1)**, et survit au changement d'hébergeur (**I3**) : `SHA-256("asl/service/1" ‖ m-… ‖ nom)` tronqué à 128 bits ; le titulaire n'entre pas dans le calcul. Deux membres, deux racines, un annuaire local et une racine frappent le même sans se parler. **La forme exacte, arrêtée par la PR de code (0.37.0)** : les treize octets ASCII de `asl/service/1`, puis les **seize octets** du `m-…` (jamais son texte), puis les octets UTF-8 du nom, sans longueur ni séparateur — la chaîne et `m` ont une longueur fixe, le nom est le reste, donc deux couples ne donnent jamais le même message ; les seize premiers octets du condensat. Vecteur : `m-32Q2JXER1HTVRZQ956T7V3GE0S` + `essai-federation` → `s-7ANMGMZPJ3EGA41WA129KAJTWE` (`asl_registre::service_derive`, figé par les essais). Le périmètre et la migration : décision 72. | **Décidé** (2026-09-28, Thierry) — **fait (0.37.0)** |
| 67 | **Un `s-…` prévisible est accepté** : il se recalcule depuis `m-…` et le nom ; aucun verbe ne s'ouvre (C9). `asl-id` le dit (0.37.0) : « 128 bits ne se devinent pas » vaut pour tous les genres sauf `s-`. | **Décidé** (2026-09-28, Thierry) — **fait (0.37.0)** |
| 68 | **Les droits par service valent pour un service fédéré** : la portée « Un service » doit marcher pour une machine d'un domaine confié. Aujourd'hui impossible — les racines ne rangent pas ces services. **Le mécanisme reste une sous-question** : les racines rangent le service déclaré (sans état vivant, C13), ou le droit porte sa machine et les racines vérifient la dérivation (`annuaires.md` §7, question 18). | **Décidé** (2026-09-28, Thierry) — mécanisme ouvert |
| 69 | **L'opération `service` perdue sans bruit est corrigée en patch** : ignorée parce que sa machine n'est pas encore connue, le curseur avançait — elle est désormais gardée, ou le curseur n'avance pas. **Et le vivier** : une session rangée sous un `s-…` qui perd la convergence passe sous le gagnant, pour qu'un daemon présent ne soit plus rapporté `parti`. **Fait en 0.36.0** : chez un membre d'annuaire local (l'entrepôt le sait, `Entrepot::se_savoir_annuaire_local`), l'opération dont la machine n'est pas encore reçue des racines est **gardée** dans la table `services-en-attente` — une par `(machine, nom)`, la plus ancienne — et le curseur avance : rien ne se fige derrière elle. `ranger_les_machines_federees` la **rejoue**, par la règle ordinaire, dans la transaction où sa machine arrive. Chez une racine, rien ne change : une machine inconnue y est une machine effacée, et le service part avec elle. L'application nomme chaque remplacement `(perdant, gagnant)` (`EffetsVivants::remplaces`) ; le tireur et le fédérateur le passent à la boucle (`Fermetures::renommer`), qui **déplace la session vivante** sous le gagnant (`Vivier::renommer`, `asl_annuaire::Session::renommer`). | **Décidé** (2026-09-28, Thierry) — **fait (0.36.0)** |
| 70 | **Un membre d'une paire lancé sans `--peer` le signale fort, et c'est lui qui le détecte** : il apprend des racines que son annuaire a un second membre accepté, et le dit à chaque tour dans son journal, dans `GET /v1/version`, et les applications l'affichent sur l'écran de l'annuaire. Il ne refuse pas de démarrer. **Fait en 0.36.0** : à chaque tour de fédération, le membre dit son `--peer` aux racines (`PUT /v1/federation/paire`, `protocole.md` §3 ter), qui lui rendent son annuaire et ses membres acceptés ; il juge — `seul`, `reglee`, `sans-peer`, `peer-inconnu` —, le dit au journal dès qu'il l'apprend puis **toutes les dix minutes** tant que c'est mal réglé (`PAIRE MAL RÉGLÉE (sans-peer) : …`), et `GET /v1/version` porte `"paire":"<mot>"`. Les racines jugent de même et le rendent dans `GET /v1/annuaires` et `GET /v1/inscriptions`, membre par membre. | **Décidé** (2026-09-28, Thierry) — **fait (0.36.0)** |
| 71 | **Un annuaire local déclare, dès sa création, un service `asl-directory`** — un vrai service, qui se résout comme les autres —, parce que seule l'une des racines doit impérativement écouter sur 6630 et que tous les autres annuaires peuvent écouter ailleurs. Ses sous-questions (`annuaires.md` §7, question 21) sont tranchées par les décisions 73 à 78, et leurs suites par 79 à 85 ; la spécification est `annuaires.md` §2 quinquies. | **Accepté dans son principe** (2026-09-28, Thierry) ; sous-questions **décidées** le même jour (73 à 78, puis 79 à 85) ; **fait côté serveur (0.38.0)** |
| 72 | **La dérivation vaut pour TOUS les services**, ceux annoncés directement aux racines compris (`annuaires.md` §7, question 17, réponse P1). **Chaque `s-…` existant change une fois, au premier démarrage de la version qui dérive** : chaque entrepôt — les deux racines, chaque membre d'un annuaire local — recalcule seul, de façon déterministe, le `s-…` de chacun de ses services depuis `(machine, nom)`, et arrive au même résultat que les autres ; **les droits qui visent un ancien `s-…` sont réécrits dans la même transaction**. Une opération venue d'un pair pas encore migré se range sous l'identifiant recalculé. Un changement de format d'enregistrement, donc un cran mineur. **Fait en 0.37.0** (§11, point 5) : format de l'entrepôt 3 → 4, migration dans la transaction d'ouverture — services, index, droits, services en attente, et une correspondance ancien → dérivé qui traduit les droits d'un pair pas encore migré ; refus nommé d'un entrepôt qui tiendrait deux services pour un `(machine, nom)` ; une 0.36.0 refuse d'ouvrir un entrepôt migré. | **Décidé** (2026-09-28, Thierry) — **fait (0.37.0)** |
| 73 | **L'`asl-directory` vit sous l'identité de l'annuaire logique** (`annuaires.md` §2 quinquies, question 21 (a)) : le `n-…` du titulaire, qui nomme déjà l'annuaire aux racines — pas une machine, puisque l'hôte n'est pas forcément enrôlé et peut changer. Il se résout par `GET /v1/ou/{n-…}/asl-directory` (`asl where n-… asl-directory`). **Son `s-…` est dérivé comme A1** (décision 66), le `n-…` à la place du `m-…`, sous une chaîne de séparation distincte (`"asl/annuaire/1"`), pour ne jamais rencontrer celui d'un service de machine ; **forme exacte arrêtée par la PR de code de la décision 66** (0.37.0), **et le vecteur par celle-ci** (0.38.0) : `n-7MSV5RPCXBZH25PQM4ZPE5X87P` → `s-294B4BA9XHXFZ5DQ8Q7T35M7PY`, `asl_registre::asl_directory_derive` : `SHA-256("asl/annuaire/1" ‖ n (16 octets) ‖ "asl-directory")[0..16]`, par la fonction commune `asl_registre::deriver` — les deux chaînes diffèrent dès leur cinquième octet. **Le nom `asl-directory` est réservé** : aucun daemon ne peut l'annoncer, et l'annonce est refusée explicitement. | **Décidé** (2026-09-28, Thierry) — **fait (0.38.0)** |
| 74 | **Les racines synthétisent l'`asl-directory`** de ce qu'elles savent déjà (question 21 (e)) : il existe dès que l'inscription est acceptée ; il est **vivant tant qu'au moins un membre a sa voie de fédération ouverte vers cette racine** (la règle des services, trente secondes au plus ; chaque racine juge seule, rien ne se réplique) ; ses adresses sont les locateurs publiés par chaque membre (`--locator`, donc le vrai port). **Aucun ajout de protocole côté membre.** **Pas de sonde « depuis l'extérieur » en v1** : vivant veut dire « la voie tient », pas « joignable depuis l'Internet » (décision 83, question 22 reportée). | **Décidé** (2026-09-28, Thierry) — **fait (0.38.0)** |
| 75 | **Un seul `asl-directory` par annuaire logique**, vivant si l'un des membres l'est (décision 52), qui rend **l'adresse de chaque membre vivant avec SON `n-…`** (question 21 (c)) — le client épingle la bonne clé, comme au `421` (décision 59). La réponse de `GET /v1/ou` pour ce service est **le corps du `421`** — `annuaire`, `adresses`, `identites` — **plus `service`**, une chaîne que le lecteur de renvoi d'aujourd'hui saute ; `404` quand aucun membre n'est vivant, sous C9. Un champ ajouté à la réponse d'annonce aurait cassé les clients : son décodeur refuse tout champ inconnu. | **Décidé** (2026-09-28, Thierry) — la forme du corps est proposée par la spécification ; **fait (0.38.0)** |
| 76 | **Les racines sur un autre port : `GET /v1/racines`, pas d'`asl-directory`** (question 21 (b)). **Au moins une racine écoute sur 6630**, et c'est elle que la liste embarquée garantit (l'amorçage) ; les autres peuvent écouter ailleurs, et les clients l'apprennent par `GET /v1/racines` (décision 56, ports compris), qu'ils **relisent et gardent en cache**. Le client ne le fait pas aujourd'hui : il ne lit la liste que pour `asl roots`, qui l'affiche — travail client. Ce qu'un cache a le droit de changer : décision 85. | **Décidé** (2026-09-28, Thierry) — à coder côté client |
| 77 | **Qui résout l'`asl-directory`** (question 21 (d)) : **pas public** — il porte l'IP de la maison. ~~Le cercle du `421`~~ — **corrigé par la décision 79** : le cercle étroit — le propriétaire de l'annuaire, les administrateurs des racines, et les comptes qui tiennent un droit sur au moins un domaine hébergé par cet annuaire —, **qui n'est pas celui du `421`**, plus large et inchangé ; les adresses à `localiser` seul (décision 80). Calculé à la lecture, aucun droit écrit. | **Décidé** (2026-09-28, Thierry) ; cercle précisé par les décisions 79 et 80 ; **fait (0.38.0)** |
| 78 | **Ce qu'apporte l'`asl-directory`** (question 21 (f)) : un annuaire se trouve comme n'importe quel service, sans attendre un `421` ; son état vivant ou parti se voit — sur la tuile de l'annuaire dans les applications, sans écran spécial (décision 84) ; il prépare la question 12 (résoudre à la maison sans racines). **Le `421` et `GET /v1/annuaires` restent tels quels.** | **Décidé** (2026-09-28, Thierry) |
| 79 | **Le cercle de l'`asl-directory` est étroit, et le `421` ne change pas** (`annuaires.md` §7, question 24 ; corrige la décision 77). Le résolvent le propriétaire de l'annuaire, les administrateurs des racines, et les comptes qui tiennent un droit sur au moins un domaine hébergé par cet annuaire ; `rattacher` seul, ou un droit sur une seule machine ou un seul service du domaine, n'y fait pas entrer. **Le `421` continue d'aller à toute machine rattachée à un domaine confié**, quel que soit son propriétaire : sans lui, une machine d'un autre compte rangée dans le domaine ne pourrait plus annoncer du tout. **Conséquence assumée** : une machine rangée dans le domaine connaît forcément l'adresse de l'annuaire, mais le COMPTE qui la possède ne peut pas résoudre `asl-directory` sans le droit. | **Décidé** (2026-09-28, Thierry) — **fait (0.38.0)** |
| 80 | **`localiser` seul donne les adresses de l'`asl-directory`**, comme partout ailleurs ; `voir` seul (ou `administrer`, qui l'emporte, et n'emporte pas `localiser` : décision 87) apprend qu'il existe et qu'il est vivant : **`200` sans `adresses` ni `identites`** — `{"service":"s-…","annuaire":"n-…"}`. Absents, pas vides (`[]` dirait « personne ne répond », contre le `200`) ; la règle d'omission des listes ; C9 garde ses deux seules réponses, `200` et `404`, au même délai ; pas un second verbe, qui doublerait route, décision et essai de C9. | **Décidé** (2026-09-28, Thierry ; forme proposée par la spécification) — **fait (0.38.0)** |
| 81 | **Repli sur l'adresse déclarée** : un membre vivant qui n'a publié aucun locateur figure dans l'`asl-directory` sous son adresse déclarée, comme au `421`. | **Décidé** (2026-09-28, Thierry) — **fait (0.38.0)** |
| 82 | **Aucun membre vivant : `404`**, la même réponse que pour « inexistant » et « hors du cercle », après le même délai (C9) — la règle de tout service déclaré dont aucun daemon ne tient la connexion. | **Décidé** (2026-09-28, Thierry) — **fait (0.38.0)** |
| 83 | **Pas de sonde de l'`asl-directory` en v1.** Une sonde des racines vers les locateurs publiés viendra quand une machine hors de la maison devra réellement se servir de l'annuaire ; la question 22 reste ouverte, **reportée**. | **Décidé** (2026-09-28, Thierry) |
| 84 | **Les applications montrent l'état de l'annuaire local sur sa tuile** (« Mon annuaire local ») : vivant ou parti (question 23), **lu dans `GET /v1/annuaires`** — le champ `voie` de chaque membre (décision 86) —, **pas via l'`asl-directory`**, que les applications ne lisent pas. Pas de place dans les listes de services par machine ; **aucune recherche générale** — `GET /v1/ou?service=asl-directory` ne rend aucun annuaire, on résout par `n-…`. ~~La tuile lit `GET /v1/ou/{n-…}/asl-directory`, servi aussi sur la voie appareil.~~ — **réécrit par la décision 86** : l'`asl-directory` reste le moyen des machines, sur la voie machine seulement. | **Décidé** (2026-09-28, Thierry) ; **réécrit** (2026-09-29, Thierry ; décision 86) — **fait côté serveur (0.38.0)** ; à coder dans les applications |
| 85 | **La liste relue par `GET /v1/racines` ne change QUE les locateurs — adresses et ports — des racines déjà connues**, identifiées par leur `n-…` embarqué (question 25). Elle n'ajoute ni ne retire aucune racine : **une racine nouvelle exige une nouvelle version du client**. Ordre d'essai : d'abord les locateurs appris, puis ceux de la liste embarquée en secours ; l'amorçage reste garanti par la racine sur 6630. | **Décidé** (2026-09-28, Thierry) — à coder côté client |
| 86 | **Les applications ne lisent PAS l'`asl-directory`** (`annuaires.md` §7, question 26) : `GET /v1/ou/{n-…}/asl-directory` n'est servi que **sur la voie machine** — le moyen des daemons et d'`asl` —, jamais sur la voie appareil. **`GET /v1/annuaires`** (et `GET /v1/inscriptions`, la vue des administrateurs des racines) **gagne, par membre, `"voie":"ouverte"` ou `"voie":"tombee"`** : la voie de fédération de ce membre vers **la racine qui répond** tient (la règle des services, trente secondes au plus, décision 74), ou a tenu depuis qu'elle tourne et s'est tue. **Absent** tant que ce membre ne lui a pas parlé depuis son démarrage, comme `paire`, et pour une inscription non acceptée. **Une chaîne, pas un booléen** : les décodeurs clients déployés ne sautent qu'une clé inconnue à valeur chaîne ou entier. La tuile « Mon annuaire local » en tire vivant (un membre `ouverte`), parti (aucun ouvert, un `tombee`) ou pas de nouvelles. **Conséquence assumée** : qui tient un droit sur un domaine hébergé sans être propriétaire de l'annuaire n'a pas de tuile et ne voit pas cet état dans l'application ; la fiche du domaine pourra le montrer plus tard (question 28, ouverte). | **Décidé** (2026-09-29, Thierry ; forme du champ proposée par la spécification) — **fait (0.38.0)** |
| 87 | **`administrer` n'emporte PAS `localiser`, pour l'`asl-directory` comme partout** (`annuaires.md` §7, question 27) : la décision 44 ne change pas. Un administrateur d'un domaine hébergé reçoit la réponse réduite, sans `adresses` ni `identites` (décision 80). **Il peut s'accorder `localiser`** sur ce domaine, explicitement — administrer, c'est gérer les droits accordés sur lui (`modele.md` §2.13) — : un geste conscient, écrit avec son donneur et sa date, qui se voit et se retire comme tout droit. | **Décidé** (2026-09-29, Thierry) — **fait (0.38.0)** |

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
   - **Tant qu'un banc n'avait pas de `--identity-key`** (jusqu'à 0.34.0, qui
     la rend obligatoire), il estampillait sous
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
5. **La migration des `s-…` vers leur forme dérivée — FAIT (0.37.0,
   décisions 66 et 72).** Le `s-…` d'un service est désormais les seize
   premiers octets de `SHA-256("asl/service/1" ‖ m (16 octets) ‖ nom)`
   (`modele.md` §2.4, la forme exacte et son vecteur). Trois temps, tous dans
   `asl-store` (`src/identifiants.rs`) :

   - **À la première ouverture par la 0.37.0** (format 3 → 4), chaque
     entrepôt — racine ou membre — fait passer chacun de ses services sous
     son dérivé, **dans la transaction d'ouverture**, avec tout ce qui le
     nomme : la table des services, l'index `services-par-nom` (reconstruit
     en entier), les droits dont l'élément est ce service et leur index par
     élément, les services du pair en attente de leur machine
     (`services-en-attente`), et une **correspondance** ancien → dérivé
     (table `services-renommes`). Avant d'écrire, il vérifie l'invariant : un
     service par `(machine, nom)`, un dérivé par service — **deux
     enregistrements pour le même `(machine, nom)`, ou deux services qui
     dériveraient au même `s-…`, font refuser l'ouverture** en les nommant
     (`Faute::Doublon`, `Faute::Collision`), rien n'étant écrit. Le journal
     d'exploitation dit : `migration A1 : N service(s) ré-identifié(s) sur M
     — … ; D droit(s) les suivent, A service(s) du pair en attente
     re-dérivé(s)`, une fois, même quand N vaut zéro. **L'estampille des
     services ne change pas, et le journal d'opérations n'est PAS réécrit** :
     rien n'est déclaré, tout est renommé ; la voie ne se coupe pas.
   - **À l'application d'une opération `service`** venue d'un pair, le
     `s-…` du fil n'est qu'indicatif : le service se range sous le dérivé
     recalculé depuis `(machine, nom)`. Si le fil portait autre chose — un
     pair encore en 0.36.0 —, la correspondance le retient, et le tireur le
     dit : `service s-… venu de n-… rangé sous s-…, son identifiant dérivé :
     ce pair n'est pas encore en 0.37.0 (décision 72) — mettez-le à jour`.
     Entre deux déclarations du même `(machine, nom)`, il n'y a plus de
     perdant : **le même `s-…` des deux côtés**, et la plus petite estampille
     reste dans l'enregistrement, pour que les deux entrepôts portent les
     mêmes octets.
   - **À l'application d'une opération `droit`** dont l'élément est un `s-…`
     qu'on ne tient pas, la correspondance le traduit : c'est le nôtre d'avant
     la migration (deux racines qui avaient convergé tenaient le même aléa),
     ou celui qu'une opération `service` du pair nous a appris.

   **La réplication mixte, pendant le déploiement** — éprouvée entre le code
   de la 0.36.0 et celui de la 0.37.0 sur la même fixture
   (`crates/asl-store/tests/fixtures/entrepot-0.36.0.redb`) :

   | Le cas | Ce qui se passe | Ce qui en reste |
   |---|---|---|
   | **Migré ← pas encore migré** : services | Rangés sous le dérivé ; la correspondance retient l'aléa ; le journal dit l'écart. | Rien : un seul service, sous le dérivé. |
   | **Migré ← pas encore migré** : droits sur un service | Traduits par la correspondance, et rangés. | Rien. |
   | **Pas encore migré ← migré** : services | La 0.36.0 range le dérivé comme un aléa quelconque : c'est un service qu'elle n'avait pas (les deux côtés avaient convergé sur les anciens). Si elle venait de déclarer le même `(machine, nom)` sous son aléa, la règle d'hier départage — la plus petite estampille —, et la session suit le gagnant (0.36.0) ; l'aléa, s'il gagne chez elle, se range sous le dérivé chez le migré. À sa propre migration, elle fait passer les siens sous leur dérivé. | Rien : après les deux migrations, les deux entrepôts tiennent les mêmes `s-…`. |
   | **Pas encore migré ← migré** : un droit accordé, après la migration de l'un, sur un service que l'autre tient encore sous l'aléa | **La 0.36.0 le refuse** (`peut_entrer` : élément inconnu) et avance son curseur : il est perdu de ce côté, et sa propre migration ne le rattrape pas. | **Un droit « Un service » qui n'existe que sur une racine.** D'où la règle de déploiement : les deux racines l'une après l'autre, **sans accorder de droit sur un service entre les deux**. Il n'y en avait aucun en production au 2026-09-29 (copies de speedy et d'argon, migrées hors ligne) ; un droit perdu ainsi se ré-accorde. |
   | **Membre migré ↔ membre pas encore migré** | Les membres ne tiennent pas de droits (décision 68, mécanisme ouvert) : seuls les services voyagent, et ils se rangent comme ci-dessus. Aux racines, les deux rapports portent deux `s-…` pour le même `(machine, nom)` — ceux-ci sont rangés par membre, et la racine rend celui du rapport retenu, comme en 0.36.0 ; elle **signale** le membre qui rapporte des `s-…` non dérivés. | Rien, dès que le second membre est à jour : un seul `s-…`, identique partout. |

   **Aucune version minimale du pair n'est exigée** au-delà de la 0.36.0
   (qui garde les services d'une machine pas encore reçue, et déplace la
   session vivante d'un `s-…` remplacé) : la 0.37.0 lit tout ce que la
   0.36.0 écrit, et l'inverse est vrai sauf pour le cas du droit ci-dessus.
   **Le retour arrière** d'un entrepôt migré vers la 0.36.0 est refusé à
   l'ouverture (`l'entrepôt est au format 4, que ce binaire ne connaît pas`) :
   une 0.36.0 frapperait de nouveau des aléas, que rien ne migrerait plus. Il
   passe par la sauvegarde d'avant la mise à jour (`README.md`, « Déployer la
   0.37.0 »).
