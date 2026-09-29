# Modèle

Ce que l'annuaire connaît, ce qui lie ces objets, et ce que « en ligne » veut
dire exactement.

**Ce document tranche.** Chaque décision porte sa raison, et les points restés
ouverts sont rassemblés en fin de document plutôt que dispersés — pour qu'on
voie d'un coup d'œil ce qui n'est pas décidé.

---

## 1. L'exigence, et le fait qui la contrarie

**EXIGENCE : un daemon annoncé doit être joignable depuis l'Internet.** C'est le
but du produit. Un client quelconque, où qu'il soit, doit pouvoir ouvrir une
connexion vers le point d'écoute que l'annuaire lui donne ; un annuaire qui
rendrait des adresses inatteignables ne servirait à rien.

### IPv6 d'abord, IPv4 en repli — et ce n'est pas une préférence

**C'est la réponse principale à l'exigence.** Une machine qui a une adresse IPv6
publique n'est derrière aucun NAT : il n'y a rien à traverser, juste un pare-feu
à ouvrir. Le port qu'elle annonce est le port par lequel on l'atteint.

Le NAT n'est donc pas le cas général, c'est **le cas dégradé d'IPv4**. Cela
change la forme du produit : au lieu d'un annuaire qui doit résoudre un problème
de traversée, on a un annuaire qui fonctionne pleinement sur IPv6 et qui, sur
IPv4, mesure et rapporte ce qu'il constate.

| Cas | Exigence tenue ? |
|---|---|
| IPv6 publique | **Oui**, sans rien faire. C'est la voie normale. |
| IPv4 publique, ou port redirigé | Oui. |
| IPv4 derrière un NAT | **Non**, et *comment* l'y amener n'est pas décidé (§6.3). |

**Partout où des adresses sont rendues, IPv6 vient en premier** — candidats de
résolution, ordre d'essai, ordre de sonde. IPv4 est le repli, et il est nommé
comme tel plutôt que traité à égalité.

Ce que cela impose au modèle **dès maintenant**, quelle que soit la réponse
qu'on donnera plus tard :

- Le **port local** qu'un daemon annonce ne veut rien dire vu de l'extérieur
  quand il est derrière un NAT.
- L'**adresse source** que l'annuaire observe sur la connexion d'annonce est une
  adresse réelle — mais elle n'est réutilisable par un tiers que si le NAT est
  *indépendant du point distant* (« cône complet »). Sur un NAT restreint ou
  symétrique, elle ne l'est pas.
- Donc **l'annuaire MESURE la joignabilité, et la dit** — il ne la suppose
  jamais. Tant que la question du NAT n'est pas tranchée, cette mesure est ce
  qui apprend à un administrateur que son daemon ne tient pas l'exigence. Sans
  elle, il l'apprendra le jour où quelqu'un s'en plaindra.

En particulier, le mot « en ligne » est banni de l'API : il confond « le daemon
parle » avec « on peut l'atteindre », et c'est exactement la distinction que le
NAT rend visible.

---

## 2. Les objets

### 2.1 Utilisateur

Un particulier, ou un administrateur pour une entreprise. Créé depuis
l'application iOS ou Android.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `u-` + 26 caractères. **Public — c'est ce qu'on donne à un ami pour qu'il vous autorise.** |
| `appareils` | Les téléphones enrôlés qui peuvent administrer ce compte. |
| `machines` | Les machines en gestion — celles qui servent comme celles qui consomment. |
| `alias` | **Facultatif.** Unique, public, choisi. Sert à être retrouvé (voir ci-dessous). |
| `effacé le` | Date, ou vide — et la **cause** : `titulaire`, `orphelin`, `exploitant`. Un compte effacé n'a plus rien d'autre (voir « Effacer son compte », ci-dessous). |

### Aucune donnée personnelle n'est hébergée

**Pas de courriel. Pas de numéro. Pas de nom. Pas de mot de passe.** Un compte
est un identifiant, un jeu de clés publiques, et rien d'autre.

Ce n'est pas une posture : c'est ce qui rend cet annuaire tenable. Il sait déjà
où écoutent des services qui ne publient pas leur port ; y ajouter une identité
civile ferait de sa base la cible la plus intéressante du produit. **Ce qu'on
n'héberge pas ne fuit pas, ne se subpoena pas, et ne se perd pas.**

### L'alias public — la seule exception, et elle est choisie

Un utilisateur PEUT enregistrer un **alias** : une chaîne unique et publique,
pour qu'un autre utilisateur le retrouve sans avoir à recopier 26 caractères.

**Ce que l'alias coûte, et qu'il faut dire au moment de le choisir :**

- Il est **public par construction**. C'est son emploi : `alias → identifiant`
  est une requête que quiconque peut faire.
- Donc l'espace des alias **est énumérable**, contrairement au reste de
  l'annuaire. Un inconnu peut essayer des alias et découvrir lesquels existent.
- Il ne rend **rien d'autre que l'identifiant** — ni machines, ni services, ni
  état. Savoir qu'un alias existe n'ouvre aucune porte : l'accès reste une
  autorisation nominative (§2.5).

**L'alias est facultatif, et le rester est une position tenable.** Un utilisateur
qui ne l'enregistre pas n'est trouvable que par son identifiant, transmis de la
main à la main — SMS, courriel, à voix haute. C'est le mode le plus discret, et
il doit rester le défaut.

**Sa forme, depuis 0.26.0** (`replication.md` décision 46, Thierry,
2026-09-27) : **de l'UTF-8, sensible à la casse, rangé en NFC**, comme l'alias
de domaine et l'alias de machine — « une machine comme un domaine, comme un
compte dispose d'un alias : chaîne UTF-8 sensible à la casse ». Trois à
trente-deux octets rangés, sans contrôle, forceur de sens d'écriture, marque
d'ordre des octets, `"` ni `\`, et **un deuxième caractère qui n'est pas un
tiret**, pour qu'il ne se confonde jamais avec un `u-…` dans le champ où l'on
tape l'un ou l'autre. **Il reste UNIQUE** : c'est par lui qu'on retrouve
quelqu'un. « Thierry » et « thierry » sont deux alias, que deux comptes peuvent
tenir.

~~Minuscules ASCII, chiffres, `-`, `_`, `.`~~ — la forme d'avant 0.26.0 : une
CLÉ, et l'équivalence Unicode aurait fait qu'un même alias s'écrive de deux
façons. **C'est le NFC qui règle désormais l'équivalence**, à l'écriture comme
à la résolution ; les alias d'avant, tous en minuscules ASCII, sont déjà dans
leur forme et ne changent pas.

**Le coût, nommé : la ressemblance.** Unique et sensible à la casse, l'alias
« Thierry » n'empêche plus « thierry » ; en UTF-8, il n'empêche pas non plus
un sosie typographique (« Тhierry », dont le T est cyrillique). C'est le prix
de l'UTF-8 pour une clé publique, et il est choisi : **l'application doit
montrer l'identifiant `u-…` à côté de l'alias résolu**, et c'est l'identifiant
qui fait foi. Voir §6.

### Effacer son compte — le geste, ce qui part, ce qui reste

**Décidé le 2026-09-18.** Un compte s'ouvre depuis un appareil ; il se ferme
depuis un appareil, et de la même main. Jusqu'ici l'annuaire savait révoquer
un appareil, une clé de machine, une autorisation — jamais le compte qui les
tient, et trois comptes de banc sans plus aucune clé derrière eux l'ont montré :
un compte que personne ne peut plus administrer restait là, indéfiniment,
parce que rien n'était écrit pour qu'il s'en aille.

**Pourquoi c'est un geste du titulaire, et de lui seul.** Le compte est un jeu
de clés ; qui détient une clé vivante détient le compte, et personne d'autre
n'en détient rien — ni l'exploitant, qui ne tient que des clés publiques, ni
une machine, qui agit *au nom* du compte sans en décider (§2.3). Effacer est
donc un verbe de la voie appareil, sous biométrie, et **c'est le dernier acte
de la clé qui le demande** : elle est révoquée dans la même transaction que
tout le reste, et la connexion qui a porté la demande est fermée par
l'annuaire. Le verbe est `DELETE /v1/compte` (`protocole.md` §2.2).

**Ce qui part, dans UNE transaction** — un effacement à moitié fait serait un
compte dans un état qu'aucun autre chemin ne produit :

| | Ce qu'il en advient |
|---|---|
| Les **appareils** | Tous révoqués, celui qui demande compris ; leurs enregistrements, leurs points de poussée et leurs descriptions **effacés**. Il n'y a plus d'écran « Compte » à qui montrer ce qu'on a retiré. |
| Les **machines** | Clés révoquées, connexions fermées, baux tombés (§2.3, « Révoquer ») ; les codes d'enrôlement en cours annulés ; les enregistrements **effacés**, et leurs **services** déclarés avec eux. |
| Les **autorisations**, accordées ET reçues | **Retirées** — effacées, non marquées. L'autre partie ne voit **plus rien** : la ligne quitte sa liste, et ses machines ne résolvent plus rien de ce compte, à la seconde, comme après une révocation. Une ligne « révoquée » qui nommerait un compte qui n'existe plus lui montrerait un `u-…` sur lequel `GET /v1/utilisateurs/{u}` répond désormais `404` ; c'est ce qu'il faut lui épargner. |
| L'**alias** | **Libéré.** L'alias est une réclamation (`replication.md` §3.2) ; l'effacement retire la réclamation, exactement comme `DELETE /v1/alias`. Si un autre compte l'attendait en file, il l'obtient. |

**Ce qui reste, et pourquoi.** L'identifiant `u-…`, marqué **effacé**, avec la
date et la cause — et rien d'autre : ni clé, ni alias, ni arête, ni machine.
Il reste pour trois raisons qui tiennent chacune seule :

- **la réplication doit converger.** Une racine qui applique l'effacement
  après avoir reçu une écriture de ce compte doit pouvoir dire « effacé,
  refusé » plutôt que « inconnu, créons-le » ; sans marque, une opération en
  retard ressusciterait un compte que son titulaire a fermé
  (`replication.md` §3.2) ;
- **les caches doivent converger.** Une application qui tient encore ce
  `u-…` dans une autorisation, un carnet, un écran, doit lire une réponse qui
  ne se confond pas avec une coupure ;
- **un identifiant ne se réattribue pas.** Cent vingt-huit bits ne
  collisionnent pas ; mais un identifiant *libéré* est un identifiant qu'un
  malchanceux pourrait un jour retirer, et hériter des arêtes que quelqu'un
  aurait oublié de retirer chez lui. Marqué, il ne l'est pas.

**Et c'est compatible avec C13, parce qu'un `u-…` sans rien derrière n'est pas
une donnée personnelle.** C13 interdit ce qui *identifie une personne* — un
courriel, un nom, un numéro. Un identifiant tiré au hasard, dont on a retiré la
clé qui le prouvait, l'alias qui le nommait et tout ce qu'il possédait, ne
désigne plus personne : il dit qu'un compte a existé et qu'il n'existe plus.
C'est la même chose qu'un appareil révoqué, et pour la même raison — l'état
qu'on garde est celui qui empêche une erreur, pas celui qui décrit quelqu'un.

**Le journal (`journal.md`) n'est pas touché à part, et c'est voulu.** Les
entrées brutes qui nomment ce compte expirent à quatre-vingt-dix jours comme
toutes les autres (C18) ; les agrégats, qui ne nomment personne, survivent.
Effacer le journal d'un compte au moment où il s'efface détruirait la preuve
au moment précis où l'on peut en avoir besoin — un compte qui s'efface juste
après un abus est exactement le cas que la rétention existe pour couvrir
(`journal.md` §5 bis). Ce que cela coûte est dit : pendant un trimestre, le
journal d'exploitation sait encore ce que ce `u-…` a demandé.

**Un effacement ne se défait pas.** Il est de la classe des révocations
(`replication.md` §3.2) : il gagne sur toute écriture concurrente, et une
écriture pour ce compte qui arrive après — rejeu, retard, autre racine — est
refusée. Il n'y a pas de « restaurer » : ce qui rendrait une restauration
possible est précisément ce qu'on vient d'effacer.

#### Un compte sans aucun appareil vivant s'efface tout seul — la règle des orphelins

**Un compte dont aucun appareil n'est vivant ne peut plus rien décider** — ni
enrôler, ni révoquer, ni rejoindre, ni s'effacer : il n'y a plus de clé pour
signer. Ce n'est pas une limite qu'on pourrait lever, c'est la construction
même du produit (§2.2, « il n'y a donc rien à exporter »). Un tel compte est
un enregistrement que personne ne pourra plus jamais toucher, et qui tient
un alias et des arêtes pour rien. **La racine l'efface elle-même, après un
délai de grâce, et le dit au journal d'exploitation.**

| | La règle |
|---|---|
| **Ce qui déclenche le décompte** | La révocation du **dernier appareil vivant** du compte. (La création du compte enrôle le premier appareil — `POST /v1/comptes` — donc un compte sans aucun appareil jamais enrôlé n'existe pas.) |
| **Le délai** | **Trente jours**, cause `orphelin`. |
| **Ce qui l'arrête** | Rien ne peut l'arrêter de l'intérieur — c'est le point : sans clé vivante, personne ne peut enrôler un appareil pour ce compte. Le délai n'est pas là pour que le titulaire réagisse. |
| **Comment la racine sait la date** | Par `révoqué le` sur l'appareil (§2.2) — une date, celle de la racine qui a révoqué, répliquée telle quelle (§2.10). Le compte est orphelin depuis le `révoqué le` le plus récent de ses appareils. |
| **Qui efface, à deux racines** | **Chacune peut.** L'opération est idempotente et de la classe « révocation, toujours » : la première qui passe le délai efface, l'autre applique ce qu'elle reçoit — ou, si elle a effacé de son côté dans la même minute, applique un effacement sur un compte déjà effacé, ce qui ne fait rien. Les deux tiennent la même date, donc la même échéance. |
| **Ce qui se journalise** | Une ligne du journal d'exploitation, avec l'identifiant et la cause — comme toute révocation. |

**Pourquoi trente jours, alors que le titulaire ne peut de toute façon rien
faire.** Il faut être honnête sur ce que le délai n'achète pas : **il ne
laisse pas au titulaire qui a perdu son dernier téléphone le temps de s'en
apercevoir**, parce que s'en apercevoir ne lui servirait à rien — sans appareil
vivant, il ne peut ni rejoindre son compte ni y enrôler quoi que ce soit. Ce
que le délai achète est ailleurs :

- **la fenêtre de propagation.** Une révocation prise sur une racine pendant
  une coupure met du temps à atteindre l'autre ; un enrôlement pris sur
  l'autre pendant la même coupure aussi. Un délai de quelques secondes
  ferait effacer un compte dont un appareil venait d'être enrôlé ailleurs.
  Trente jours couvrent toute coupure qu'on accepterait de tolérer, et
  c'est la rétention du journal d'opérations (`replication.md` §5.4) : au-delà,
  une racine ne se rattrape plus, elle se reconstruit ;
- **la lisibilité.** Un compte qui disparaît à la seconde où l'on révoque son
  dernier appareil est un compte qu'on efface par accident, depuis l'écran
  d'un autre appareil qu'on est en train de retirer. Trente jours, c'est le
  temps de voir dans le journal d'exploitation ce qui va s'effacer, et de
  s'en étonner si l'on doit.

**Ce que cela implique, et que l'application dit déjà : un compte à un seul
appareil est un compte qu'un téléphone perdu ferme** (§2.2). La règle des
orphelins ne change pas ce fait, elle en tire la conséquence : trente jours
après la perte, le compte n'existe plus, son alias est libre, et ce que ses
amis lui avaient accordé est retiré. **L'application doit le dire en ces
termes, à l'enrôlement et dans l'écran Compte** — « avec un seul appareil,
perdre ce téléphone efface ce compte » —, et non seulement pousser à enrôler
un second appareil.

**Le réglage d'exploitant : `--orphans <jours>`**, trente par défaut, **`0`
pour jamais**. Une racine peut vouloir « jamais » pour une raison qui tient :
son exploitant veut que tout effacement soit un acte humain — le sien, avec
`--forget`, ci-dessous —, parce qu'il tient un annuaire où chaque compte a
un visage, ou parce qu'il veut voir ses orphelins avant qu'ils partent. Ce
qu'il y perd est dit : des comptes que personne ne peut plus administrer, qui
tiennent des alias et des arêtes indéfiniment.

#### Ce que la règle n'attrape pas, et le verbe d'exploitant qui le couvre

**Un appareil qui ne s'est pas présenté depuis longtemps n'est pas « mort »
pour autant.** Un téléphone rangé dans un tiroir six mois est un appareil
vivant : sa clé existe, et il signera le jour où on le rallume. L'annuaire
n'affirme que ce qu'il mesure (C6), et il ne mesure pas la mort d'une clé —
il constate une révocation, ou rien. **La règle des orphelins ne compte donc
que les révocations, jamais le silence.**

C'est pourquoi elle **n'attrape pas** les trois comptes du banc `nitrogen`
qui ont motivé ce chantier (`u-24MF…`, `u-6TEE…`, `u-6J5S…`) : leurs clés ont
été effacées **côté appareil**, sans révocation — un simulateur remis à zéro,
une app non sandboxée qui a écrit sa clé au mauvais endroit —, et l'annuaire
les croit vivants depuis leur création. Il n'y a que deux sorties honnêtes :
les laisser, ou un geste d'exploitant, **une fois**, par quelqu'un qui *sait*
que la clé est perdue parce que c'est lui qui l'a perdue.

**Le verbe : `asl-server --forget <u-…> --store <fichier>`.** Hors ligne,
entrepôt arrêté, comme `--new-identity-key` (`replication.md` §8) : il ouvre
l'entrepôt, écrit l'effacement du compte — le même, avec la cause
`exploitant` — dans la même transaction et dans le journal d'opérations, pour
que l'autre racine l'applique au prochain rattrapage, imprime ce qu'il a fait,
et s'arrête. Il refuse de tourner si le daemon tient l'entrepôt, et il ne
prend qu'un identifiant à la fois : c'est un geste qu'on fait en regardant.

**C'est l'exception qui confirme la règle, et il faut la borner en le
disant.** La règle est : *personne d'autre que le titulaire n'efface un
compte, et la racine ne le fait qu'à sa place quand il ne peut plus rien
faire, sur un fait qu'elle a constaté.* `--forget` est ce qui reste quand
aucun des deux ne tient — la clé est perdue, et l'annuaire ne peut pas le
savoir. Il n'est pas un outil de modération : l'exploitant d'une racine qui
voudrait fermer le compte de quelqu'un a d'autres questions à se poser, et ce
document ne les instruit pas. Ce qu'il coûte est dit : **il n'y a rien dans
l'entrepôt qui distingue « la clé est perdue » de « l'exploitant l'a
décidé »**, sinon la cause `exploitant` elle-même, qui dit exactement cela —
un humain, sur la machine, l'a voulu.

#### Ce que les applications font, et ce qu'`asl` ne fait pas

**Un geste « Effacer mon compte » dans l'écran Compte** — iOS, macOS,
Android —, sous biométrie, en bas et en rouge comme « Révoquer » l'est pour un
appareil : visible, pas enfoui, parce que c'est le geste qu'on cherche quand
on a une raison de le chercher. Avant de signer, **une confirmation qui dit ce
qui part et ce qui ne revient pas**, dans ces termes et pas dans une page
d'aide (c'est la règle de §2.5 : un utilisateur qui apprend après coup n'a pas
consenti, il a cliqué) :

- tous les appareils de ce compte, celui-ci compris ;
- toutes ses machines, et les services qu'elles annoncent — les daemons qui
  tournent perdront leur bail à la seconde ;
- tous les accès, ceux qu'on a accordés et ceux qu'on a reçus ;
- l'alias, qui redevient libre ;
- et que rien de tout cela ne revient : il n'y a pas de « restaurer ».

Puis `DELETE /v1/compte`, la lecture du `204`, et **le carnet local vidé** —
identifiant, clé (détruite dans l'enclave ou le Keystore : elle est révoquée,
et une clé révoquée qui traîne est une clé qui fera croire à un compte),
noms locaux, préférences d'affichage — et **le retour à l'écran d'accueil**,
celui qui propose d'ouvrir un compte ou d'en rejoindre un. La connexion tombe
juste après le `204` ; l'application ne doit pas le lire comme une panne.

**Sur le Mac, l'identité de machine part aussi.** L'app macOS tient dans son
conteneur l'identité de la machine (`Application Support/asl/identite`) que
`asl` lit par défaut sur cette machine ; sa clé est révoquée par l'effacement, et un fichier
d'identité dont la clé ne vaut plus rien ferait rendre `401` à chaque `asl`
sans dire pourquoi. L'app l'efface avec le carnet.

**`asl` n'a rien à y faire, et n'aura pas de verbe.** Une machine ne décide
pas du compte (§2.3) ; ce qu'elle voit d'un effacement est sa connexion
fermée, puis `401` — comme d'une révocation de clé, et elle n'a pas à
distinguer les deux. `asl diagnose` dira « clé refusée », ce qui est exact.

### 2.2 Appareil

Le téléphone. Un compte en porte au moins un, et **c'est l'appareil qui signe**,
jamais l'utilisateur : il n'y a pas de mot de passe dans ce produit.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `a-` + 26 caractères. |
| `clé publique` | La partie publique d'une clé qui vit dans le matériel sécurisé du téléphone et ne peut être employée qu'après une confirmation biométrique. **P-256** — la Secure Enclave et StrongBox ne font que cette courbe (`protocole.md` §2.1). |
| `attestation` | Sous quoi l'appareil est entré : `aucune`, `apple` (App Attest), `android` (l'attestation de clé du Keystore, contre une racine que l'exploitant épingle), `invitation` (un code émis par l'exploitant, servi depuis le 2026-09-24 — `protocole.md` §2.2), ou **`attendue`** — une clé apportée par un autre appareil du compte sous une posture exigée, que son porteur n'a pas encore prouvée ni attestée : il n'est pas entré (2026-09-21, `protocole.md` §2.2). `google` — Play Integrity — n'a jamais été acceptée et est abandonnée (`protocole.md` §2.1, décision du 2026-09-16, C19). **Une valeur, pas une absence** : un annuaire en posture facultative laisse entrer des appareils sans preuve, et il faut pouvoir dire lesquels — c'est ce qu'on regarde le jour où l'on resserre, pour savoir qui prévenir. |
| `point de poussée` | Une URL UnifiedPush, que le distributeur choisi par l'utilisateur a donnée à l'appareil — pour les notifications (§2.6), sur Android. Déposée par l'appareil lui-même, une seule, révoquée avec lui. Ni APNs ni FCM depuis le 2026-09-25 (C19). |
| `plateforme` | `ios`, `android` ou `macos` — ce que l'appareil fait tourner. **Déclaré par l'appareil lui-même**, absent tant qu'il ne l'a pas fait. |
| `modele` | « iPhone 17 », « MacBook Pro (2019) » — le nom de son **modèle**, libre, 1 à 64 octets, aux règles du nom de machine (§2.3). Déclaré avec la plate-forme, absent avec elle. |
| `enrôlé le` | Date. |
| `révoqué le` | Date, ou vide. **C'est la date que la règle des orphelins lit** (§2.1) : un compte est orphelin depuis le `révoqué le` le plus récent de ses appareils. |

**Ces deux dates sont promises ici depuis le premier jour, et l'entrepôt n'en
porte encore aucune** (2026-09-18 : `Appareil` porte un drapeau `revoque`, et
l'estampille est un compteur, pas une heure — §2.10). Tant que rien n'en avait
besoin, ce n'était pas un défaut : une colonne qui n'existe pas ne se remplit
pas (C13). **La règle des orphelins a besoin de `révoqué le`**, et c'est la PR
de code qui l'ajoute à l'enregistrement — un changement de format, donc un
cran mineur en 0.x — en millisecondes d'époque, comme toute date de ce
protocole (`protocole.md` §1.1). Une seule date, posée une fois, sur un
enregistrement qui ne vaut déjà plus rien : elle ne dessine aucun graphe
d'usage, et C18 n'a rien à en dire. `enrôlé le` n'est pas ajouté par la même
occasion — rien n'en a besoin, et « pendant qu'on y est » est la porte que
C13 nomme. **Les appareils déjà révoqués au moment du changement de format**
reçoivent pour `révoqué le` la date de la reprise de l'entrepôt : l'annuaire
ne sait pas mieux, et poser une date plus ancienne serait affirmer ce qu'il
n'a pas mesuré (C6).

**La plate-forme et le modèle sont une étiquette que l'appareil se pose
lui-même, pas une preuve.** L'annuaire ne vérifie rien de ce qu'elle dit — un
appareil pirate peut se dire « iPhone 17 ». Ce qui identifie un appareil est
son identifiant `a-…`, et c'est lui que les applications affichent à côté ;
l'étiquette sert à ce que l'écran Compte — celui qu'on regarde pour vérifier
qu'aucun appareil de trop n'est entré — montre « MacBook Pro » et non
« Autre », de quoi reconnaître les siens, jamais de quoi les prouver. Elle
reste sur un appareil révoqué, pour la même raison qu'il reste marqué :
« iPhone 17, révoqué » dit ce qu'on a retiré.

**C'est le MODÈLE, et jamais le nom que l'utilisateur a donné à son
téléphone.** « iPhone de Thierry » porte un prénom — précisément ce que C13
refuse — et l'application ne l'envoie pas ; « iPhone 17 » ne nomme personne. Le
précédent est la machine, qui a déjà un nom « pour l'humain » (§2.3) : ce que
le produit a décidé est qu'une étiquette d'affichage n'est pas une donnée
personnelle, et ce qui reste à décider, appareil par appareil, est ce qu'on
met dedans. **Un nom libre saisi par l'utilisateur et rangé sur l'annuaire est
exactement la « commodité » par laquelle C13 dit qu'elle tombera** ; s'il en
faut un, il vit dans le carnet local de l'application, et n'en sort pas.

**Les machines d'un compte voient ses appareils, sans rien pouvoir dessus.**
`asl enrolled`, sur une machine, rend la même liste que l'écran Compte —
identifiants, modèles, révoqués marqués (`protocole.md` §3,
`GET /v1/moi/appareils`). C'est une décision de produit : l'administrateur
d'une machine doit pouvoir répondre depuis un terminal à « quels appareils
administrent ce compte ? ». Ce qu'elle abaisse est dit là-bas — une clé de
machine compromise voit désormais qui administre le compte, sans pouvoir y
toucher.

**Un compte à un seul appareil est un compte qu'un téléphone perdu ferme
définitivement.** L'application le dit à l'enrôlement et pousse à en enrôler un
second ; elle ne l'impose pas. Depuis le 2026-09-18, « ferme » a un sens
précis : trente jours après la révocation de son dernier appareil vivant, la
racine efface le compte (§2.1, la règle des orphelins). Un téléphone perdu et
non révoqué, lui, laisse un compte que l'annuaire croit vivant — la règle ne
compte que ce qu'elle constate.

**Un second appareil ne s'ajoute pas en « important » le compte : il s'ajoute
en faisant enrôler SA clé par un appareil qui l'est déjà.** L'intuition
contraire — exporter l'identifiant `u-…` depuis le premier appareil, le lire
depuis le second — ne peut pas marcher ici, et ce n'est pas une limite
d'implémentation : l'identifiant est public et ne prouve rien, et la clé qui
prouve ne quitte jamais le matériel où elle est née. Il n'y a donc rien à
exporter. Le sens du geste est le sens inverse : **le nouvel appareil montre sa
clé publique** (un code à l'écran) ; **l'appareil déjà enrôlé la lit, la
présente à l'annuaire** (`POST /v1/appareils`, `protocole.md` §2.1 ter) et rend
en retour au nouveau l'identifiant du compte et le sien ; le nouveau prouve
alors sa clé sur sa propre connexion. Rien de secret ne passe d'un écran à
l'autre — une clé publique, deux identifiants —, et cela vaut quelle que soit
la paire d'appareils : deux téléphones, ou un Mac et un téléphone (le Mac
affiche un code, il n'en lit pas ; ce qu'il reçoit se colle).

**Et le nouvel appareil entre attesté, comme le premier — depuis le
2026-09-21.** La chaîne d'attestation de sa clé ne peut venir que de lui : elle
est liée au défi qu'il a tiré sur sa connexion AVANT de générer la clé
(`protocole.md` §2.1), et l'ancien appareil n'en sait rien. C'est donc au
moment où le nouveau prouve sa clé qu'il la présente — `POST /v1/attestation`,
la preuve et la chaîne en un verbe, sur la connexion tenue depuis le défi.
Ce que cela change à la cérémonie : le nouveau se connecte et tire son défi
**avant** de montrer sa clé, et garde sa connexion le temps que l'ancien la
lise et la présente ; si elle tombe, la clé ne s'attestera plus, et l'on
recommence avec une nouvelle. Sous une posture exigée, l'apport par l'ancien
ne fait pas entrer l'appareil : il est **`attendue`** jusqu'à sa preuve
attestée — visible dans Appareils, révocable, vivant pour la règle des
orphelins, jamais expiré. Sous une posture facultative, il entre `aucune` à
l'apport, comme avant, et sa chaîne — si son application la présente — le
fait passer à `android` ou `apple` (`protocole.md` §2.2, la table des
postures).

### 2.3 Machine

Déclarée par un utilisateur depuis l'application.

**Une machine n'est PAS forcément une machine qui héberge un daemon.** C'est
n'importe quelle machine d'un utilisateur — celle qui *sert* un service comme
celle qui le *consomme*. B, qui veut joindre les services d'A, déclare ses
propres machines exactement comme A a déclaré les siennes.

C'est ce que le scénario impose : les machines n'ont pas de biométrie, et une
machine qui interroge l'annuaire doit pourtant prouver qu'elle agit au nom d'un
compte. Elle le prouve avec un secret, comme celle qui annonce.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `m-` + 26 caractères. **Public.** |
| `nom` | **Un nom d'hôte** depuis 0.26.0 (décision 47) : une étiquette RFC 1123 — lettres ASCII, chiffres, tiret, 1 à 63 octets, ni tiret en tête ni en queue —, **rangée en minuscules**. Il doit pouvoir servir de `hostname` à la machine. Les noms déclarés avant restent tels quels (voir plus bas). |
| `alias` | **Facultatif**, depuis 0.26.0 (décision 47) : UTF-8, **sensible à la casse**, rangé en NFC, 1 à 253 octets — la longueur d'un nom de domaine complet, parce qu'il est fait pour pouvoir en servir —, aux règles de l'alias de domaine (§2.11). **Indépendant du nom et du domaine par définition** : il peut contenir tout autre chose qu'une composition « nom.domaine », et c'est voulu. **Non unique.** Posé et retiré par le propriétaire de la machine, et lui seul. |
| `propriétaire` | Un utilisateur. **La machine le sait** : l'annuaire le lui rend à l'enrôlement et sur demande (`protocole.md` §2.0, §3), parce qu'une machine qui agit au nom d'un compte doit pouvoir dire lequel — à son exploitant comme à ses journaux. Identifiant public, comme le sien. |
| `capacités` | `annonce`, `lecture`, ou les deux. Choisies à la déclaration, modifiables. |
| `clé publique` | Ed25519, **ou rien**. Une machine déclarée n'en a pas encore : elle arrive à l'enrôlement, et la partie privée est générée SUR la machine et n'en sort jamais. |
| `domaine` | Un `d-…`, **ou rien** (§2.11, 2026-09-26). Une machine est rattachée à **un seul** domaine à la fois, et seulement par son propriétaire — qui doit détenir le droit `rattacher` sur ce domaine (§2.13) ; on la déplace d'un domaine à l'autre. Les machines d'avant le domaine n'en ont pas, et n'en ont pas besoin : **le domaine n'est pas obligatoire.** |

#### Le nom : un nom d'hôte, et l'alias pour le reste (0.26.0)

**Décidé le 2026-09-27 (Thierry) : « je tiens à ce que pour une machine on
garde un nom pouvant prétendre être utilisable comme le hostname d'une
machine. Et je tiens à ce qu'un alias existe en plus pour permettre de se
servir du contenu de cet alias comme un hostname FQDN : c'est volontaire que
cet alias puisse par définition contenir tout autre chose qu'une composition
d'une chaîne et le nom de la machine. »**

- **Le nom est une étiquette RFC 1123**, rangée en minuscules : le DNS compare
  les noms sans casse (RFC 4343), et « Grenier » et « grenier » sont le même
  hôte. Ranger une forme, une seule, fait porter la règle à l'écriture, une
  fois, plutôt qu'à chaque lecteur. Un nom qui ne pourrait pas servir de
  `hostname` rend `400` à la déclaration comme au renommage.
- **L'alias est du texte choisi**, en UTF-8 : c'est là que vont les accents,
  les espaces, les majuscules, et un nom complet s'il le faut.
- **Les noms déclarés avant 0.26.0 restent tels quels** (point à valider par
  Thierry) : ils se relisent, se rendent et se répliquent sans changer — un
  nom rangé n'est jamais revérifié à la relecture, faute de quoi une base
  réelle cesserait de s'ouvrir. Seuls les nouveaux noms, et les renommages,
  passent par la règle. Les dériver automatiquement (« Salle à manger » →
  `salle-a-manger`) a été écarté : une translittération est une décision de
  langue que l'annuaire n'a pas à prendre à la place du propriétaire.

**Ce qui suit est le texte d'avant 0.26.0, gardé parce qu'il vaut désormais
pour l'ALIAS de machine** (et pour les noms d'avant, qui restent) :

~~Le nom est le premier TEXTE LIBRE du produit, et c'est une décision.~~ Il porte les accents, les idéogrammes et les émoji — tout l'UTF-8. Ailleurs, le
cadrage refuse le non-ASCII, et pour une raison qui tient : `é` s'écrit de deux
façons en Unicode, et **deux écritures d'une même valeur ouvrent la porte à ce
que deux lecteurs n'en voient pas le même nombre.**

**Cette raison ne vaut que pour ce qui se COMPARE** — un identifiant, un alias,
un nom de service, qui sont des clés. Un nom d'affichage n'est comparé à rien :
la clé est l'identifiant, à côté. Refuser les accents n'achèterait donc rien, et
coûterait à tout utilisateur dont la langue en porte.

**Trois choses restent refusées, et chacune pour une raison :**

— **les échappements JSON.** Les apprendre, c'est apprendre l'UTF-16, ses paires
  de substitution et ses moitiés orphelines — la moitié des failles historiques
  des analyseurs. Le prix se dit : un nom ne peut porter ni `"` ni `\` ;
— **les contrôles C0 et DEL**, qu'un nom porterait jusqu'au terminal qui
  l'affiche ;
— **les contrôles C1, les forceurs de sens d'écriture et la marque d'ordre des
  octets.** Ceux-là ne s'affichent pas eux-mêmes : ils changent la façon dont le
  TEXTE AUTOUR s'affiche. Un nom de machine se lit dans une liste, à côté
  d'autres noms ; l'un d'eux ne doit pas pouvoir retourner ses voisins.

**Une machine déclarée et pas encore enrôlée n'a PAS de clé**, et l'enregistrement
le dit — un drapeau, et une place laissée nulle. Trente-deux zéros n'auraient pas
fait l'affaire : ce n'est pas une valeur absurde pour Ed25519, c'est un point
d'ordre faible dont on peut forger des signatures. Une machine sans clé aurait
alors eu une clé que n'importe qui détient.

#### Les capacités, et pourquoi elles ne sont pas cumulées par défaut

| Capacité | Ce qu'elle ouvre |
|---|---|
| `annonce` | Les daemons de cette machine peuvent annoncer et rafraîchir des services. |
| `lecture` | Cette machine peut demander à l'annuaire où joindre un service — les siens, et ceux qui ont été accordés à son propriétaire (§2.5). |

**Une machine qui porte les deux a un rayon de dégât plus large qu'une machine
qui n'en porte qu'une.** Un daemon compromis sur une machine `annonce` peut
usurper le nom d'un autre daemon de la même machine. Le même daemon compromis
sur une machine `annonce + lecture` peut **en plus** énumérer tout ce que son
propriétaire a le droit de voir — y compris les services que des amis lui ont
accordés, sur des machines qui ne lui appartiennent pas.

L'application demande donc explicitement à la déclaration, et ne coche rien
d'avance. Les machines d'A qui hébergent le daemon portent `annonce` ; les
machines de B qui le consomment portent `lecture`.

#### La clé de machine — et pourquoi ce n'est PAS un secret partagé

**Il n'y a aucune authentification par secret partagé dans ce produit**, pas plus
pour une machine que pour un humain. Une machine détient une **paire de clés
Ed25519** dont la partie privée est générée sur place et **ne quitte jamais la
machine**. L'annuaire ne connaît que la partie publique.

Un secret partagé — un jeton porteur qu'on recopie — a trois défauts qu'aucune
précaution ne rattrape : il existe en deux exemplaires au moins, il transite au
moment où on le pose, et **quiconque l'intercepte devient la machine**. Une
signature, elle, prouve la détention sans jamais transmettre ce qui est détenu.

Elle est par MACHINE et non par daemon : un daemon quelconque doit pouvoir
s'annoncer sans qu'on ait déclaré d'avance qu'il existerait — c'est l'énoncé
même du produit. Le prix se dit : **tout daemon tournant sur cette machine et
capable de lire la clé peut s'annoncer sous n'importe quel nom.** La clé ne
sépare pas les daemons entre eux, elle sépare cette machine des autres.

#### L'enrôlement — comment la clé publique arrive à l'annuaire

La difficulté est réelle : la machine génère sa clé, mais rien ne dit à
l'annuaire que **cette** clé est bien celle d'une machine de **cet** utilisateur.

1. L'application affiche un **code d'enrôlement** — dix symboles de l'alphabet de
   Crockford, groupés pour l'œil (`4K9M2-P7R1T`), à usage unique, valable dix
   minutes.
2. L'administrateur le saisit sur la machine : `asl enroll <code>`.
3. La machine **génère sa paire de clés**, et présente sa clé publique avec le
   code.
4. La machine POSTE le tout sur `/v1/enrolement` (`protocole.md` §2.0) ;
5. l'annuaire lie la clé à la machine, et le code est consommé — c'est-à-dire
   **supprimé**, dans la même transaction que la liaison.

**Dix symboles font cinquante bits.** Au-dessous, le code se devine : c'est un
secret qui ouvre la liaison d'une clé à un compte, présenté à un verbe que
n'importe qui peut appeler. Au-dessus, il ne se tape plus — c'est un humain qui
le recopie d'un téléphone vers un terminal, et chaque symbole de trop est une
occasion de se tromper. **Cela ne dispense pas de limiter le débit**, et cette
limite-là n'est pas encore écrite.

**Un second code partage cette forme, et rien d'autre** : celui de la posture
`invitation` (`protocole.md` §2.2), que l'exploitant émet pour qu'un compte
s'ouvre. Mêmes dix symboles, même usage unique, même empreinte seule sur le
disque — parce qu'un humain le recopie dans les mêmes conditions. Mais il ne
lie pas une clé à une machine déjà déclarée : **il ouvre l'entrée du
service**, il vit vingt-quatre heures et non dix minutes puisqu'il s'envoie à
quelqu'un qui n'est pas devant, et c'est pour cela que lui seul s'accompagne
d'une limite de débit écrite. Ne pas confondre les deux : l'un est montré par
l'application au titulaire d'un compte, l'autre est donné par l'exploitant à
qui n'en a pas encore.

**L'annuaire n'en garde que l'empreinte** (SHA-256, domaine séparé) : une base
qui fuirait ne livrerait aucune machine en cours d'enrôlement. C'est aussi ce qui
permet de chercher sans nommer la machine — voir `protocole.md` §2.0.

**Le code d'enrôlement EST un secret partagé, et il faut le dire plutôt que de
prétendre le contraire.** Ce qui le rend acceptable est qu'il n'authentifie rien
sur la durée : il ne sert qu'une fois, il expire en quelques minutes, et il
n'ouvre qu'une seule opération — lier une clé. Le justificatif durable est la
clé, et elle, personne ne l'a jamais transmise.

**Le sens de la saisie n'est pas arbitraire** : c'est un code court qu'on tape
sur un terminal, et non une clé publique de 44 caractères qu'on recopierait dans
un téléphone. La direction est choisie pour l'humain qui fait le geste.

#### Révoquer

Se fait depuis l'application, et prend effet à la seconde : les connexions de la
machine sont fermées, ses baux tombent. Il faut alors ré-enrôler sur place.

C'est l'opération à faire quand une machine est compromise, et elle est
délibérément visible plutôt qu'enfouie dans un menu.

**La machine RESTE**, et c'est ce qui rend le ré-enrôlement possible sans tout
redéclarer : elle garde son identifiant, son nom, ses capacités et ses services.
Ce qu'elle perd est sa clé — le moyen de prouver qu'elle est elle. Un nouveau
code la remet en marche, et les autorisations qui la nommaient valent toujours.

**Fermer les connexions n'est pas une précaution de plus, c'est la moitié du
travail.** Effacer la clé refuse la prochaine authentification ; une connexion
déjà authentifiée, elle, porte son pair avec elle et continuerait de servir. Et
comme la connexion EST le bail (§4), la fermer fait tomber les annonces par le
chemin ordinaire d'un départ — il n'y a pas de second mécanisme à tenir d'accord
avec le premier.

### 2.4 Service

Ce qu'un daemon annonce. **Identifié par le couple (machine, nom).**

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `s-` + 26 caractères. **Dérivé de la machine et du nom** (A1 ; décisions 65, 66, 67 et 72 — **fait en 0.37.0**) : les seize premiers octets de `SHA-256("asl/service/1" ‖ m (16 octets) ‖ nom (UTF-8))`, la forme exacte au paragraphe qui suit. Il n'est plus tiré : tout annuaire — racine, membre d'une paire, l'hébergeur d'hier et celui de demain — calcule le même pour le même `(machine, nom)`, sans rien échanger ; il est stable à travers bascules, redémarrages et changements d'hébergeur. Un `s-…` prévisible est accepté (décision 67). Jusqu'à la 0.36.0 il était **tiré au hasard par l'annuaire qui recevait la première annonce** (défaut constaté le 2026-09-28, `annuaires.md` §2 ter) ; chaque `s-…` existant a changé une fois, au premier démarrage de la 0.37.0 (`replication.md` §11, point 5). |
| `machine` | La machine qui le porte. |
| `nom` | Choisi par le daemon, 1 à 64 caractères. C'est ce que son client connaît. |
| `points d'écoute` | Un ou plusieurs `(protocole, port)`. |
| `candidats` | Voir §3. |
| `bail` | Voir §4. |

**La forme exacte du `s-…` dérivé** (0.37.0, `crates/asl-registre/src/derivation.rs`,
figée par ses vecteurs d'essai) :

```
s-… = SHA-256( "asl/service/1" ‖ m ‖ nom )[0..16]
```

- `"asl/service/1"` : les treize octets ASCII, sans terminateur ;
- `m` : les **seize octets** du `m-…` — jamais son texte, qui n'est pas unique
  (Crockford rattrape `I`, `L`, `O`) ;
- `nom` : les octets UTF-8 du nom, sans longueur ni terminateur ;
- les seize premiers octets du condensat forment le corps du `s-…`.

La chaîne et `m` ont une longueur fixe, le nom est tout ce qui suit : deux
couples différents donnent deux messages différents, sans qu'un séparateur ou
une longueur préfixée soit nécessaire. Vecteur : `m-32Q2JXER1HTVRZQ956T7V3GE0S`
et `essai-federation` donnent **`s-7ANMGMZPJ3EGA41WA129KAJTWE`**.

**Un service porte PLUSIEURS points d'écoute**, et non un seul : un daemon qui
sert en TCP et en UDP est un seul service, pas deux. Le contraire obligerait son
client à connaître deux noms pour un seul programme.

**Le nom est choisi par le daemon, et une deuxième annonce du même nom REMPLACE
la première.** C'est le comportement qu'un redémarrage exige : un daemon qui
redémarre avec un nouveau port doit pouvoir le dire, et non se heurter à son
propre fantôme. Un conflit y ferait échouer précisément le cas nominal.

Le prix, là encore : deux daemons du même nom sur la même machine se chassent
l'un l'autre indéfiniment. C'est visible — la date d'annonce oscille — et
l'application le signale.

**Un service n'a pas toujours une machine : l'`asl-directory`** (décidé le
2026-09-28, Thierry ; décisions 73 à 78, `annuaires.md` §2 quinquies). Chaque
annuaire local accepté a un service nommé `asl-directory`, **sous le `n-…` de
son titulaire** et non sous un `m-…` ; personne ne l'annonce, les racines le
synthétisent de l'inscription et des voies de ses membres, et son `s-…` se
dérive du `n-…` sous une chaîne de séparation propre (`"asl/annuaire/1"`),
par la même forme : `SHA-256("asl/annuaire/1" ‖ n (16 octets) ‖
"asl-directory")[0..16]` — la fonction commune, `asl_registre::deriver`,
existe depuis la 0.37.0 ; l'`asl-directory` est servi depuis la 0.38.0
(`asl_registre::asl_directory_derive` : `n-7MSV5RPCXBZH25PQM4ZPE5X87P` →
`s-294B4BA9XHXFZ5DQ8Q7T35M7PY`).
**Le nom est réservé** : un daemon qui l'annonce est refusé. Il se résout par
`GET /v1/ou/{n-…}/asl-directory`, en rendant l'adresse et l'identité de chaque
membre vivant, et seulement à un cercle étroit — son propriétaire, les
administrateurs des racines, qui tient un droit sur un domaine qu'il héberge
(décision 79 ; `annuaires.md` §2 quinquies, « Le cercle ») —, les adresses à
`localiser` seul (décision 80) : **pas au public**, et pas par un droit qu'on
écrirait. **C'est le moyen des machines**, servi sur la voie machine seulement
(décision 86) : les applications ne le lisent pas. Elles montrent l'état de
l'annuaire sur sa tuile, lu dans `GET /v1/annuaires` — le champ `voie` de
chaque membre —, jamais dans les services d'une machine (décisions 84 et 86).

**Un service que chaque machine enrôlée peut porter : l'`asl-echo`**
(décidé le 2026-09-29, Thierry ; décisions 89 à 94, `protocole.md` §3
quater). `asl echo` l'annonce sur **un port tiré au hasard**,
en UDP, et tient son bail comme `asl announce` ; il ne répond qu'aux sondes
autorisées — celle de l'annuaire qui tient son bail, et celle d'`asl ping`
munie d'un jeton —, **par une signature de la clé de la machine**. C'est
une annonce ordinaire, sous le `m-…` de la machine, et non un service
synthétisé ; son nom est réservé à sa forme — un seul point, UDP (décision 90).

### 2.5 Autorisation

> **Renversé le 2026-09-26 (Thierry) — l'autorisation devient un DROIT accordé à
> un GROUPE** (§2.12, §2.13, `replication.md` décision 41). Ce qui suit décrit le
> modèle d'avant : une arête d'un compte vers un compte. Il reste vrai dans ce
> qu'il protège — rien ne s'interroge anonymement, on sait à qui l'on a donné, et
> retirer suffit —, et il reste la **forme des verbes de compatibilité** que les
> applications déployées appellent (`protocole.md` §2.2, « Les autorisations
> d'hier »). Ce qui change est le bénéficiaire : ce n'est plus un compte, c'est
> un groupe — et partager avec un ami, c'est accorder un droit à **son groupe
> personnel**, qui ne contient que lui. Les autorisations existantes sont
> converties à la mise à jour, sans changer d'identifiant (§2.13).

**Rien ne s'interroge anonymement.** Pour obtenir l'adresse d'un service, il
faut prouver qu'on agit au nom d'un compte enregistré — et que ce compte a été
autorisé.

Une autorisation est **une arête entre deux comptes**, pas un jeton qui circule.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `g-` + 26 caractères. |
| `accordée par` | Le compte qui possède les services. |
| `accordée à` | Le compte bénéficiaire. |
| `portée` | Tous les services du compte, une machine, ou un service. |
| `étiquette` | Libre — pour savoir ce qu'on révoque six mois plus tard. |
| `accordée le` / `révoquée le` | Dates. |

#### Le scénario qu'elle sert, et qui la définit

A possède cinq machines, chacune faisant tourner une instance du même daemon,
sur cinq ports et cinq adresses différents. A ne veut pas que ces instances
soient publiques.

1. B se crée un compte et obtient son identifiant public `u-…`.
2. **B transmet cet identifiant à A hors de l'annuaire** — SMS, courriel, à voix
   haute. L'annuaire ne connaît ni le numéro de B ni son adresse, et n'a donc
   aucun annuaire d'utilisateurs à énumérer.
3. A saisit `u-…` dans son application, choisit la portée, et accorde.
4. **B est notifié** (§2.6), et voit l'autorisation dans son application.
5. Chacune des machines de B portant la capacité `lecture` peut désormais
   demander à l'annuaire où joindre les cinq instances.

#### Pourquoi une arête entre comptes plutôt qu'un jeton porteur

Un jeton porteur qu'on donne à un ami est un jeton qu'on ne récupère pas : il se
recopie, se transmet, apparaît dans un fichier de configuration sauvegardé. On
ne sait jamais combien de copies existent, ni qui les détient.

Une arête, elle, **nomme le bénéficiaire**. On voit à qui on a donné, on retire
à qui on veut, et retirer suffit — il n'y a rien à récupérer. C'est aussi la
seule forme qui permette de répondre à « qui peut voir mes services ? », qui est
la question qu'un utilisateur se pose vraiment.

#### Une autorisation donne aussi à voir les MACHINES — c'est décidé

**« Tout mon compte » veut dire tout : les services, et les machines qui les
portent.** Un bénéficiaire d'une autorisation de portée « tout le compte »
peut demander la **liste des machines** de celui qui l'a accordée — leurs
identifiants `m-…` et leurs noms — et, de là, ce que chacune sert. Une portée
plus étroite ne montre que ce qu'elle nomme : la machine, ou celle qui porte le
service.

C'est une décision, et elle tranche contre une prudence antérieure qui refusait
toute énumération du parc, même autorisée. La raison de l'abandonner : un
identifiant de machine est **public par construction** — c'est ce qu'on donne à
un tiers pour qu'il joigne un service (`protocole.md` §3, `GET /v1/ou/{m}/{s}`)
—, et un bénéficiaire à qui A a dit « tout mon compte » n'a pas à deviner les
`m-…` d'A un par un, ni à connaître le nom de chaque service pour découvrir
qu'il existe. Ce que C10 exige tient toujours : **rien ne se lit sans
autorisation nominative**, et la liste se calcule depuis les arêtes du
demandeur, jamais depuis l'identifiant qu'il désigne. Ce qui change est ce
qu'une arête accorde — et c'est écrit ici, au moment où A accorde, pas
découvert après.

#### Ce que le bénéficiaire voit, et qu'il faut dire à celui qui accorde

Accorder n'est pas neutre. B voit alors :

- **les machines** d'A dans la portée — leurs identifiants et leurs noms ; avec
  la portée « tout le compte », **toutes ses machines**, même celles qui ne
  servent rien,
- **les noms des services**,
- **les adresses et ports** — donc des adresses IP réelles d'A,
- **l'état et la date de dernière joignabilité**.

L'application doit l'énoncer au moment où A accorde, et non dans une page
d'aide. Un utilisateur qui apprend après coup qu'il a révélé l'adresse de son
domicile n'a pas consenti, il a cliqué.

#### La saisie confirme que le destinataire existe

Quand A saisit l'identifiant de B — **ou son alias** —, l'application doit dire
si le destinataire est valide. Sans quoi une faute de frappe produit une
autorisation muette accordée à personne, et A croit avoir partagé.

Les deux chemins n'ont pas le même coût :

| Ce que A saisit | Ce que cela révèle |
|---|---|
| Un **identifiant** `u-…` | L'existence d'un compte, à qui détient déjà 128 bits qu'il ne peut pas deviner et qu'il tient de son porteur. Sans conséquence. |
| Un **alias** | L'existence d'un compte derrière un nom **devinable**. C'est le prix assumé de l'alias, et la raison pour laquelle il est facultatif (§2.1). |

**L'annuaire ne rend jamais rien à partir d'autre chose** — ni courriel, ni
numéro, ni nom : il ne les a pas.

### 2.6 Notification

B doit apprendre qu'A l'a autorisé, sans avoir à ouvrir son application au bon
moment.

**Et aucun service d'Apple ni de Google n'est appelé pour cela** (C19, décidé le
2026-09-25). L'annuaire réveille les appareils de B par ce que chaque
plate-forme permet sans eux : sur **Android**, un message vers le point de
poussée UnifiedPush que l'utilisateur a choisi (son distributeur, ntfy ou un
autre) ; sur **macOS**, une ligne dans la connexion que l'app résidente tient
déjà ; sur **iOS**, rien — un iPhone ne réveille une application que par
APNs, et l'utilisateur d'iPhone apprend l'autorisation en ouvrant l'app. Le
détail, et ce que chaque choix coûte : `protocole.md` §2.2, « Les
notifications ».

**La notification est une commodité, jamais la source de vérité.** Elle peut
être refusée par l'utilisateur, perdue en route, ou arriver en retard.
L'autorisation existe dès qu'A l'a accordée ; la liste dans l'application de B
est ce qui fait foi, et l'application montre, à l'ouverture, ce qu'elle
n'avait pas encore montré. Un produit qui ferait dépendre un droit d'accès de
l'arrivée d'un message reposerait sur un service qu'il ne contrôle pas.

**Son contenu est vide.** Le message ne dit rien — ni qui, ni quoi :
l'application affiche « Du nouveau dans Service Locator », et c'est ouverte,
après le geste biométrique qui déverrouille sa clé, qu'elle montre qui a
accordé l'accès. Ni nom de machine, ni adresse, ni identifiant : une
notification s'affiche sur un écran verrouillé, devant qui se trouve là, et
traverse un serveur de poussée qui n'a pas à le savoir.

### 2.7 Annuaire

**Un annuaire appartient à un utilisateur**, et il y en a plusieurs.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `n-` + 26 caractères. **Se déduit de la clé d'identité** — les seize premiers octets d'un SHA-256 à domaine séparé —, pour qu'épingler la clé épingle l'identifiant (`replication.md` §2.2 ; codé depuis 0.7.0). **C'est cette dérivation que la poignée de main TLS vérifie** (décision 53). |
| `propriétaire` | Un utilisateur. Les deux annuaires racines appartiennent à air-desktop-project. **Un annuaire local n'héberge que les domaines de son propriétaire**, de un à n (2026-09-27, décision 48). |
| `clé de signature` | Ce avec quoi il signe les enregistrements dont il est l'autorité, et ce avec quoi il PROUVE qui il est — à l'autre racine, aux racines, et **depuis le 2026-09-27 dans la poignée de main TLS** : il présente un certificat **auto-signé par cette clé**, et qui le joint l'attend par son `n-…` (`annuaires.md` §2 quater, décision 53). ~~Ed25519, distincte de la clé TLS : celle-ci tourne avec le certificat~~ — la clé TLS distincte servait un certificat sous autorité, qui n'existe plus ; ce que l'autre épingle, ce que les estampilles nomment (§2.10) et ce que TLS prouve sont désormais la même clé. |
| `locateurs` | **Décidé (2026-09-27, décision 57)** : les adresses (`[IPv6]:port`, `IPv4:port`, éventuellement un nom DNS) par lesquelles on le joint. **Aucune valeur de confiance** : on joint un locateur, on attend une identité. Pour une racine, embarqués dans le logiciel ; pour un annuaire local, déclarés à l'inscription puis tenus à jour par lui-même sur sa voie. |
| `rôle` | `racine`, **`local`** (2026-09-26), ou `ordinaire`. Un annuaire **local** est l'`asl-server` qu'un utilisateur fait tourner chez lui : il fait autorité sur les domaines qu'il héberge (§2.11), et il est **inscrit** auprès des racines après approbation (ci-dessous). `ordinaire` — l'annuaire qui fait autorité sur des COMPTES, relié à d'autres par une confiance bilatérale — reste décrit par `annuaires.md` §4–§5, et devient une suite nommée (`annuaires.md` §8). |
| `pairs` | Les annuaires avec qui une relation de confiance est établie, et ce qui se réplique dans chaque sens. |
| `membres` | **Pour un annuaire local** (2026-09-27, décision 49) : un ou deux `n-…` — le titulaire, dont le `n-…` nomme l'annuaire, et au plus un second, sa paire de secours. Chacun approuvé à son tour (`annuaires.md` §2 ter). |
| `asl-directory` | **Pour un annuaire local accepté** (2026-09-28, décisions 73 à 85) : son service, sous le `n-…` du titulaire, synthétisé par les racines — vivant tant qu'une voie de membre tient, avec les locateurs de chaque membre vivant et son `n-…`. **Pas pour une racine** : `GET /v1/racines` en tient lieu — ses locateurs relus ne changent que ceux des racines déjà connues (décision 85) —, et au moins une racine écoute sur 6630 (`annuaires.md` §2 quinquies). |

Deux annuaires racines sont fournis par air-desktop-project — **deux, pour ne
pas être un point de panne unique**. D'autres utilisateurs et d'autres
entreprises sont encouragés à déployer le leur, et peuvent demander à s'y
rattacher.

**Les racines sont un REGISTRE et un ENTREMETTEUR, pas un dépositaire.** Elles
vivent sur deux adresses IPv6 connues de tout annuaire, dont les clés publiques
sont inscrites dans le code — c'est l'ancre de confiance, et une adresse seule
n'y suffirait pas : qui détourne une route parle depuis cette adresse.

~~Un annuaire neuf s'enregistre auprès d'au moins une racine. **Cela ne lui donne
accès à rien** : c'est figurer dans un annuaire d'annuaires, pour que d'autres
puissent le trouver.~~

~~**La confiance est BILATÉRALE, et le propriétaire des racines n'arbitre rien.**
Ce sont les administrateurs des deux annuaires concernés qui acceptent leur
relation ; la racine ne fait que porter la demande. Un réseau où le fondateur
déciderait qui parle à qui ne serait pas une fédération.~~

**Renversé le 2026-09-26 (Thierry) — l'inscription d'un annuaire local est
APPROUVÉE par les administrateurs des racines** (§2.12, `annuaires.md` §4,
`replication.md` décision 32). Ce qui était écrit valait pour un annuaire qui
ne demandait aux racines que d'être *recensé* : figurer dans un registre ne
coûtait rien à personne, et le filtrer aurait fait du fondateur un arbitre sans
raison. **Un annuaire local demande davantage** : que les racines portent, et
servent à d'autres, l'état vivant des services qu'il héberge (§2.11). Ce qu'une
racine sert en son nom, elle doit pouvoir le refuser — un annuaire qui
affirmerait des adresses fausses ferait des racines le relais de son mensonge.
L'approbation est donc le prix de ce service, et **un seul administrateur
suffit** pour accepter comme pour refuser. Ce qui reste bilatéral, et que
personne n'arbitre, est la confiance entre deux annuaires `ordinaires`
(`annuaires.md` §4.3) — qui n'est pas la v1.

Une fois la relation établie, **chaque administrateur choisit ce qu'il réplique
chez lui**, en suivant la chaîne de possession — un utilisateur possède ses
machines, ses machines possèdent leurs services.

Tout ceci — l'ancre de confiance, l'entremise, la réplication sélective, et ce
qui ne se synchronise surtout pas — a son propre document :
**[`annuaires.md`](annuaires.md)**.

### 2.8 Exposition

Ce qu'un annuaire rend disponible à un pair donné.

| Champ | Ce que c'est |
|---|---|
| `relation` | La relation de confiance concernée. |
| `portée` | Tout l'annuaire, quelques utilisateurs, ou quelques machines — la chaîne de possession (`annuaires.md` §5.1). |
| `retraits` | Ce que des utilisateurs en ont soustrait. |

**Trois décisions distinctes, prises par trois personnes :** l'administrateur qui
donne décide de ce qu'il EXPOSE ; celui qui reçoit décide de ce qu'il PREND
là-dedans ; **l'utilisateur décide de ce qu'il RETIRE** — son compte entier, ou
telle de ses machines.

**C'est un retrait, pas un consentement, et la différence est réelle.**
L'exposition prend effet quand l'administrateur la décide ; le retrait, quand
l'utilisateur le décide. Entre les deux, les données ont circulé — et retirer
arrête le flux sans défaire ce qui a déjà été copié.

**L'application doit donc montrer à un utilisateur ce qui est exposé de lui, par
relation**, et le lui notifier quand une exposition nouvelle le couvre. Un droit
de retrait qu'on ignore n'en est pas un.

Le raisonnement complet — pourquoi ce partage plutôt qu'un consentement préalable,
et ce qu'il coûte — est dans [`annuaires.md`](annuaires.md) §5.2.

### 2.9 L'origine — un champ que TOUT enregistrement porte

**Ce n'est pas un objet, c'est une colonne sur tous les autres**, et elle est là
pour une raison unique et suffisante : rompre une relation de confiance efface
tout ce qui en venait.

| Valeur | Ce que ça veut dire |
|---|---|
| `locale` | Cet annuaire en est l'autorité. |
| Une relation de confiance | L'enregistrement est entré par là. |

**Sans ce champ, une rupture serait approximative** : il faudrait deviner ce qui
venait de qui, et ce qu'on ne saurait pas rattacher resterait. Avec lui, la
rupture est un effacement, et l'effacement est complet.

**Il ne se déduit pas de l'autorité, même si aujourd'hui les deux coïncident.**
C11 interdit d'accepter d'un pair ce dont il n'est pas l'autorité, donc un
enregistrement d'un compte de X ne peut être entré que par la relation avec X.
Cela restera vrai tant que C11 tiendra — et un champ qui repose sur l'invariant
d'un autre est un champ qui se trompera le jour où cet invariant bougera.

**Il n'y a pas de réplication transitive**, et donc pas de cascade à gérer : Y
n'est pas l'autorité des comptes de X et ne peut rien en dire à Z. Une rupture
X↔Y ne se propage nulle part, parce que rien ne s'est propagé.

**Entre les deux racines, la provenance reste `locale`** (`replication.md` §7 ;
proposé, à confirmer). Une relation de confiance se rompt, et la rupture
efface ; entre racines il n'y a rien à rompre — une seule autorité, en deux
exemplaires — et rompre la réplication n'efface rien. Qui a écrit est dit par
l'estampille (§2.10), et c'est là que cette information sert.

### 2.10 L'estampille — une colonne de plus, sur le modèle de l'origine

**Chaque enregistrement porte l'estampille de sa dernière écriture** : le
compteur de la racine qui a écrit, et son identifiant. C'est une horloge de
Lamport, pas une date — les deux racines n'ont pas la même heure, et une règle
de conflit à l'heure murale changerait de gagnant quand un exploitant recale un
NTP (`replication.md` §4).

| Valeur | Ce que ça veut dire |
|---|---|
| `(compteur, racine)` | La `compteur`-ième écriture de cette racine ; son compteur se hisse au-dessus de tout ce qu'elle reçoit. |

Là où un `PATCH` change un champ sans toucher aux autres — le nom et les
capacités d'une machine —, **chaque champ a la sienne**, sans quoi un nom
perdrait parce qu'une capacité a gagné. La réclamation d'alias d'un compte en
porte une ; la clé d'une machine en porte deux, la sienne et celle de
l'émission du code qui l'a liée.

**Elle ne dit pas l'heure, et c'est une qualité** : répliquer n'ajoute aucune
ligne de temps à ce que l'entrepôt porte déjà (C13, C18). Les dates que ce
modèle porte — `enrôlé le`, `révoqué le`, `effacé le` — restent celles de la
racine qui a écrit, et se répliquent telles quelles. C'est ce qui fait que
deux racines calculent la même échéance pour un compte orphelin (§2.1) :
elles lisent la même date, pas chacune leur pendule.

### 2.11 Domaine

**Décidé le 2026-09-26 (Thierry).** Un domaine est **un lieu où l'on range des
machines** — la maison, le bureau, le laboratoire —, et c'est l'unité qu'un
annuaire local tient à la place des racines (`annuaires.md` §2 bis).

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `d-` + 26 caractères. **Public**, comme les autres. La lettre `d` est libre dans `asl-id::Genre` (u, a, m, s, g, n sont pris). |
| `propriétaire` | **Un** compte. **C'est le compte qui possède le domaine, pas le domaine qui contient le compte** : un compte possède **un ou plusieurs** domaines — **toujours au moins un** —, et un domaine n'appartient qu'à un compte. |
| `alias` | **Facultatif, non unique**, public (ci-dessous). |
| `administrateurs` | **Un groupe** (§2.12), créé avec le domaine, dont le propriétaire est membre d'office. Y ajouter un compte, c'est lui confier la gestion du domaine — ce que la spec du 2026-09-26 appelait « déléguer » (ci-dessous). |
| `groupes` | Les autres groupes du domaine, que ses administrateurs créent (§2.12). |
| `niveau` | `1`. **Le domaine racine est seul au niveau 0** (ci-dessous) ; il n'y a jamais de niveau 2. |
| `hébergé par` | `racines`, ou le `n-…` d'un annuaire local inscrit et approuvé (§2.7). |
| `machines` | Celles qui y sont rattachées — **une machine n'est que dans un domaine à la fois** (§2.3). |

**Deux niveaux, et pas un de plus.** Le **domaine racine** est seul au niveau
0 ; tous les domaines des utilisateurs sont au niveau 1, sous lui. Il n'y a pas
de sous-domaine entre domaines d'utilisateurs : un domaine du niveau 1 ne
contient pas de domaine. Ce qu'une hiérarchie plus profonde achèterait —
confier une branche — un groupe d'administrateurs par domaine le donne déjà,
sans que l'autorité ait à se chercher le long d'un arbre.

#### Le domaine racine — niveau 0

**Décidé le 2026-09-26 (Thierry).** Il y a **un** domaine racine, tenu par les
deux racines, dont Thierry est propriétaire. **Son groupe d'administrateurs EST
le groupe des administrateurs des racines** : ceux qui acceptent ou refusent
l'inscription d'un annuaire local (§2.7, `replication.md` décisions 32 et 33).

| Règle | Pourquoi |
|---|---|
| **Son identifiant se DÉDUIT d'une étiquette fixe** — les seize premiers octets d'un SHA-256 à domaine séparé de la chaîne `asl domaine racine` —, et non d'un tirage (décidé le 2026-09-26, codé en 0.24.0 : `asl_registre::domaine_racine`) | Les deux racines et tout annuaire local le calculent pareil, sans rien échanger ni rien amorcer : il n'y a pas de fenêtre où l'une le connaîtrait et l'autre non, et on peut l'écrire dans le code comme les clés des racines. |
| ~~Il naît au premier démarrage d'une racine qui tient `--operator-key`~~ **Il n'est écrit nulle part : il se CALCULE** (0.24.0, `replication.md` décision 43), sans rangée ; **son propriétaire est le premier compte nommé administrateur sous la clé d'exploitant** — celui dont l'ajout, encore vivant, est le plus ancien (décidé le 2026-09-26) | La caution des invitations et du groupe des administrateurs est déjà cette clé ; il n'en faut pas une autre. **Pourquoi ne pas l'écrire au démarrage** : son propriétaire est le premier nommé, et deux racines qui nommeraient chacune un premier administrateur dans la même fenêtre écriraient deux domaines racines de propriétaires différents — « insérer si absent » dépendrait de l'ordre d'arrivée. Calculé sur l'ensemble des nominations, il est le même des deux côtés. |
| ~~Il ne contient aucune machine en v1 — ni alias, ni autre groupe que son groupe d'administrateurs~~ **Corrigé le 2026-09-29 : cette règle n'avait pas été décidée par Thierry**, et deux de ses trois termes étaient déjà faux dans le code — l'alias s'y écrit depuis la 0.31.1. **Il se comporte comme un domaine que ses administrateurs possèdent** (`replication.md` décision 88, 0.39.0) : ils y tiennent `administrer`, `rattacher`, `voir` et `localiser`, et **y rangent LEURS machines**. Il ne porte toujours aucun autre groupe que son groupe d'administrateurs | Les racines elles-mêmes ne s'y rangent pas — elles ne sont pas des machines enrôlées, elles ne s'annoncent pas. Mais les machines qui les hébergent le sont : nitrogen (`m-0Z971MJ6TZRWXE8C5CE8VBD2AY`) et argon (`m-5N5A5Z42DJRZSB6G3HF9PH99AD`), machines du compte de Thierry, trouvent leur place naturelle dans le domaine racine, et non dans un domaine de la maison. |
| **Ce qu'il n'accepte PAS, lui seul** (décision 88) | Il ne se confie à aucun annuaire local (`PUT /v1/domaines/{d}/hebergeur` : `404`, il n'est à personne au sens d'une rangée, et `heberge_par` reste `racines` même si un hébergement arrivait) ; il ne se supprime pas ; **aucun droit ne s'écrit sur lui** (décision 44) — ses quatre droits viennent de son groupe d'administrateurs, et de lui seul. Pour que les applications le sachent sans le deviner, `GET /v1/domaines` et `GET /v1/domaines/{d}` portent sur son objet, **et sur lui seul**, `"sorte":"racine"` (`protocole.md` §2.2). |
| **Il n'est PAS un ancêtre pour les droits** | Un droit posé sur le domaine racine ne descend pas dans les domaines du niveau 1 (§2.13) — il ne contient aucun domaine, seulement les machines que ses administrateurs y rangent. Sans cette règle, administrer les racines donnerait à voir les machines de tout le monde — exactement ce que la décision 33 promettait d'éviter : **un administrateur des racines ne gagne rien sur les domaines du niveau 1, ni sur une machine d'un autre qui n'est pas rangée dans le domaine racine.** |
| **Son groupe d'administrateurs ne change que sous la clé d'exploitant** | Contrairement aux autres domaines, où un administrateur en nomme un autre : ici, nommer un administrateur, c'est donner le pouvoir de juger des annuaires qui parleront au nom des racines. La règle de la décision 33 tient. |

#### Un domaine à la création du compte — et jamais moins d'un

**Un compte a TOUJOURS au moins un domaine** (Thierry, 2026-09-26 : « de 1 à
n », et non « de 0 à n »). Le premier lui est attribué **à la création du
compte, dans la même transaction**, hébergé par les racines. C'est ce qui fait
que l'utilisateur n'a jamais à comprendre ce qu'est un domaine pour commencer :
il a déjà un endroit où ranger ses machines, et il ne coûte qu'un identifiant.

**Supprimer son DERNIER domaine est refusé** — `409`, comme un alias pris : la
demande est légitime, c'est l'état du compte qui s'y oppose (`protocole.md`
§2.1 quinquies). **Seul l'effacement du compte les emporte tous**, et avec
eux (décidé le 2026-09-26, Thierry) :

| Ce que le domaine tenait | Ce qu'il en advient à l'effacement du compte |
|---|---|
| Les machines du compte effacé | Elles partent avec lui, comme aujourd'hui (§2.1). |
| Les machines **d'autres comptes** rattachées à ses domaines | **Détachées** : elles restent à leurs propriétaires, sans domaine. Effacer un compte ne doit rien retirer à un autre. |
| Les groupes de ses domaines, et les droits qu'ils portaient ou que ses domaines accordaient | Retirés. |
| Son appartenance aux groupes d'autres domaines, et son groupe personnel | Retirés ; ses machines, qu'il avait pu rattacher chez d'autres, partent avec lui. |
| L'alias de ses domaines | Retiré. |
| Un annuaire local qui hébergeait ses domaines | Ne les héberge plus ; son inscription, si c'était le sien, est retirée (`annuaires.md` §4.1). |

**À la création, et non à la demande**, et pour une raison de réplication en
plus de celle de Thierry : un domaine « par défaut » que chaque racine
fabriquerait de son côté, à la première lecture, en ferait deux — deux
identifiants tirés au hasard pour le même compte, que rien ne départagerait.
**Son identifiant se DÉDUIT du compte, pour tous les comptes** (PR du socle,
0.23.0, `replication.md` décision 42) — ceux d'avant comme ceux d'après — et il
naît **sous l'estampille du compte** : chaque racine le fait naître en
appliquant l'opération `compte`, au même enregistrement octet pour octet, et
aucune opération de plus ne voyage.

**Les comptes d'avant le 2026-09-26** reçoivent le leur **à la reprise de
l'entrepôt, à la mise à jour** (décidé le 2026-09-26, Thierry), avec un identifiant **déduit du
`u-…`** — les seize premiers octets d'un SHA-256 à domaine séparé du compte,
comme le `n-…` se déduit de sa clé (§2.7). **Déduit, et non tiré**, parce que
les deux racines font la reprise chacune de son côté : un identifiant tiré en
donnerait deux, un identifiant déduit donne le même, et l'invariant « au moins
un » tient dès la mise à jour, sans fenêtre. Ce que la déduction coûte : qui
connaît un `u-…` peut calculer le `d-…` de ce premier domaine. Il n'y apprend
rien qu'il ne sache — un domaine ne rend ni machine ni service à qui n'y a pas
droit, et le `u-…` est déjà public. L'autre voie, « à la première connexion
d'une application », laissait des comptes sans domaine tant que personne ne
s'y connectait, et deux applications sur deux racines pouvaient en créer deux.

**Supprimer un domaine, et ce que la suppression ne fait PAS** (décision 42).
Un domaine supprimé est marqué, et la marque ne s'efface jamais ; il cesse
d'exister pour qui le demande — `404` —, ne se trouve plus par son alias, et
n'abrite plus rien : ses machines sont vues sans domaine. **Rien ne s'écrit
sur elles ni sur l'alias** : c'est le lecteur qui écarte ce qui vise un domaine
mort. Le jour où la règle des suppressions concurrentes garde un domaine en
vie (`replication.md` §3.2), il retrouve donc ses machines et son alias sans
qu'aucune écriture ait eu à les lui rendre.

**Autant de domaines qu'on veut.** Un utilisateur en crée d'autres, depuis
l'application, et en particulier pour son annuaire local : « chez moi, sur mon
serveur asl, je peux créer autant de domaines que je veux ».

#### Gérer un domaine à plusieurs — le groupe d'administrateurs

~~**La délégation** : le propriétaire délègue la gestion d'un domaine à des
comptes existants ; un délégué voit le domaine, rattache et détache SES
machines, pose l'alias ; un seul niveau ; seul le propriétaire délègue.~~

**Renversé le 2026-09-26 (Thierry) : la délégation disparaît, le groupe la
remplace** (`replication.md` décision 39). « Déléguer », c'est **ajouter un
compte au groupe d'administrateurs du domaine** (§2.12). Une notion de moins,
et la même que partout ailleurs : ce que la délégation faisait à part — un rôle
propre, une liste propre, ses opérations propres — les groupes et les droits
(§2.13) le font pour tout.

| Qui | Ce qu'il peut |
|---|---|
| **Le propriétaire** | Tout. **Membre d'office** du groupe d'administrateurs, et **il ne s'en retire pas** : un domaine sans personne pour le gérer ne se rattraperait pas. Lui seul supprime le domaine et le confie à un annuaire local. |
| **Un membre du groupe d'administrateurs** | Le droit `administrer` sur le domaine (§2.13) : poser l'alias, créer et supprimer les groupes du domaine, en changer les membres — y compris celui des administrateurs —, accorder et retirer des droits sur le domaine, ses machines et ses services. |
| **Un membre d'un groupe qui a `rattacher`** | Rattacher et détacher **SES PROPRES** machines — sans administrer (0.25.0 ; en 0.24.0, avant les droits, ranger c'était administrer). |

**On ne rattache que des machines dont on est propriétaire**, quel que soit le
droit qu'on tient : `rattacher` ouvre le domaine, jamais les machines d'un
autre. Retirer un compte du groupe qui lui donnait `rattacher` **détache ses
machines du domaine** (décidé le 2026-09-26, Thierry : sans quoi il garderait
des machines dans un lieu où il n'a plus sa place). **Ce détachement se LIT, il
ne s'écrit pas** (0.24.0, décision 43) : un rattachement ne vaut que tant que le
propriétaire de la machine peut encore ranger dans le domaine ; rajouté au
groupe, il retrouve sa machine sans qu'aucune écriture la lui ait rendue.

**Rattacher sa machine à un domaine, c'est confier à ses administrateurs le
droit de la partager.** Un droit posé sur un domaine vaut pour ses machines
(§2.13) : l'administrateur d'un domaine peut accorder `localiser` sur tout ce
qui y est rangé, y compris ce qu'un autre y a rattaché. C'est la conséquence du
choix de Thierry — « un droit posé sur un domaine vaut pour ses machines » — et
l'application doit le dire au moment de rattacher : **« les administrateurs de
ce domaine pourront la partager »**. Celui qui ne le veut pas garde sa machine
hors du domaine, ou dans un des siens.

C'est aussi une réponse au premier point de §6 — les sous-comptes
d'entreprise : un groupe d'administrateurs par lieu plutôt que des comptes
subordonnés.

#### L'alias de domaine — lisible, pas unique

Un domaine peut porter un **alias** : une chaîne lisible, pour qu'on le
retrouve sans recopier 26 caractères. **Il n'est pas unique, et c'est ce qui le
distingue de l'alias de compte** (§2.1) : deux domaines peuvent s'appeler
« Maison ». Il n'y a donc rien à réclamer, rien à départager entre racines, et
pas de file d'attente.

| Règle | Pourquoi |
|---|---|
| **UTF-8 valide, 1 à 64 octets**, sans contrôle C0, DEL, C1, forceur de sens d'écriture ni marque d'ordre des octets | Les règles du nom de machine (§2.3), pour les mêmes raisons. |
| **Rangé en forme normalisée NFC** | **Il se COMPARE**, contrairement au nom de machine : `é` s'écrit de deux façons, et deux écritures d'une même chaîne ne se trouveraient pas l'une l'autre. C'est exactement la raison que §2.3 donnait pour refuser le non-ASCII là où l'on compare — ici on l'accepte, et on normalise. |
| **Recherche : correspondance EXACTE, après NFC, SENSIBLE À LA CASSE** (0.26.0, décision 45) | « maison » ne trouve pas « Maison » : ce sont deux alias. ~~Pliage simple de casse d'Unicode~~ — la règle de 0.23.0 à 0.25.0, **renversée par Thierry le 2026-09-27** : un alias est une chaîne UTF-8 sensible à la casse, pour le domaine comme pour la machine et le compte. Le NFC reste : ce n'est pas une question de casse, c'est une question d'écriture. |
| **La réponse est une LISTE** | Tous les domaines qui portent cet alias, chacun avec son `d-…` et l'annuaire `n-…` qui fait autorité sur lui. Aucun n'est « le bon » ; c'est à celui qui cherche de reconnaître le sien. |
| **Réservée aux comptes authentifiés**, sans préfixe ni énumération | On ne trouve que ce dont on connaît déjà l'alias exact. Pas de recherche par début de chaîne, pas de liste des alias. |

**C'est une donnée publique, choisie**, comme l'alias de compte et le nom de
machine : une exception de C13, qui le dit. L'application doit le dire au moment
de le poser : **« visible de tous les comptes »**. Ce que l'alias rend est un
`d-…` et un `n-…` — **jamais le propriétaire, jamais une machine, jamais un
service** : savoir qu'un domaine « Maison » existe n'ouvre aucune porte.

**Ce que la normalisation coûte, nommé.** Le NFC demande des tables Unicode,
en Rust pur (C4) et sans entrée-sortie (C1) ; leur version doit être la même
sur les deux racines et sur les annuaires locaux, sans quoi deux annuaires
normaliseraient différemment un caractère récent. **La version d'Unicode est
donc épinglée, comme la toolchain** (décidé le 2026-09-26, Thierry) : **Unicode
17.0.0** — le NFC d'`unicode-normalization`, épinglée à `=0.1.25`. Chaque
changement de version est une rupture qui se déploie sur les deux racines et
les annuaires locaux ensemble. (La table de pliage de casse, engendrée par
`scripts/plis-unicode.sh` de 0.23.0 à 0.25.0, est retirée avec la décision 45.)

### 2.12 Groupe

**Décidé le 2026-09-26 (Thierry), amendé le même jour : les groupes sont une
notion GÉNÉRALE dès la v1** (`replication.md` décision 38). La première
rédaction n'en connaissait qu'un, celui des administrateurs des racines ; il
devient le groupe d'administrateurs du domaine racine, un groupe parmi d'autres.

Un groupe est **un ensemble de comptes**, et c'est **à lui, jamais à un compte
seul, que les droits s'accordent** (§2.13).

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `e-` + 26 caractères (*ensemble* : `g` est pris par l'autorisation, devenue droit). **Public.** |
| `domaine` | Le domaine auquel il **appartient** — ses administrateurs le créent et le gèrent —, **ou rien** pour un groupe personnel (ci-dessous). |
| `étiquette` | Libre, 1 à 64 octets, aux règles du nom de machine : « Famille », « Bureau ». Pour l'humain ; visible des administrateurs du domaine et des membres, **jamais publique**, jamais cherchable. |
| `membres` | Des comptes existants — **n'importe lesquels**, du même annuaire ou non. Un compte est membre d'un ou de plusieurs groupes. |

**Trois sortes de groupes, et une seule mécanique :**

| Groupe | Naît | Membres | Particularité |
|---|---|---|---|
| **Le groupe d'administrateurs d'un domaine** | Avec le domaine, dans sa transaction ; **identifiant déduit du `d-…`** (décidé, codé en 0.24.0 : `asl_registre::groupe_d_administrateurs`), pour que les deux racines arrivent au même sans rien échanger | Le propriétaire, **d'office et non retirable** ; ceux que les administrateurs y ajoutent | Porte le droit `administrer` sur le domaine ; ne se supprime qu'avec lui. |
| **Un groupe du domaine** | Créé par un administrateur | Ceux que les administrateurs y mettent | Ne porte que les droits qu'on lui accorde. |
| **Le groupe personnel d'un compte** | Avec le compte ; **identifiant déduit du `u-…`** (décidé, codé en 0.24.0 : `asl_registre::groupe_personnel`) | **Le compte seul**, et jamais personne d'autre | **N'appartient à aucun domaine** (décidé le 2026-09-26) : il ne dépend pas du premier domaine, qui peut être supprimé tant qu'il en reste un autre. Il ne se modifie pas et ne se supprime qu'avec le compte. C'est lui qu'on nomme pour partager avec une personne. |

**Le groupe d'administrateurs du domaine racine est celui des administrateurs
des racines** (§2.11). Ce qui le distingue des autres groupes d'administrateurs,
et qui garde tout ce que la décision 33 promettait :

| Règle | |
|---|---|
| **Un seul administrateur suffit** | pour accepter comme pour refuser une inscription. Pas de quorum : deux racines n'ont pas de majorité (`annuaires.md` §6), et un groupe de deux n'en aurait pas davantage. |
| **Ses membres se nomment et se retirent sous la clé d'exploitant, et sous elle seule** | `--operator-key`, `protocole.md` §2.2 — la même caution que les invitations ; l'outil est `asl-server --add-admin <u-…>` / `--remove-admin <u-…>`, sur un annuaire EN MARCHE, la clé privée restant chez l'exploitant (0.24.0). Le premier est le compte de Thierry — **aucun compte n'est écrit dans le code** : c'est l'exploitant qui le nomme. Un administrateur des racines n'en nomme pas un autre, contrairement aux autres domaines. Retirer est une révocation, et gagne toujours (`replication.md` §3.2). |
| **Ce qu'un administrateur des racines peut** | Accepter ou refuser une inscription ; **et, dans le domaine racine, ce que l'administrateur d'un domaine y peut** (décision 88, 0.39.0) : y ranger et en retirer SES machines, voir ce qui y est rangé, partager ce qui y est rangé (décision 40), poser l'alias. **Rien d'autre** : le domaine racine n'est pas un ancêtre pour les droits (§2.11, §2.13), il ne lit aucun compte, n'en efface aucun, ne voit aucun service hors du domaine racine qui ne lui a pas été accordé comme à n'importe qui. |

**CE QUE CELA RENVERSE, ET IL FAUT LE DIRE.** La posture `invitation` avait
écarté « un compte d'exploitation » pour une raison écrite : il aurait mis dans
le modèle **un `u-…` qui vaut plus que les autres** (`protocole.md` §2.2,
`replication.md` décision 26). Le groupe des administrateurs des racines en fait
exister. La raison de changer est que l'approbation d'une inscription est un
**jugement** — regarder qui demande, et décider —, pas un geste d'exploitation
qu'on scripte sur la machine qui tient la clé : il se fait depuis une
application, sous biométrie, par quelqu'un qui peut n'être pas devant le
serveur. **Ce que le renversement garde de l'ancienne raison** : la clé
d'exploitant reste la seule à pouvoir nommer un administrateur des racines, et
ce qu'il peut se limite à l'inscription — et au domaine racine lui-même, où il
range ses machines (décision 88).

**Ce que les groupes ne sont PAS en v1** (§6) : ils ne s'imbriquent pas — un
groupe n'est pas membre d'un groupe —, ils n'ont pas de nombre maximal de
membres écrit, et il n'existe aucun groupe « tout le monde » : un tel groupe
serait le mode anonyme que C10 interdit.

### 2.13 Droit

**Décidé le 2026-09-26 (Thierry)** (`replication.md` décisions 40 et 41 ; la
forme codée, décision 44, 0.25.0). Un
droit est ce qui remplace l'autorisation (§2.5) : **un groupe reçoit des droits
sur un élément**.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `g-` + 26 caractères — **la lettre de l'autorisation, gardée** : une autorisation convertie garde son identifiant, et une application qui tient un `g-…` le retrouve. |
| `groupe` | Le groupe bénéficiaire (§2.12). **Jamais un compte seul** : pour une personne, c'est son groupe personnel. |
| `élément` | Un domaine `d-…`, une machine `m-…`, ou un service `s-…` ; et, pour les seules autorisations converties, **un compte `u-…`** — « tout ce que ce compte possède » (décidé, ci-dessous). |
| `droits` | Un ou plusieurs de : **`administrer`**, **`rattacher`**, **`voir`**, **`localiser`** (ci-dessous). |
| `étiquette` | Libre — pour savoir ce qu'on retire six mois plus tard, comme l'autorisation. |
| `accordé par` / `accordé le` / `retiré le` | Le compte qui l'a accordé, et les dates. Un droit retiré reste, marqué — même raison qu'un appareil révoqué. |

**Les quatre droits :**

| Droit | Ce qu'il permet | Sur quoi il a un sens |
|---|---|---|
| `administrer` | Gérer le domaine : son alias, ses groupes et leurs membres, les droits accordés sur lui, ses machines et ses services. **Emporte `rattacher` et `voir`** (décision 44) : qui administre un domaine y range, et voit ce qu'il administre. | Un domaine. |
| `rattacher` | Rattacher et détacher **ses propres** machines au domaine. | Un domaine. |
| `voir` | Lister les machines et les services — identifiants, noms, état —, **pas leurs adresses**. | Domaine, machine, service. |
| `localiser` | Obtenir l'adresse et le port d'un service : `GET /v1/ou` (`protocole.md` §3). **Emporte `voir`** sur ce qu'il couvre. | Domaine, machine, service. |

**Un service échappe à ce tableau : l'`asl-directory` d'un annuaire local**
(décisions 77, 79 et 80, `annuaires.md` §2 quinquies). Aucun droit ne s'écrit
sur lui ; le résolvent son propriétaire, les administrateurs des racines, et
tout compte qui tient un droit sur un domaine que cet annuaire héberge — la
règle du tableau y vaut : **`localiser` donne les adresses, `voir` seul
seulement l'existence et l'état** — et **`administrer` n'emporte pas
`localiser`** (décision 87) : l'administrateur d'un domaine hébergé qui veut
les adresses s'accorde `localiser` sur ce domaine, un droit écrit, daté, qui
se retire comme les autres. `rattacher` seul n'y donne rien — une machine
rattachée apprend pourtant où est l'annuaire, par le `421`, qui ne change
pas : c'est la machine qu'il guide, pas son compte.

**Qui accorde.** Sur un domaine, ses machines et ses services : un membre d'un
groupe qui a `administrer` sur ce domaine. Sur **sa propre machine**, et ses
services, quel que soit le domaine où elle est : **son propriétaire**, toujours
— c'est le partage d'hier, « A accorde à B », et il ne dépend de personne.
**Aucun droit ne se crée pour soi par un autre chemin** : on n'accorde que sur
ce qu'on possède ou qu'on administre.

**Un droit sur une machine ou un service ne vaut que tant que celui qui l'a
accordé en a encore le pouvoir** (décision 44) : il en est le propriétaire, ou
il administre le domaine où elle est rangée. Sortir sa machine d'un domaine
retire donc, **à la lecture**, ce que les administrateurs du domaine en avaient
partagé ; l'y remettre le rend. Rien ne s'écrit pour cela — la règle du
rattachement (décision 43, point 5) appliquée au partage. Un droit sur un
domaine, lui, vaut tant que le domaine vit.

**Retirer un droit** : celui qui l'a accordé, ou qui a aujourd'hui le pouvoir
d'accorder sur l'élément. Un membre du groupe bénéficiaire le voit, et ne le
retire pas (`403`) : il quitte le groupe, ou demande.

**La règle de résolution : l'UNION, sans droit négatif** (décidé, décision 44). Ce qu'un compte peut sur un élément est **la réunion** de
tous les droits accordés, sur cet élément et sur ce qui le contient — le
service, sa machine, le domaine de sa machine —, à **tous** les groupes dont il
est membre. Le propriétaire d'une machine a tous les droits sur elle et ses
services, sans qu'on les écrive.

Pourquoi l'union, et pas « le plus précis l'emporte » :

- **Elle ne dépend d'aucun ordre.** Une réunion est la même quel que soit
  l'ordre dans lequel les droits arrivent — et deux racines qui les reçoivent
  dans deux ordres différents (`replication.md` §3.1) doivent répondre pareil.
  « Le plus précis l'emporte » n'a de sens qu'avec des droits qui en RETIRENT
  d'autres, et c'est là que l'ordre commence à compter.
- **Elle s'explique en une phrase** à celui qui se demande pourquoi quelqu'un
  voit sa machine : « parce qu'un de ses groupes a reçu ce droit, ici ou plus
  haut ». Un droit négatif demande de dérouler une précédence.
- **Retirer reste le geste unique** : on retire un droit, ou un membre d'un
  groupe. Il n'y a rien à « contrer ».

Le coût, nommé : on ne peut pas dire « tout le domaine sauf cette machine ». On
sort la machine du domaine, ou on accorde machine par machine. Les droits
négatifs sont nommés au §6.

**Le domaine racine ne transmet rien** (§2.11) : la chaîne « ce qui contient »
s'arrête au domaine de la machine. Une machine rangée DANS le domaine racine
l'a pour domaine, comme toute autre (décision 88) ; mais il ne contient aucun
domaine, et rien de ce qu'on peut sur lui ne descend ailleurs.

**Le domaine racine, avec plusieurs administrateurs** (décidé le 2026-09-29,
Thierry ; décision 88). Ses administrateurs y tiennent les quatre droits, comme
le propriétaire d'un domaine ordinaire, et **la logique est celle d'un domaine
ordinaire à plusieurs administrateurs** pour la machine qu'un AUTRE
administrateur y a rangée :

| Ce qu'un administrateur des racines a sur la machine d'un autre, rangée dans le domaine racine | |
|---|---|
| `voir` | **Oui** : il la voit — le détail du domaine la liste, avec son nom ; `GET /v1/utilisateurs/{u}/machines` la rend. Comme tout administrateur voit ce qui est rangé dans son domaine (`administrer` emporte `voir`). |
| Accorder sur elle | **Oui** : ranger sa machine dans un domaine, c'est confier à ses administrateurs le droit de la partager (décision 40), et le domaine racine ne fait pas exception — l'application le dit au moment de ranger. |
| `localiser` | **Non, pas de lui-même** — la forme codée en 0.39.0, **à confirmer par Thierry** : `localiser` sur un domaine, tenu par sa propriété ou son administration, ne se transforme pas en adresse d'une machine d'un AUTRE compte — c'est vrai de tout domaine, où seuls les droits ÉCRITS (§2.13, décision 44) ouvrent `GET /v1/ou`. Il l'obtient en s'accordant `localiser` sur la machine ou le service — un geste écrit, daté, qui se voit et se retire (décision 87) ; pas sur le domaine racine, sur lequel aucun droit ne s'écrit. |

Ses propres machines, il les localise toujours : c'est la propriété, pas le
domaine. Et ce qu'il a sur la machine d'un autre ne vaut que tant qu'elle est
rangée dans le domaine racine **et** que son propriétaire en est encore
administrateur : retiré du groupe sous la clé d'exploitant, ses machines s'en
détachent à la lecture (décision 43, point 5), et ce qu'on en avait partagé
avec elles (décision 44, point 3).

#### Les autorisations d'hier — converties, et ce qu'elles deviennent

**Chaque autorisation existante devient un droit, à la reprise de l'entrepôt**
(décidé : Thierry ; le détail, décision 44), sur les deux racines, chacune de son
côté et au même résultat — rien ne s'échange :

| L'autorisation | Le droit |
|---|---|
| `g-…` | **Le même `g-…`.** |
| `accordée par` A, `accordée à` B | Accordé par A, au **groupe personnel de B** (identifiant déduit de `u-…` de B, donc le même sur les deux racines). |
| Portée « un service » / « une machine » | Élément : ce service / cette machine. |
| Portée « tout mon compte » | Élément : **le compte d'A** (décidé). Hier, cette portée couvrait toutes les machines d'A, y compris celles déclarées après ; un droit par domaine ne couvrirait pas les machines d'A **sans domaine** — celles d'avant les domaines —, et un droit par machine ne couvrirait pas les suivantes. Le quatrième élément est la seule conversion qui ne change pas en silence ce qu'A avait accordé. Il ne s'accorde plus que par le verbe de compatibilité ; les applications nouvelles accordent sur un domaine. |
| Les droits | **`voir` et `localiser`** : exactement ce qu'une autorisation donnait (§2.5, « Ce que le bénéficiaire voit »). |
| `étiquette`, `révoquée le` | L'étiquette ; `retiré le`. |

**Ce que deviennent les gestes d'hier** :

- **Accorder à une personne** : un droit `voir` + `localiser` à son groupe
  personnel. Les applications d'aujourd'hui continuent d'appeler
  `POST /v1/autorisations`, qui fait exactement cela (`protocole.md` §2.2, « Les
  autorisations d'hier »).
- **Retirer** : retirer le droit — ou, pour un groupe, retirer le membre.
  **Effet immédiat** dans les deux cas : la résolution se recalcule à chaque
  requête depuis le demandeur (C10), et rien n'est mis en cache.
- **L'étiquette** reste sur le droit.
- **Le réveil** (§2.6) : **un droit accordé réveille les membres du groupe
  bénéficiaire** ; **ajouter un compte à un groupe qui porte des droits réveille
  ce compte**. Le reste — retirer un droit, retirer un membre, créer un groupe
  vide — ne réveille personne, comme une révocation aujourd'hui (décision 27).
  La ligne du flux des nouvelles garde son genre, `{"quoi":"autorisation"}` :
  les applications déployées relisent sur elle, et c'est ce qu'on veut
  (`protocole.md` §2.2).
- **La conversion est une fonction des seuls octets de l'autorisation** : le
  même enregistrement des deux côtés, octet pour octet. Elle se fait une fois,
  à la première ouverture en 0.25.0, et **ne vide pas le journal** : une
  opération `autorisation` encore au journal de l'autre racine se convertit à
  l'application par la même fonction (`replication.md` décision 44).
- **La vue de compatibilité rend les octets d'hier** : `GET /v1/autorisations`
  rend, pour un droit converti ou accordé par le verbe d'hier, exactement ce
  qu'il rendait pour l'autorisation — sans champ `groupe`, ni rien de neuf. Un
  droit qui n'a pas de forme d'hier — sur un domaine, ou sans `localiser` —
  n'y paraît pas ; de ceux que j'ai accordés, seuls ceux donnés à un groupe
  personnel y paraissent, son titulaire pour bénéficiaire.
- **L'exposition** (§2.8) n'est pas touchée : elle concerne ce qu'un annuaire
  réplique vers un pair, pas qui peut lire.

---

## 3. Les candidats, et pourquoi ce mot

À chaque annonce, l'annuaire retient **deux sortes d'adresses**, et ne les
confond jamais :

| Candidat | D'où il vient | Ce qu'il vaut |
|---|---|---|
| `annoncé` | Le daemon le dit : ses adresses locales et ses ports d'écoute. | Vrai sur le réseau du daemon. Souvent faux ailleurs. |
| `réflexif` | L'annuaire l'OBSERVE : l'adresse source de la connexion d'annonce. | Vrai vu de l'annuaire. Réutilisable par un tiers **seulement si le NAT est indépendant du point distant**. |

**Les candidats sont rendus IPv6 d'abord**, IPv4 ensuite (§1). Un candidat IPv6
public est le seul qui tienne l'exigence sans rien supposer du réseau qui le
sépare de son client.

**Le candidat réflexif n'a pas la même valeur en TCP et en UDP, et c'est une
propriété du réseau, pas un choix.**

- En **UDP**, si le daemon envoie son annonce **depuis la socket sur laquelle il
  écoute**, le NAT crée un mapping pour cette socket-là, et le port réflexif
  observé est celui par lequel on peut lui parler. C'est ce que `asl-client`
  devra faire — et c'est la seule façon d'obtenir un candidat réflexif utile.
- En **TCP**, le port source d'une connexion sortante n'est PAS le port
  d'écoute. Le candidat réflexif observé sur une annonce HTTPS ordinaire ne
  désigne donc **rien** de joignable. Seule son adresse IP est utile — et elle
  ne l'est que si la machine n'est pas derrière un NAT, ou si un port a été
  redirigé.

Cette asymétrie est la raison pour laquelle §4 de `protocole.md` réserve une
voie d'annonce UDP, et pourquoi la v1 ne la promet pas.

---

## 4. Le bail, et ce que « en ligne » veut dire

### 4.1 La connexion tenue, et le keepalive

**Le daemon TIENT une connexion QUIC ouverte vers l'annuaire**, et la maintient
par un keepalive. Il n'y a pas de réannonce périodique : la connexion *est* le
bail.

Ce que cela apporte, et qui ne s'obtient pas autrement :

- **Un arrêt propre est instantané.** Le daemon ferme la connexion, l'annuaire
  le sait dans la milliseconde. Aucune fenêtre d'état faux.
- **Une coupure est détectée en un délai d'inactivité**, pas en un bail.
- **Le mapping NAT reste ouvert** par le keepalive lui-même, sans mécanisme
  séparé.
- **L'annuaire peut PARLER au daemon.** C'est ce qui rendrait possible, plus
  tard, un rendez-vous pour un perçage de NAT (§6.3) : les deux extrémités sont
  déjà en ligne au même instant. Sans connexion tenue, cette route serait
  fermée d'avance.

#### Le delta — MESURÉ une fois, et il reste des liens à éprouver

| | Valeur accordée | D'où elle vient |
|---|---|---|
| Keepalive | **10 s** | **Mesuré** (`bancs/nat/README.md`, 2026-09-10) : sur un lien résidentiel, 28 s de silence tiennent et 30 s non. À 15 s, **un seul keepalive perdu faisait 30 s de silence** — exactement la borne. À 10 s, il en faut deux d'affilée. |
| Délai d'inactivité QUIC | **30 s** | **Trois keepalives manqués avant de conclure** — et c'est aussi ce que le chemin tolère. Une perte de paquet ou une seconde de latence ne doit pas faire basculer un daemon sain hors ligne : une fausse alerte coûte plus cher qu'une détection tardive. |

**Les deux valeurs viennent maintenant de la mesure.** 45 s promettait une
tolérance que le réseau ne rend pas : le chemin meurt à 30 s, donc une connexion
ne pouvait de toute façon jamais rester inactive 45 s puis reprendre. Le rapport
de trois pour un est celui de la politique, et il est retrouvé.

**Les DEUX inactivités doivent s'accorder.** Celle du transport (`--idle`)
ferme la CONNEXION ; celle du bail fait tomber l'ANNONCE. §1.2 de
`protocole.md` promet que les deux sont la même chose : les laisser diverger
ouvrirait une fenêtre où un daemon est désannoncé sans être déconnecté, donc sans
rien apprendre. Elles valent 30 s toutes les deux.

**Un échantillon de un ne fait pas une campagne.** Ce qui est mesuré, c'est une
box, un soir. Ce qu'il reste : un autre opérateur, un partage de connexion mobile
— les NAT des opérateurs y sont les plus courts —, un réseau d'entreprise. Le
banc est écrit pour qu'on les ajoute, et son tableau pour qu'on les compare.

**Sur IPv6, on croyait que la question ne se posait pas de la même façon**, au
motif qu'il n'y a pas de mapping à maintenir, seulement un état de pare-feu
« généralement plus généreux ». **La mesure dit le contraire, et c'est son
résultat le plus instructif** : sur le lien éprouvé, la borne est la MÊME en IPv4
et en IPv6 — 28 s tenus, 30 s perdus, des deux côtés. Ce n'est donc pas la
traduction d'adresses qui borne, c'est le pare-feu à état de la box, et passer en
IPv6 ne dispense de rien.

L'optimisation qu'on notait ici — un keepalive plus lent en IPv6 — **n'a donc pas
lieu d'être**, du moins pas sur ce lien-là.

#### Les valeurs viennent du serveur

**L'annuaire annonce le keepalive attendu et le délai d'inactivité ; le client
les applique.** Rien n'est figé dans `asl-client`.

Sans cela, changer le delta après la campagne de mesure exigerait de mettre à
jour tous les daemons installés chez des tiers — ce qui ne se produira jamais.
C'est la seule raison, et elle suffit.

**La voie entre les deux racines se tient de la même façon** — mêmes valeurs,
mêmes réglages, même reprise (`replication.md` §2.3). Deux machines dans le
même centre n'ont pas besoin de dix secondes, mais une troisième valeur serait
une troisième chose à mesurer, et rien ici ne souffre d'un keepalive trop
fréquent.

### 4.2 Les trois états, et le mot qui est banni

L'énoncé du produit dit « online / offline ». **L'API ne dira jamais cela**,
parce que l'annuaire ne le sait pas : il sait qu'un daemon lui parle, ce qui
n'est pas la même chose que « un client peut l'atteindre ». Pour une machine
derrière un NAT, les deux diffèrent, et c'est le cas courant.

| État | Ce qu'il affirme, exactement |
|---|---|
| `annoncé` | La connexion du daemon est tenue. **Le daemon dit qu'il écoute** — et l'annuaire sait qu'il est vivant, ce qui n'est pas la même chose que joignable. |
| `joignable` | L'annuaire a lui-même ouvert une connexion vers un candidat et l'a vue aboutir, à telle date, sur tel candidat. |
| `parti` | La connexion est fermée. Proprement — le daemon l'a dit — ou par expiration du délai d'inactivité. **L'annuaire distingue les deux et le rend**, parce qu'un arrêt volontaire et une coupure réseau n'appellent pas la même réaction chez celui qui regarde. |

**`joignable` porte toujours sa date et son candidat.** Un « joignable » sans
date est un mensonge à retardement : il décrit le passé au présent.

**Sur le point de l'`asl-echo`, `joignable` dit plus** (décisions 89 et
92) : l'annuaire n'a pas seulement vu un chemin aboutir, il a reçu **une
réponse signée par la clé de cette machine**, vérifiée — « joignable, preuve
de clé vérifiée, constaté à … » (§4.3, « L'écho »). Le mot sur le fil ne
change pas ; l'état par machine (`echo`) le dit en clair.

### 4.3 La sonde de joignabilité

**LE KEEPALIVE NE REMPLACE PAS LA SONDE**, et c'est le point à ne pas confondre.

Le keepalive prouve que le daemon est vivant et que *sa* connexion vers
l'annuaire fonctionne. Il ne prouve **rien** sur la capacité d'un tiers à
atteindre le port de service : une connexion sortante réussit là où une
connexion entrante échoue, et c'est précisément le cas derrière un NAT. Deux
choses différentes, deux mesures différentes.

**L'annuaire sonde donc lui-même, à l'annonce et à chaque changement de
candidat** — pas à chaque keepalive. La connexion tenue rend cela naturel : il
n'y a plus de « renouvellement de bail » périodique auquel accrocher une sonde,
et il n'en faut pas.

Une connexion TCP ouverte puis refermée aussitôt, **vers le seul candidat
RÉFLEXIF**. Elle ne transmet rien et ne parle aucun protocole applicatif : elle
répond à une seule question, « le trois-temps aboutit-il ? ».

#### On ne sonde JAMAIS une adresse annoncée, et c'est une correction

Une version antérieure de ce document disait « vers chaque candidat TCP ». C'était
faux, et dangereux.

**C'était inutile.** Les adresses annoncées sont les adresses LOCALES du daemon.
Se connecter à `192.168.1.20` depuis l'annuaire ne joint pas sa machine : cela
joint ce qui se trouve à cette adresse **sur le réseau de l'annuaire**, qui est
une machine sans aucun rapport. La mesure n'aurait rien mesuré.

**Et c'était une faille.** Ces adresses sont choisies par le client. Les sonder
ferait de l'annuaire un intermédiaire qui ouvre des connexions vers des cibles
qu'un inconnu désigne :

- **un balayage de notre propre réseau** — `10.0.0.5:22`, `169.254.169.254:80`
  et le reste. Le trois-temps aboutit ou non, et cette seule différence est un
  oracle : le client apprend ce qui écoute chez nous, avec notre adresse ;
- **un relais vers des tiers**, qui verraient notre IP dans leurs journaux et
  nous l'imputeraient — huit adresses par annonce, autant d'annonces qu'on veut.

**Le candidat réflexif n'a aucun de ces défauts**, et c'est ce qui le distingue :
c'est l'adresse d'où ce pair vient de nous parler, et la poignée de main QUIC a
déjà prouvé qu'il tient ce chemin. Lui répondre n'ouvre aucune cible nouvelle —
nous ne parlons qu'à qui nous a parlé.

Les adresses annoncées gardent leurs deux emplois, qui ne demandent aucune
connexion de notre part : **le verdict de NAT** les compare à ce qu'on constate,
et **un client sur le même réseau** peut les essayer lui-même, ce qui est
exactement l'endroit d'où elles ont un sens.

Il reste une réserve, et il faut la dire : derrière un NAT, le candidat réflexif
est l'adresse publique d'une box que plusieurs abonnés peuvent partager. Sonder
le port qu'un daemon y déclare peut donc atteindre le voisin. C'est une gêne, non
une faille : n'importe quel pair peut faire la même chose directement, et sans
nous.

**Pourquoi ce coût est justifié.** Sans sonde, l'annuaire ne peut rendre que
`annoncé`, et un administrateur derrière un NAT découvre que son service est
injoignable au moment où quelqu'un essaie de s'en servir. Avec elle, l'annuaire
le lui dit **dans la réponse à sa propre annonce**, à la seconde où il démarre.
C'est, pour ce produit, la fonction la plus utile qui soit — et elle tombe du
protocole sans rien ajouter.

**Ce qu'elle ne fait pas, et qui doit être dit :**

- **L'UDP ne se sonde pas.** Il n'y a pas de poignée de main, et aucun écho
  générique : une sonde UDP ne distingue pas « écoute et ignore » de « rien
  n'écoute ». Un point d'écoute UDP reste donc à `annoncé`, jamais `joignable`,
  et l'application le montre différemment plutôt que de laisser croire à un
  échec.
  **Sauf l'écho** (décisions 89 et 92) : l'`asl-echo` est un point UDP qui
  répond, et qui signe — le seul qui devienne `joignable` (ci-dessous).
- **Elle sonde depuis l'annuaire, pas depuis le client.** Un service joignable
  depuis notre machine peut ne pas l'être depuis ailleurs — pare-feu de sortie,
  filtrage par pays, NAT restreint qui n'a ouvert que pour nous. `joignable`
  dit donc « depuis l'annuaire », et l'API le nomme ainsi.
- Elle a un **coût sur le réseau du propriétaire** : une connexion par service à
  l'annonce, et à chaque fois qu'un candidat change. Vers un port qu'il a
  lui-même déclaré, et donc autorisée — mais elle se voit dans ses journaux, et
  la documentation d'installation doit le dire avant qu'il la découvre.

**Ce coût a beaucoup baissé** en passant du bail périodique à la connexion
tenue : une sonde par démarrage de daemon, au lieu d'une toutes les
quatre-vingt-dix secondes à perpétuité.

#### L'écho : une sonde qui prouve la clé (décision 89)

**Décidé le 2026-09-29 (Thierry)** : un service **`asl-echo`** sur chaque
machine enrôlée, sur un port aléatoire publié par son annonce, et **deux
sondes autorisées** — celle de l'annuaire, et `asl ping` lancé par un compte
qui en a le droit. **Le but** : prouver qu'une machine est joignable **et que
c'est bien elle**, depuis l'annuaire ou depuis n'importe où.

Ce que le trois-temps ne sait pas faire, l'écho le fait : il **répond**, en
UDP, et sa réponse est **signée par la clé de la machine** sur un défi du
sondeur. Un port ouvert chez quelqu'un d'autre — une adresse réattribuée, un
NAT partagé — ne produit pas cette signature ; un point UDP qui écoute, si.

**La forme est tranchée** (décisions 90 à 93, les réponses de Thierry aux
questions E1 à E14) et se lit dans `protocole.md` §3 quater — les
datagrammes, le jeton, qui sonde et d'où, l'installation ; **l'écho parle
UPnP** à la box pour ouvrir son seul port (décision 94 ; la forme proposée,
questions E15 et suivantes). Ce qu'elle garde de cette section :

- **toujours le seul candidat réflexif** pour la sonde de l'annuaire, jamais
  une adresse annoncée ;
- **`joignable` porte sa date et son candidat**, et dit « depuis
  l'annuaire » ; `asl ping` dit « d'ici », et **ne remonte rien** : un verdict
  de sondeur n'écrit pas l'état d'une machine ;
- **l'état par machine** — `echo` : `verifie`, `injoignable`, `autre_cle`
  (une réponse signée d'une autre clé), `en_cours`, absent s'il n'y a pas
  d'écho — avec sa date, l'annuaire qui a sondé, et s'il l'a fait de
  l'intérieur ou de l'extérieur (la règle de `sonde_locale`, décision 60).

---

## 5. Ce que le serveur ne verra jamais

Aucune empreinte, aucun gabarit facial. Ces données ne quittent pas le matériel
sécurisé du téléphone, et ni iOS ni Android ne les exposent.

Ce que le serveur constate est **une signature produite par une clé qui vit dans
ce matériel, et que le système refuse de débloquer sans confirmation
biométrique**. La confirmation est une condition d'usage de la clé, vérifiée par
le matériel — jamais un booléen que le client transporte.

Un serveur qui croirait un booléen envoyé par le client ne vérifierait rien.

---

## 6. Ce qui n'est PAS décidé

Nommé ici plutôt que supposé ailleurs.

0. **Chercher une machine par son alias** (0.26.0). L'alias de machine est fait
   pour pouvoir servir de nom complet, mais aucun verbe ne le résout encore :
   qui le ferait, sous quel droit, et s'il faut un index (il n'est pas unique)
   restent à trancher. **Les sosies d'alias de compte** (§2.1) : un alias
   unique et sensible à la casse n'empêche ni « thierry » à côté de « Thierry »
   ni un T cyrillique ; si cela devient un abus, une règle de confusables
   (UTS #39) se discutera — elle coûterait une table de plus, épinglée.
   **Les noms de machine d'avant 0.26.0** qui ne sont pas des noms d'hôte :
   gardés tels quels (§2.3) — à valider par Thierry, ou à reprendre.

1. **Les sous-comptes d'entreprise.** La v1 a un compte et plusieurs appareils
   enrôlés. Depuis le 2026-09-26, un domaine se gère à plusieurs par son groupe
   d'administrateurs (§2.11, §2.12) : un administrateur qui part se retire du
   groupe sans emporter le domaine. Ce qui manque encore — des comptes
   subordonnés, des rôles plus fins que les quatre droits — dépend de la taille
   des parcs réels, qu'on ne connaît pas encore.
2. **Le transfert d'une machine.** Non couvert : on retire, on redéclare, on
   ré-enrôle la machine. Suffisant tant qu'une machine change rarement de
   mains.
3. **COMMENT une machine derrière un NAT devient joignable depuis l'Internet.**
   C'est l'exigence du §1, et c'est la question ouverte la plus lourde du
   produit. Trois routes, par coût croissant :

   | Route | Ce qu'elle vaut |
   |---|---|
   | Le daemon demande lui-même une redirection à sa box (NAT-PMP, PCP, UPnP-IGD) | La moins chère, et elle tient dans `asl-client`. Marche souvent, **échoue en silence** — et un daemon qui croit avoir obtenu une redirection sans l'avoir est pire qu'un daemon qui sait qu'il n'en a pas. La sonde de §4.3 est ce qui le détrompe. |
   | L'annuaire sert de rendez-vous pour un perçage simultané | Exige un canal tenu ouvert des deux côtés, donc un annuaire qui n'est plus seulement interrogé mais *connecté*. Échoue sur NAT symétrique. |
   | Un relais transporte le trafic | Marche **toujours**. Et **change la nature du produit** — d'un annuaire vers un réseau — avec la bande passante, le coût et la responsabilité qui vont avec. Ne doit jamais être choisi par accident. |

   **La v1 ne choisit pas.** Elle mesure, et dit à l'administrateur que son
   daemon n'est pas joignable — ce qui est déjà ce que personne d'autre ne lui
   dit.
   **Pour l'écho seul, la première route est prise** (décision 94,
   2026-09-29) : `asl echo` demande à la box, par UPnP, une redirection de
   son seul port — et la sonde par l'écho (§4.3) est ce qui dit si elle
   tient. Les daemons des autres ne sont pas concernés.
4. **La rétention.** Combien de temps garde-t-on un service expiré, et son
   historique de joignabilité ?
5. **Le bénéficiaire peut-il refuser ?** La v1 le notifie et lui montre
   l'autorisation ; elle ne lui demande rien. Recevoir un droit d'accès ne
   nuit pas — mais B doit au moins pouvoir **masquer** une autorisation qu'il
   ne veut pas voir, et cela n'est pas spécifié.
6. **La découverte publique.** Un service qu'on voudrait joignable par tous,
   sans autorisation nominative, n'existe pas en v1 : tout passe par une arête
   entre comptes. C'est le choix sûr, et il ferme un cas d'usage réel (un
   service ouvert, une démonstration). À rouvrir seulement si le besoin se
   présente vraiment — l'ouvrir « au cas où » ferait exister le mode anonyme
   que tout le reste de ce modèle évite.
7. **Ce que devient une autorisation quand une machine change de capacités.**
   Retirer `lecture` à une machine de B doit-il couper ses résolutions en cours,
   ou seulement les suivantes ?
8. ~~**Accorder l'accès à un domaine entier.**~~ **Décidé le 2026-09-26** : un
   droit sur un domaine vaut pour ses machines et ses services (§2.13).
9. ~~**Les groupes généraux.**~~ **Décidé le 2026-09-26** : dès la v1 (§2.12).
10. ~~**Supprimer un domaine qui n'est pas le dernier.**~~ **Décidé le
    2026-09-26 (Thierry)** : ses machines sont détachées, son alias, ses
    groupes et les droits qui le visent retirés, l'identifiant marqué supprimé
    comme un compte effacé. Le dernier ne se supprime pas : `409`.
11. ~~**Le premier domaine des comptes d'avant le 2026-09-26.**~~ **Décidé
    (Thierry)** : à la reprise de l'entrepôt, identifiant déduit du `u-…`
    (§2.11) ; le groupe personnel et le groupe d'administrateurs de ce domaine
    naissent de la même reprise, déduits eux aussi.
12. **Les droits négatifs** (§2.13) : « tout le domaine sauf cette machine ».
    Écartés en v1 parce qu'ils rendent la résolution dépendante d'une
    précédence ; à rouvrir si les parcs réels le demandent.
13. **Les groupes imbriqués** : un groupe membre d'un groupe. Écartés en v1 —
    la résolution deviendrait un parcours de graphe, avec ses cycles.
14. **Un nombre maximal de membres, de groupes, de droits.** Rien n'est écrit ;
    il faudra une borne, au moins pour que la résolution reste en temps borné
    (C9) et qu'un compte ne puisse pas gonfler l'entrepôt d'un autre.
15. **Retirer l'élément « compte »** (§2.13) : il n'existe que pour les
    autorisations converties. Le jour où les applications n'appelleront plus
    les verbes de compatibilité, il pourra disparaître — en convertissant
    chacun en droits par domaine, après avoir rattaché les machines sans
    domaine.
