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

Les machines qui portent les daemons sont de deux sortes, et **une seule tient
cette exigence toute seule** :

| | Exigence tenue ? |
|---|---|
| Adresse IPv4 ou IPv6 publique | Oui, sans rien faire. |
| Derrière un NAT | **Non**, et *comment* l'y amener n'est pas décidé — c'est la question ouverte la plus lourde du produit (§6.3). |

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

**L'identifiant public a un seul emploi, et c'est lui qui le justifie** : il se
transmet hors de l'annuaire — SMS, courriel, à voix haute — pour qu'un autre
utilisateur vous accorde l'accès à ses services (§2.5). L'annuaire ne connaît
donc ni votre numéro, ni votre adresse : il n'y a aucun annuaire d'utilisateurs
à énumérer, et rien ne se cherche par nom.

### 2.2 Appareil

Le téléphone. Un compte en porte au moins un, et **c'est l'appareil qui signe**,
jamais l'utilisateur : il n'y a pas de mot de passe dans ce produit.

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `a-` + 26 caractères. |
| `clé publique` | La partie publique d'une clé qui vit dans le matériel sécurisé du téléphone et ne peut être employée qu'après une confirmation biométrique. |
| `jeton de poussée` | APNs ou FCM, pour les notifications (§2.6). Lié à l'appareil, révoqué avec lui. |
| `enrôlé le` | Date. |
| `révoqué le` | Date, ou vide. |

**Un compte à un seul appareil est un compte qu'un téléphone perdu ferme
définitivement.** L'application le dit à l'enrôlement et pousse à en enrôler un
second ; elle ne l'impose pas.

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
| `nom` | Libre, 1 à 64 caractères. Pour l'humain, jamais pour la machine. |
| `propriétaire` | Un utilisateur. |
| `capacités` | `annonce`, `lecture`, ou les deux. Choisies à la déclaration, modifiables. |
| `secret de machine` | `sm-` + 52 caractères. **Montré UNE SEULE FOIS**, à la déclaration. |

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

#### Le secret de machine

**C'est ce que l'administrateur copie sur la machine** — dans le fichier de
configuration des daemons, ou dans celui du client.

Il est par MACHINE et non par daemon : un daemon quelconque doit pouvoir
s'annoncer sans qu'on ait déclaré d'avance qu'il existerait — c'est l'énoncé
même du produit.

Le prix est réel et se dit : **tout daemon tournant sur cette machine peut
s'annoncer sous n'importe quel nom.** Le secret ne sépare pas les daemons entre
eux, il sépare cette machine des autres.

Il se remplace depuis l'application. Le remplacement invalide immédiatement
l'ancien : les daemons cessent de rafraîchir, leurs baux expirent, et il faut
repasser sur la machine. C'est l'opération à faire quand une machine est
compromise, et elle est délibérément visible.

### 2.4 Service

Ce qu'un daemon annonce. **Identifié par le couple (machine, nom).**

| Champ | Ce que c'est |
|---|---|
| `identifiant` | `s-` + 26 caractères. Attribué à la première annonce. |
| `machine` | La machine qui le porte. |
| `nom` | Choisi par le daemon, 1 à 64 caractères. C'est ce que son client connaît. |
| `points d'écoute` | Un ou plusieurs `(protocole, port)`. |
| `candidats` | Voir §3. |
| `bail` | Voir §4. |

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

### 2.5 Autorisation

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

#### Ce que le bénéficiaire voit, et qu'il faut dire à celui qui accorde

Accorder n'est pas neutre. B voit alors :

- **les noms des machines** d'A qui portent les services concernés,
- **les noms des services**,
- **les adresses et ports** — donc des adresses IP réelles d'A,
- **l'état et la date de dernière joignabilité**.

L'application doit l'énoncer au moment où A accorde, et non dans une page
d'aide. Un utilisateur qui apprend après coup qu'il a révélé l'adresse de son
domicile n'a pas consenti, il a cliqué.

#### La saisie d'un identifiant confirme qu'il existe

Quand A saisit l'identifiant de B, l'application doit dire si l'identifiant est
valide — sans quoi une faute de frappe produit une autorisation muette accordée
à personne, et A croit avoir partagé.

**Cela révèle donc l'existence d'un compte à qui connaît son identifiant.** C'est
acceptable, et pour une raison précise : un identifiant porte 128 bits, il ne se
devine pas, et quiconque le détient le tient de son porteur. L'annuaire ne rend
jamais rien à partir d'autre chose — ni un nom, ni un courriel, ni un numéro.

### 2.6 Notification

B doit apprendre qu'A l'a autorisé, sans avoir à ouvrir son application au bon
moment.

L'annuaire pousse donc une notification vers les appareils enrôlés de B — APNs
sur iOS, FCM sur Android. Chaque appareil enrôle un jeton de poussée, qui est
lié à l'appareil et se révoque avec lui.

**La notification est une commodité, jamais la source de vérité.** Elle peut
être refusée par l'utilisateur, perdue par la plate-forme, ou arriver en retard.
L'autorisation existe dès qu'A l'a accordée ; la liste dans l'application de B
est ce qui fait foi. Un produit qui ferait dépendre un droit d'accès de
l'arrivée d'un message chez Apple ou chez Google reposerait sur un service qu'il
ne contrôle pas.

**Son contenu est délibérément pauvre** : « <identifiant> vous a accordé
l'accès à des services ». Ni nom de machine, ni adresse — une notification
s'affiche sur un écran verrouillé, devant qui se trouve là.

---

## 3. Les candidats, et pourquoi ce mot

À chaque annonce, l'annuaire retient **deux sortes d'adresses**, et ne les
confond jamais :

| Candidat | D'où il vient | Ce qu'il vaut |
|---|---|---|
| `annoncé` | Le daemon le dit : ses adresses locales et ses ports d'écoute. | Vrai sur le réseau du daemon. Souvent faux ailleurs. |
| `réflexif` | L'annuaire l'OBSERVE : l'adresse source de la connexion d'annonce. | Vrai vu de l'annuaire. Réutilisable par un tiers **seulement si le NAT est indépendant du point distant**. |

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

### 4.1 Le bail

L'annuaire n'enregistre pas un état, il accorde un **bail** : le daemon annonce,
l'annuaire lui accorde une durée, le daemon rafraîchit avant qu'elle expire.

| | Valeur | Pourquoi celle-là |
|---|---|---|
| Durée du bail | **90 s** | |
| Cadence de rafraîchissement | **30 s** | **TROIS occasions de rafraîchir avant l'expiration.** Une perte de paquet ou une seconde de latence ne doit pas faire basculer un daemon sain hors ligne — une fausse alerte coûte plus cher qu'une détection tardive. |
| Détection d'un arrêt brutal | ≤ 90 s | |

Ces valeurs sont **rendues par l'annuaire, pas figées dans le client** : la
réponse à une annonce porte la durée accordée et la cadence attendue.
`asl-client` les lit. Sans cela, changer la cadence exigerait de mettre à jour
tous les daemons installés chez des tiers — ce qui ne se produira jamais.

**La voie UDP, quand elle existera, aura une cadence PLUS COURTE — 25 s.** Elle
n'obéit pas au même besoin : elle doit maintenir ouvert un mapping NAT, et
beaucoup de NAT en expirent un en 30 secondes.

### 4.2 Les trois états, et le mot qui est banni

L'énoncé du produit dit « online / offline ». **L'API ne dira jamais cela**,
parce que l'annuaire ne le sait pas : il sait qu'un daemon lui parle, ce qui
n'est pas la même chose que « un client peut l'atteindre ». Pour une machine
derrière un NAT, les deux diffèrent, et c'est le cas courant.

| État | Ce qu'il affirme, exactement |
|---|---|
| `annoncé` | Le bail court. **Le daemon dit qu'il écoute.** L'annuaire n'a rien vérifié. |
| `joignable` | L'annuaire a lui-même ouvert une connexion vers un candidat et l'a vue aboutir, à telle date, sur tel candidat. |
| `expiré` | Le bail n'a pas été rafraîchi. Le daemon est mort, coupé, ou son réseau est tombé — l'annuaire ne sait pas lequel. |

**`joignable` porte toujours sa date et son candidat.** Un « joignable » sans
date est un mensonge à retardement : il décrit le passé au présent.

### 4.3 La sonde de joignabilité

**L'annuaire sonde lui-même, une fois par bail accordé** — pas en continu.

Une connexion TCP ouverte puis refermée aussitôt, vers chaque candidat TCP.
Elle ne transmet rien et ne parle aucun protocole applicatif : elle répond à une
seule question, « le trois-temps aboutit-il ? ».

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
- **Elle sonde depuis l'annuaire, pas depuis le client.** Un service joignable
  depuis notre machine peut ne pas l'être depuis ailleurs — pare-feu de sortie,
  filtrage par pays, NAT restreint qui n'a ouvert que pour nous. `joignable`
  dit donc « depuis l'annuaire », et l'API le nomme ainsi.
- Elle a un **coût sur le réseau du propriétaire** : une connexion par service
  et par bail. Vers un port qu'il a lui-même déclaré, et donc autorisée — mais
  elle se voit dans ses journaux, et la documentation d'installation doit le
  dire avant qu'il la découvre.

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

1. **Les sous-comptes d'entreprise.** La v1 a un compte et plusieurs appareils
   enrôlés. Un administrateur qui part emporte donc l'accès. Ce qu'il faut —
   des comptes subordonnés, une délégation par machine, des rôles — dépend de la
   taille des parcs réels, qu'on ne connaît pas encore.
2. **Le transfert d'une machine.** Non couvert : on retire, on redéclare, on
   repose le secret d'annonce. Suffisant tant qu'une machine change rarement de
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
