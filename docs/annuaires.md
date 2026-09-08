# Les annuaires — réplication et fédération

Un annuaire appartient à un utilisateur. Il y en a plusieurs, et ils se parlent.

**Ce document est le moins avancé des quatre.** Il pose la distinction qui
gouverne tout, ce qui se synchronise et ce qui ne doit surtout pas se
synchroniser, et le chemin du rattachement. Le reste est nommé comme ouvert
plutôt que supposé résolu — la synchronisation entre autorités distinctes est le
sujet où une décision prise à la légère coûte le plus cher, et le plus tard.

---

## 1. DEUX problèmes, et les confondre serait la faute

Ils ont l'air du même — « faire que deux annuaires aient les mêmes données » — et
ils n'ont ni le même modèle de confiance, ni les mêmes garanties, ni le même
protocole.

| | **Réplication** | **Fédération** |
|---|---|---|
| Entre qui | Les deux annuaires racines | Une racine et un annuaire rattaché |
| Autorité | **La même.** Les deux racines sont interchangeables. | **Différentes.** Chacun fait foi pour ce qui lui appartient. |
| Ce qu'on craint | Une panne | **Un pair qui ment** |
| Confiance | Totale | **Aucune, hors de son périmètre d'autorité** |
| But | Ne pas être un point de panne unique | Que les comptes de deux mondes puissent se joindre |

**Un annuaire rattaché n'est pas une réplique.** Il a ses propres utilisateurs,
ses propres machines, ses propres services, et il en est l'autorité. Ce qu'il
échange avec une racine est une **assertion signée** au sujet de ce qui lui
appartient — pas un extrait de base de données.

Traiter la fédération avec le protocole de réplication reviendrait à donner à
chaque entreprise rattachée le droit d'écrire dans les comptes des autres.

---

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

### Comment on sait à qui demander

Un identifiant porte 128 bits d'aléa et **ne dit pas d'où il vient**. C'est un
choix, et il a une contrepartie : il faut un moyen de savoir quel annuaire fait
autorité pour un compte donné.

**Les racines tiennent cet index.** Un annuaire rattaché déclare aux racines les
identifiants dont il est l'autorité ; une résolution qui ne trouve pas chez soi
demande aux racines à qui s'adresser.

L'autre forme — **faire porter l'annuaire par l'identifiant** (`u-<annuaire>-<aléa>`)
— éviterait cet index et rendrait la résolution autonome. Elle a été écartée
pour une raison précise : un compte ne pourrait plus changer d'annuaire sans
changer d'identifiant, et un identifiant est ce qu'on a transmis à ses amis par
SMS. **Ce n'est pas une décision fermée** — elle mérite d'être rouverte le jour
où le coût de l'index se mesurera.

---

## 3. Ce qui se synchronise, et ce qui NE SE SYNCHRONISE PAS

**C'est la décision qui rend tout le reste tenable.**

| | Se synchronise ? |
|---|---|
| Comptes, clés publiques des appareils | Oui |
| Machines, leurs capacités, l'empreinte de leur secret | Oui |
| Services **déclarés** (nom, machine, propriétaire) | Oui |
| Autorisations accordées | Oui |
| **Le bail — la connexion tenue, l'état `annoncé`** | **NON** |
| **La joignabilité mesurée, les candidats d'adresse** | **NON** |

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

## 4. Le rattachement

Le chemin, tel que l'énoncé le fixe :

1. Une entreprise ou un utilisateur **déploie son annuaire**.
2. Il **demande à air-desktop-project** le rattachement aux deux racines.
3. **Le propriétaire des racines accepte** — à la main, en connaissance de
   cause.
4. Les clés sont échangées, et la synchronisation commence.

**L'approbation manuelle n'est pas une friction à supprimer.** C'est la seule
barrière entre un réseau d'annuaires et n'importe qui se déclarant l'autorité de
n'importe quoi. Elle doit rester manuelle tant que le nombre d'annuaires le
permet, et le jour où il ne le permettra plus, c'est un autre problème qu'il
faudra résoudre — pas celui-là qu'il faudra automatiser.

### Ce qu'un annuaire rattaché obtient, et ce qu'il ne peut pas faire

| Il peut | Il ne peut pas |
|---|---|
| Affirmer ce dont il est l'autorité | Affirmer quoi que ce soit sur un compte d'un autre annuaire |
| Résoudre pour ses propres utilisateurs les services qu'on leur a accordés | Voir un service que personne n'a accordé à l'un de ses utilisateurs |
| Se faire connaître des racines comme autorité de ses identifiants | Revendiquer un identifiant déjà attribué ailleurs |

### Ce que la révocation d'un rattachement doit faire

**Non décidé, et c'est un manque à combler avant tout déploiement fédéré.** Les
questions : que deviennent les autorisations croisées déjà accordées ? Les
comptes de l'annuaire retiré disparaissent-ils des racines, ou restent-ils
visibles comme injoignables ? Une révocation se propage-t-elle à l'autre racine
avant ou après avoir pris effet ?

---

## 5. La résolution entre annuaires

A a ses services sur l'annuaire X. B a son compte sur l'annuaire Y. A a autorisé
B. **C'est le cas que la fédération existe pour servir**, et c'est celui qui
reste le plus ouvert.

Deux formes, et elles ne se valent pas :

| | **Y relaie la question à X** | **Y a répliqué ce que X lui a accordé** |
|---|---|---|
| Fraîcheur | Exacte | En retard d'une synchronisation |
| X est en panne | La résolution échoue | La résolution marche, avec des données peut-être fausses |
| Ce que X apprend | **Que B résout, et quand** | Rien |
| Ce que Y détient | Rien de durable | Des adresses IP de machines d'A |

**Le troisième critère est celui qu'on oublie, et c'est peut-être le plus
important** : dans la forme « relais », X voit passer chaque résolution, donc
sait quand B se connecte aux services d'A. C'est une trace d'usage que personne
n'a demandée.

Dans la forme « réplication », c'est Y qui détient durablement des adresses de
machines d'A — un annuaire tiers, dont A n'a jamais rien approuvé d'autre que
d'autoriser B.

**Aucune des deux n'est choisie ici.** Le choix demande de savoir ce qu'on
préfère fuiter, et cela ne se tranche pas en écrivant un document — cela se
tranche en sachant qui déploiera des annuaires, et pour qui.

---

## 6. Ce qui n'est pas décidé

Rassemblé, plutôt que dispersé.

1. **La forme de la résolution inter-annuaires** (§5).
2. **La révocation d'un rattachement** (§4).
3. **Le conflit entre les deux racines.** Elles ont la même autorité : que se
   passe-t-il quand elles divergent — partition réseau, écriture concurrente sur
   le même compte ? Il faut un ordre, et il n'est pas choisi. **Deux répliques
   n'ont pas de majorité** : un quorum à deux ne départage rien, ce qui est la
   difficulté propre à ce nombre-là et qu'il faut regarder en face plutôt que
   d'espérer qu'elle ne se présente pas.
4. **Le transport de la synchronisation.** QUIC comme le reste, probablement.
   Mais un flux entre pairs de confiance n'a pas les mêmes besoins qu'une requête
   de client, et rien n'oblige à ce que ce soit le même protocole applicatif.
5. **Ce qu'un annuaire rattaché journalise et conserve** des comptes d'autres
   annuaires. Sans règle, chacun décidera pour soi, et c'est ainsi qu'une
   fédération devient un réseau de copies incontrôlées.
6. **La migration d'un compte d'un annuaire à un autre.** Écartée du choix
   d'identifiants au §2 — donc censée être possible. Elle n'est spécifiée nulle
   part.
