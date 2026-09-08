# Le journal

**Toutes les requêtes sont journalisées** : qui a interrogé, quelle requête, avec
un horodatage précis. **Les réplications entre annuaires le sont aussi.** Le
journal alimente des statistiques.

---

## 1. Ce que cela crée, et qu'il faut regarder en face

`contraintes.md` C13 dit : « ce qu'on n'héberge pas ne fuit pas, ne se
réquisitionne pas, et ne se perd pas ». C'est l'argument qui interdit de stocker
un courriel ou un nom.

**Le journal est quelque chose que nous hébergeons.**

Ce n'est pas une contradiction — C13 interdit les données d'IDENTITÉ, et un
journal en contient peu. Mais il faut voir ce qu'il contient à la place :

| | Ce que l'annuaire savait déjà | Ce que le journal ajoute |
|---|---|---|
| | Où écoutent des services qui ne publient pas leur port | **Qui les consulte, et quand** |

Un graphe d'usage horodaté en dit souvent plus long sur des gens qu'un carnet
d'adresses : il montre les habitudes, les horaires, les liens, et les changements
de comportement. **Il faut donc le traiter comme un actif à part**, avec sa
rétention, ses accès et ses limites — et non comme un effet de bord de
l'exploitation.

**Ce document ne conteste pas la décision** : la journalisation est nécessaire,
pour les statistiques, la détection d'abus, le diagnostic et la mesure de charge.
Il dit ce qu'elle coûte et ce qui la borne.

---

## 2. Ce qui est journalisé

### 2.1 Les requêtes

| Champ | Pourquoi |
|---|---|
| **Le demandeur** | La machine, donc le compte qui la possède. C'est le « qui » imposé. |
| **La requête** | Ce qui a été demandé — quel service, quelle machine. |
| **L'horodatage** | Précis, imposé. |
| **Le verdict** | Servi, refusé, introuvable. Sans lui, on ne distingue pas l'usage normal du balayage. |
| **L'origine** | Requête locale, ou venue d'un annuaire pair. |

### 2.2 Les réplications

Qui a tiré, quoi, quand, et sous quelle relation de confiance.

**Ce journal-là a une fonction DÉFENSIVE, et pas seulement statistique.** C11
interdit d'accepter d'un pair ce dont il n'est pas l'autorité ; le journal est ce
qui permet de constater qu'un pair a essayé. Sans lui, un refus est un incident
isolé qu'on ne peut ni corréler ni prouver — et une rupture de relation se
décide sur des faits, pas sur une impression.

### 2.3 Deux champs qui ne sont PAS décidés

**L'adresse source.** L'annuaire la voit — c'est une connexion. La CONSERVER est
un geste de plus, et c'est le champ le plus identifiant du lot : il rattache une
activité à un lieu et à un fournisseur d'accès. Il sert à la détection d'abus, et
peu à autre chose.

**Le résultat rendu.** Journaliser les candidats servis ferait du journal **une
carte de l'infrastructure à un instant donné** — bien plus que la base courante,
qui ne garde que l'état présent. Une fuite du journal donnerait l'historique des
ports de tout le monde.

Ces deux champs se décident séparément du reste, et par défaut **ils ne sont pas
retenus** : c'est le choix qu'on peut relâcher plus tard, alors que l'inverse ne
se rattrape pas.

---

## 3. La rétention — la décision qui n'est pas un détail

**Un journal sans limite de rétention est une archive comportementale
permanente.** Ce n'est presque jamais une décision : c'est ce qui arrive quand
personne ne tranche.

| | Ce qu'on garde | Combien de temps |
|---|---|---|
| **Entrées brutes** | Chaque requête, avec son demandeur | **90 jours** |
| **Agrégats** | Des compteurs : volumes, taux de refus, pics | Sans limite — ils ne nomment personne |

**Agréger puis jeter.** Les statistiques imposées survivent ; le détail qui les
a produites n'a pas à survivre avec elles. Un compteur « 4 812 résolutions cette
semaine » ne dit rien de personne, et c'est pourtant lui qu'on regarde.

### Quatre-vingt-dix jours — ce que ça achète, ce que ça coûte

**Ce que ça achète.** Un trimestre couvre une saison entière : on voit un cycle,
et pas seulement une semaine. Surtout, **un abus se découvre souvent longtemps
après** — un balayage lent, un compte qui dérive, un pair qui insiste. Trente
jours laisseraient l'enquête arriver après les faits.

**Ce que ça coûte, et il faut le dire.** Quatre-vingt-dix jours d'activité
horodatée, c'est long pour un graphe d'usage. Pendant ce trimestre, la base
répond à « qui a consulté quoi, et quand », pour tout le monde.

### L'expiration s'exécute, et son échec se voit

**Une rétention qui repose sur une intention est une rétention infinie.**

Ce qui la fait tenir n'est pas la valeur écrite ici : c'est un travail
d'expiration qui tourne, et **dont l'arrêt est une alarme**. Un nettoyage qui
cesse silencieusement ne se remarque pas — la base grossit, ce qu'on ne regarde
pas —, et l'on découvre trois ans plus tard qu'on détenait trois ans.

La supervision doit donc porter sur **l'âge de l'entrée la plus ancienne**, pas
sur le fait que le travail « a tourné ». Un travail qui tourne et n'efface rien
passe tous les contrôles de la seconde sorte.

---

## 4. Qui peut lire le journal

| Qui | Ce qu'il voit |
|---|---|
| L'administrateur de l'annuaire | Tout, chez lui. |
| **Un utilisateur, pour SES services** | Qui a résolu ses services, et quand. |
| **Un utilisateur, pour SES requêtes** | Ce que son propre compte a demandé. |

**Le deuxième n'est pas une fuite, c'est une fonctionnalité.** A a autorisé B ; il
est légitime qu'A voie que B s'est servi. C'est le pendant exact de la règle qui
veut qu'on énonce à A ce qu'il révèle quand il accorde (`modele.md` §2.5).

**Le troisième est une exigence de loyauté.** On journalise l'activité des gens ;
le moins est qu'ils puissent voir ce qu'on a noté d'eux.

---

## 5. Le journal traverse la fédération, et c'est nouveau

L'état vivant ne traverse pas la fédération (`annuaires.md` §5.3) : une
résolution portant sur un service d'A est servie par l'annuaire d'A. **Cet
annuaire journalise donc l'activité d'un utilisateur qu'il ne possède pas** — B
est un compte de Y, et son comportement s'inscrit chez X.

**Cela n'est pas un défaut à corriger, c'est une conséquence à énoncer.** Elle
doit apparaître au moment où B se voit accorder l'accès : utiliser un service
hébergé ailleurs, c'est laisser une trace ailleurs.

**C'est le propriétaire du SERVICE qui détient l'historique**, jamais celui du
demandeur. Deux conséquences, et elles vont dans le bon sens :

- A voit qui consulte ses services — ce qui est cohérent, puisque son propre
  daemon verra la connexion de toute façon.
- **L'annuaire de B n'accumule rien** sur ce que B va chercher ailleurs.

C'était l'un des deux critères du choix de l'hybride, à côté de la fraîcheur.

---

## 5 bis. Le journal survit à une rupture — et c'est une exception à C17

**C17 dit que rompre une relation de confiance efface tout enregistrement dont
l'origine est cette relation. LE JOURNAL EN EST EXCLU.**

**Pourquoi.** Ce qui motive une rupture est souvent ce que le journal a
enregistré : un pair qui affirme hors de son autorité (C11), un balayage, un
volume anormal. **Effacer le journal en rompant, ce serait détruire la preuve au
moment précis où l'on s'en sert.** On ne peut ni établir ce qui s'est passé, ni
le montrer à qui que ce soit, ni décider plus tard de rétablir la relation en
connaissance de cause.

**Ce que cela coûte, et qui n'est pas éludé.** On conserve des lignes qui
concernent les utilisateurs d'un annuaire avec lequel on n'a plus aucun lien —
et qui, eux, n'ont plus aucun moyen de les consulter (§4), puisque la relation
qui les rattachait n'existe plus.

**Et c'est la rétention qui rend cette exception tenable.** Le journal survit à
la rupture, mais **il expire quand même à quatre-vingt-dix jours** (§3).
L'exception est donc bornée par construction : elle dure le temps d'une enquête,
pas le temps d'une archive. Les deux décisions se répondent, et ni l'une ni
l'autre ne tiendrait seule — une rétention infinie ferait de cette exception un
dossier permanent sur des inconnus.

**Les agrégats, eux, survivent sans limite** et ne posent pas la question : ils
ne nomment personne.

---

## 6. Ce que la journalisation ne doit PAS casser

**C9 — les réponses en temps constant.** Un chemin qui journalise davantage sur
un succès que sur un refus rend le temps de réponse dépendant du résultat, et
rouvre exactement le canal que C9 ferme. **La journalisation se fait donc hors
du chemin de réponse**, ou elle coûte la même chose dans tous les cas.

C'est le genre de régression qu'aucune relecture n'attrape et qu'un essai de
temporisation attrape.

**C13 — aucune donnée personnelle.** Le journal ne doit pas devenir la porte par
laquelle elle rentre. Une ligne qui embarquerait un alias, un nom de machine ou
un nom de service dans un système de statistiques externe hébergerait ailleurs ce
qu'on refuse d'héberger ici.

---

## 7. Ce qui n'est pas décidé

1. **L'adresse source est-elle conservée ?** (§2.3)
2. **Le résultat rendu est-il conservé ?** (§2.3)
3. **L'utilisateur voit-il qui a résolu ses services ?** (§4) — proposé, pas
   confirmé.
4. **Où vivent les agrégats**, et s'ils sortent de la machine. Un système de
   statistiques tiers ferait sortir ce que §6 interdit de faire sortir.
5. **Que voit un utilisateur de SON journal après quatre-vingt-dix jours ?**
   Rien, par construction. Il faut que l'application le dise, plutôt que de
   laisser croire à un historique complet.
