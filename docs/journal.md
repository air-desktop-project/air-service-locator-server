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

La forme qui répond au besoin sans le coût :

| | Ce qu'on garde | Combien de temps |
|---|---|---|
| **Entrées brutes** | Chaque requête, avec son demandeur | **Court** — le temps du diagnostic et de la détection d'abus |
| **Agrégats** | Des compteurs : volumes, taux de refus, pics | **Long** — ils ne nomment personne |

**Agréger puis jeter.** Les statistiques imposées survivent ; le détail qui les
a produites n'a pas à survivre avec elles. Un compteur « 4 812 résolutions cette
semaine » ne dit rien de personne, et c'est pourtant lui qu'on regarde.

**La durée des entrées brutes n'est pas décidée.** Elle doit l'être, et elle doit
être écrite dans la documentation d'exploitation — pas seulement dans le code.

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

Sous la lecture hybride (`annuaires.md` §5.3), une résolution portant sur un
service d'A est servie par l'annuaire d'A. **Cet annuaire journalise alors
l'activité d'un utilisateur qu'il ne possède pas** — B est un compte de Y, et son
comportement s'inscrit chez X.

**Cela n'est pas un défaut à corriger, c'est une conséquence à énoncer.** Elle
doit apparaître au moment où B se voit accorder l'accès : utiliser un service
hébergé ailleurs, c'est laisser une trace ailleurs.

**Et cela change la portée de la question ouverte d'`annuaires.md` §5.3.** Le
choix entre l'hybride et la réplication complète ne décide pas seulement de la
fraîcheur des données ni de la résistance à la panne :

| | Qui accumule le graphe d'usage |
|---|---|
| **Hybride** | L'annuaire d'A — donc le propriétaire du service |
| **Réplication complète** | L'annuaire de B — donc le propriétaire du demandeur |

Ce n'est pas un détail d'implémentation. C'est le choix de qui, dans une
fédération, détient l'historique de qui consulte quoi.

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

1. **La durée de rétention des entrées brutes** (§3). C'est le manque le plus
   important : sans elle, la rétention est infinie par défaut.
2. **L'adresse source est-elle conservée ?** (§2.3)
3. **Le résultat rendu est-il conservé ?** (§2.3)
4. **L'utilisateur voit-il qui a résolu ses services ?** (§4) — proposé, pas
   confirmé.
5. **Où vivent les agrégats**, et s'ils sortent de la machine. Un système de
   statistiques tiers ferait sortir ce que §6 interdit de faire sortir.
6. **Que devient le journal quand une relation de confiance est rompue ?** C17
   efface les enregistrements dont l'origine est la relation révoquée. **Les
   lignes de journal en font-elles partie ?** Les effacer perd la trace d'abus
   éventuels — qui est précisément ce qui a pu motiver la rupture. Les garder
   conserve des données sur les utilisateurs d'un annuaire avec lequel on n'a
   plus de lien. **Les deux se défendent, et il faut choisir.**
