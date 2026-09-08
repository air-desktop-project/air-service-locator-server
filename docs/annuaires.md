# Les annuaires — réplication et fédération

Un annuaire appartient à un utilisateur. Il y en a plusieurs, et ils se parlent.

**Ce document est le moins avancé des quatre.** Il pose les trois relations qu'il
ne faut pas confondre, l'ancre de confiance, ce qui se réplique et ce qui ne doit
surtout pas se répliquer. Le reste est nommé comme ouvert plutôt que supposé
résolu — la synchronisation entre autorités distinctes est le sujet où une
décision prise à la légère coûte le plus cher, et le plus tard.

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

**S'enregistrer auprès d'une racine ne donne accès à RIEN.** C'est se faire
recenser, pour que d'autres annuaires puissent vous trouver et vous proposer une
relation. Une racine est un **registre et un entremetteur**, pas un dépositaire :
elle ne détient pas les données des annuaires qu'elle recense.

**La confiance n'est pas centrale, elle est bilatérale.** Ce sont les
administrateurs des deux annuaires concernés qui l'acceptent, jamais le
propriétaire des racines. Il ne joue aucun rôle d'arbitre, et ne doit pas en
jouer : un réseau où le fondateur décide qui parle à qui n'est pas une
fédération.

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

### L'ancre de confiance — deux adresses ET deux clés

Les deux racines vivent sur **deux adresses IPv6 connues de tout annuaire**,
inscrites dans le code. C'est le point de départ : un annuaire neuf n'a rien
d'autre.

**Une adresse ne suffit pas, et l'oublier serait la faille de tout l'édifice.**
Qui détourne une route parle depuis cette adresse. Ce qui est épinglé dans le
code, ce sont donc **les CLÉS PUBLIQUES des deux racines**, et l'adresse n'est
qu'un moyen de les joindre. Un annuaire qui répond sur la bonne adresse sans
pouvoir signer n'est pas une racine.

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

---

## 3. Ce qui se synchronise ENTRE LES RACINES, et ce qui ne s'y synchronise pas

**C'est la décision qui rend tout le reste tenable.** Elle porte ici sur les deux
racines, qui ont la même autorité ; la réplication entre pairs de confiance est
sélective et relève du §5.

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

## 4. S'enregistrer, puis se faire connaître

**Deux étapes distinctes, et la première ne donne accès à rien.**

### 4.1 L'enregistrement auprès d'une racine

1. Une entreprise ou un particulier **déploie son annuaire**.
2. Il **s'enregistre auprès d'au moins une racine** — les deux adresses IPv6
   sont dans le code, les deux clés publiques aussi (§2).
3. La racine le recense : identifiant, clé publique, comment le joindre.

C'est tout. **Aucune donnée n'est échangée, aucune confiance n'est accordée.**
S'enregistrer, c'est figurer dans un annuaire d'annuaires.

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

### 5.2 Ce que la sélection NE dit PAS, et qu'il faut trancher

**IL Y A DEUX CÔTÉS, ET UN SEUL EST DÉCIDÉ.**

Ce qui est décidé : l'administrateur qui reçoit choisit ce qu'il PREND.

Ce qui ne l'est pas : l'administrateur qui donne choisit-il ce qu'il EXPOSE ?
Sans ce second côté, l'administrateur d'un annuaire peut livrer à un pair la
liste complète des machines de tous ses utilisateurs, **sans qu'aucun d'eux le
sache**.

Cela heurte deux choses écrites ailleurs :

- **La possession.** `modele.md` dit qu'un utilisateur POSSÈDE ses machines. Une
  réplication décidée entièrement entre administrateurs traite ces machines comme
  la propriété de l'annuaire.
- **Ce qu'accorder révèle.** `modele.md` §2.5 exige qu'on énonce à A ce qu'il
  révèle quand il autorise B. Une réplication d'annuaire à annuaire révèle
  strictement plus — noms de machines, noms de services — et n'énonce rien.

Trois réponses possibles, et elles ne se valent pas :

| | Ce que ça donne |
|---|---|
| **L'administrateur décide seul** | Cohérent en entreprise, où les machines appartiennent à l'entreprise. Intenable sur une racine, qui héberge des particuliers. |
| **L'utilisateur consent, par annuaire pair** | Respecte la possession. Coûte un écran, et une décision de plus à chaque nouvelle relation. |
| **L'administrateur décide, l'utilisateur voit et peut retirer** | Le compromis : rien ne bloque, mais rien n'est invisible. |

**Ce n'est pas tranché.** La question n'est pas technique : elle demande de dire
si un annuaire d'entreprise possède les machines de ses utilisateurs, ou seulement
les recense.

### 5.3 L'état vivant — la question que la réplication rouvre

**§3 dit que le bail et la joignabilité NE SE RÉPLIQUENT PAS.** Cette décision
tenait pour les racines, et elle tient toujours : ces données changent en
permanence et se reconstruisent seules.

Mais elle laisse la réplication sélective à moitié utile. Y aura répliqué qu'un
service `depot-de-messages` existe sur telle machine d'A — et **pas où il écoute
en ce moment**, qui est la seule chose que le client demande.

Deux lectures, et il faut choisir :

| | Ce que ça coûte |
|---|---|
| **Hybride** — on réplique l'arbre durable, on demande l'état vivant à l'annuaire d'autorité au moment de résoudre | Une dépendance de X à la résolution ; mais l'état rendu est exact, et rien de volatile ne traverse la fédération. |
| **Tout répliquer** — les candidats et l'état suivent | Y répond seul, même si X est tombé ; mais chaque redémarrage de daemon pousse une mise à jour à travers toute la fédération, et une réponse périmée donne un port faux. |

**Ma lecture est l'hybride**, et elle découle de ce qui est déjà écrit : la
souscription dit *ce qui existe et qui y a droit*, la résolution dit *où c'est
maintenant*. Répliquer un port qui change à chaque redémarrage, c'est distribuer
une information fausse dès qu'elle arrive — l'argument exact du §3.

**Mais c'est une lecture, pas ta décision**, et elle mérite d'être confirmée
parce qu'elle décide si un annuaire pair peut répondre quand l'annuaire
d'autorité est tombé.

---

## 6. Ce qui n'est pas décidé

Rassemblé, plutôt que dispersé.

1. **Le côté « ce que j'expose »** de la réplication sélective (§5.2), et si
   l'utilisateur a son mot à dire sur les machines qu'il possède.
2. **L'état vivant traverse-t-il la fédération ?** (§5.3) — l'hybride est
   proposé, pas confirmé.
3. **La rupture d'une relation de confiance.** Elle est bilatérale, donc elle se
   rompt bilatéralement — mais que deviennent les enregistrements déjà répliqués,
   et les autorisations croisées qui s'appuyaient dessus ? **Le cas qui dimensionne
   tout est la clé d'un annuaire compromise** : pour pouvoir dire « rien de signé
   après telle date ne vaut », il faut que TOUTE assertion porte un horodatage
   signé et que la révocation porte une date d'effet. **C'est un champ du format,
   pas une procédure — on ne l'ajoute pas après déploiement.**
4. **Le conflit entre les deux racines.** Elles ont la même autorité : que se
   passe-t-il quand elles divergent ? **Deux répliques n'ont pas de majorité** —
   un quorum à deux ne départage rien, et bloque toute écriture dès qu'une tombe.
   Le découpage durable/volatile réduit fortement l'enjeu : seules les écritures
   rares et humaines demandent un ordre. Les pistes, par coût : un témoin qui
   vote sans porter de données, ou primaire/secondaire à promotion manuelle.
5. **L'index des annuaires est-il énumérable ?** Les racines recensent tous les
   annuaires. Peut-on en demander la liste, ou seulement en résoudre un dont on
   connaît l'identifiant ? C'est la même question que celle de l'alias
   (`modele.md` §2.1), à l'échelle des annuaires.
6. **Les racines sont-elles joignables en IPv4 ?** Deux adresses IPv6 dans le
   code excluent un annuaire sur un réseau IPv4 (§2).
7. **Le transport de la synchronisation.** QUIC comme le reste, probablement.
   Un flux entre pairs de confiance n'a pas les mêmes besoins qu'une requête de
   client.
8. **La migration d'un compte d'un annuaire à un autre.**
