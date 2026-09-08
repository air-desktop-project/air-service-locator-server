# Contraintes

Les règles que ce dépôt tient, numérotées pour que `Cargo.toml` et les scripts
puissent les citer. Une contrainte sans contrôle est un vœu : chacune dit donc
**ce qui la fait respecter**, y compris quand la réponse est « rien, pas
encore ».

| | Contrainte | Contrôle |
|---|---|---|
| C1 | Étages 1 et 2 sans entrée-sortie | `check-etages.sh` — **à écrire** |
| C2 | 100 % de couverture aux étages 1 et 2 | `check-couverture.sh` — **à écrire** |
| C3 | Tout décodeur est fuzzé | `check-fuzz.sh` — **à écrire** |
| C4 | `asl-client` reste mince | `check-client.sh` — **à écrire** |
| C5 | Aucune abstraction d'exécution | Revue |
| C6 | L'annuaire n'affirme jamais ce qu'il n'a pas mesuré | Revue, et les noms de l'API |
| C7 | Aucune donnée biométrique ne traverse le réseau | Revue |
| C8 | Refus de démarrer en root | Essai |
| C9 | Réponses en temps constant sur les chemins d'autorisation | Essai — **à écrire** |
| C10 | Rien ne se lit sans autorisation nominative | Essai — **à écrire** |
| C11 | Un annuaire n'accepte d'un pair que ce dont ce pair est l'autorité | Essai — **à écrire** |
| C12 | La surface publique d'`asl-client` traverse une ABI C, et elle est stable | `check-abi.sh` — **à écrire** |
| C13 | Aucune donnée personnelle hébergée, hors l'alias public choisi | Revue, et le schéma du magasin |
| C14 | Aucune authentification par secret partagé — des clés, et rien d'autre | Revue |
| C15 | La pile QUIC et HTTP/3 est celle d'`air-mail-server`, jamais réécrite | `check-pile.sh` — **à écrire** |
| C16 | Une seule toolchain, celle d'Air, datée | `check-toolchain.sh` — **à écrire** |
| C17 | Tout enregistrement porte son origine, et rompre une relation efface ce qui en vient — **sauf le journal** | Essai — **à écrire** |
| C18 | Le journal expire à 90 jours, et n'ouvre aucun canal temporel | Essai de temporisation, et supervision de l'âge — **à écrire** |

---

## C1 — Tout protocole est un CODEC, et les étages 1 et 2 ne font aucune entrée-sortie

**Un protocole de ce produit est une fonction des octets vers des messages, et
retour.** Pas un objet qui possède une socket, pas une boucle qui attend. Cette
formulation est plus forte que « pas d'entrée-sortie » : elle dit *ce qu'est* un
protocole ici, et pas seulement ce qu'il n'a pas le droit de faire.

Ce qu'elle achète est direct : **un codec s'éprouve entièrement depuis un
essai**, tampon par tampon, y compris sur les cas qu'un réseau ne produit
qu'une fois par an — un message coupé au milieu d'un entier, un champ répété, une
longueur qui déborde. Un protocole qui possède sa socket ne s'éprouve qu'en
simulant un réseau, ce qui mesure la simulation.

**C'est aussi ce qui rend la pile QUIC d'`air-mail-server` réutilisable ici**
(C15) : elle a été écrite sous cette règle, donc elle ne traîne aucune boucle
derrière elle.

Le découpage du workspace le suppose (cf. l'en-tête de `Cargo.toml`). Deux
choses le paient ici, et ce ne sont pas des considérations d'élégance :

- **L'expiration d'un bail est une question d'horloge.** Si l'horloge est un
  appel système au fond d'une boucle, éprouver une expiration coûte d'attendre
  quatre-vingt-dix secondes réelles. En paramètre de l'étage 2, un essai la
  pilote en trois lignes — et peut éprouver le rafraîchissement à la
  quatre-vingt-neuvième seconde, ce qu'aucune suite d'essais ne ferait autrement.
- **La sonde de joignabilité DÉCIDE à l'étage 2 et AGIT à l'étage 3.** « Faut-il
  sonder ce candidat, et que conclure du résultat ? » est une décision pure.
  « Ouvrir une connexion TCP et voir » est une entrée-sortie. Les mêler rendrait
  la première inéprouvable sans réseau.

`check-etages.sh` devra refuser toute mention de `std::net`, `std::fs`,
`std::time::SystemTime` et `tokio` dans les crates des étages 1 et 2.

## C2 — 100 % de couverture aux étages 1 et 2

Une machine à états se pilote pas à pas depuis un essai ; une boucle asynchrone
ne se pilote pas, on l'attend. L'étage 3 est donc hors mesure — non par
indulgence, mais parce qu'y atteindre 100 % exigerait de simuler des pannes du
noyau, ce qui mesure la simulation.

**Le gate ne s'arme QUE lorsqu'il y a du code à mesurer.** Posé aujourd'hui sur
des crates vides, il rendrait 100 % et n'attesterait de rien.

## C3 — Tout décodeur est fuzzé

Les octets d'`asl-proto` viennent d'un inconnu, ceux d'`asl-api` aussi. Les
lints `deny` du workspace — `cast_possible_truncation`, `arithmetic_side_effects`
— voient une conversion douteuse, **jamais une borne oubliée**. Seul le fuzz
attrape la seconde.

Cas particulier qui mérite d'être nommé : un **numéro de port** hors de
`1..=65535` se REFUSE, il ne se tronque pas. Un port qui vaudrait `0` après
troncature ferait annoncer un service injoignable sans qu'aucune erreur ne soit
rendue.

## C4 — `asl-client` n'embarque que ce qu'il faut, et pas une ligne de C

Cette crate est liée par du code **qui n'est pas le nôtre** — et, avec les
liaisons Python, Ruby, C++, Kotlin et Swift, chargée dans des processus dont
nous ne savons rien.

- Elle ne dépend **jamais** d'`asl-store` ni d'`asl-annuaire`. S'annoncer ne
  doit pas coûter d'embarquer la base de données de l'annuaire.
- **Aucune ligne de C.** Ce n'est pas la même règle que pour le serveur : ici
  elle est structurelle. Une bibliothèque chargée dans un interpréteur Python ou
  Ruby qui lierait sa propre libcrypto entrerait en conflit avec celle du
  processus hôte, et ce genre de panne se diagnostique en jours. La pile QUIC
  d'`air-mail-server` est pure Rust, et c'est ce qui rend ce choix tenable.
- **Une borne chiffrée reste à fixer** sur le nombre de crates transitives, et
  `check-client.sh` devra la faire respecter. Elle sera plus haute qu'espéré —
  QUIC et TLS coûtent — mais **une borne haute et tenue vaut mieux qu'une règle
  qualitative** : sans nombre, elle se relâche d'une dépendance à la fois, et
  chaque pas paraît raisonnable.

## C5 — Aucune abstraction d'exécution

`asl-loop-tokio` porte le nom de son moteur. Le jour où ce service tournera sur
le stack Air, il aura une **deuxième boucle** — écrite contre `air-async`, dans
une autre crate — qui pilotera **la même** machine à états. Rien à adapter entre
les deux, et la logique du service n'est écrite qu'une fois.

Une couche d'abstraction devrait être maintenue pour les deux, et finirait par
ne convenir à aucun.

## C6 — L'annuaire n'affirme jamais ce qu'il n'a pas mesuré

**La contrainte propre à ce produit, et celle dont une violation coûterait le
plus cher.**

Un annuaire qui dirait « en ligne » d'un daemon dont il a seulement reçu une
annonce affirmerait la joignabilité sans l'avoir constatée. Pour une machine
derrière un NAT, c'est faux — et c'est le cas courant. Un administrateur qui
voit « en ligne » et dont personne ne peut se connecter cherchera le défaut
partout sauf là où il est.

En pratique :

- **Le mot « en ligne » n'apparaît nulle part** — ni dans l'API, ni dans les
  applications, ni dans les journaux. Les états sont `annoncé`, `joignable`,
  `expiré` (`modele.md` §4.2).
- **`joignable` porte toujours sa date et son candidat.** Sans date, il décrit
  le passé au présent.
- **Un point d'écoute UDP n'est jamais `joignable`**, parce qu'il ne se sonde
  pas. Il est `non_sondé`, et les applications le montrent différemment plutôt
  que de laisser croire à un échec.

Aucun contrôle automatique ne peut vérifier cela. C'est une règle de revue, et
c'est pourquoi elle est écrite ici plutôt que supposée.

## C7 — Aucune donnée biométrique ne traverse le réseau

Ni empreinte, ni gabarit facial. iOS et Android ne les exposent pas, et le
protocole ne doit pas faire semblant de les transporter.

Ce que le serveur vérifie est **une signature** produite par une clé qui vit
dans le matériel sécurisé du téléphone et que le système refuse de débloquer
sans confirmation biométrique. La confirmation est une **condition d'usage de la
clé**, appliquée par le matériel.

**Le corollaire est la règle utile** : aucun champ du protocole ne doit porter
un booléen d'authentification. Un serveur qui croirait un booléen envoyé par le
client ne vérifierait rien.

## C8 — Refus de démarrer en root

`asl-server` écoute sur un port, parle à un magasin, et **ouvre des connexions
sortantes vers des machines d'utilisateurs** pour les sonder. Rien de cela ne
demande de privilèges. Un port sous 1024 se cède par capacité ou par un proxy,
jamais en gardant `uid 0`.

## C9 — Les chemins d'autorisation répondent en temps constant

**Un service hors de la portée du demandeur et un service inexistant rendent la
même réponse, après le même délai.**

Sans cela, l'écart de temps de réponse apprend à un demandeur authentifié que la
machine d'un autre existe, alors qu'il n'y a aucun droit dessus — et c'est tout
ce qu'il cherchait. L'annuaire sait où écoutent des services qui, par
construction, ne publient pas leur port : **c'est une cible de reconnaissance**,
et le seul endroit de ce produit où une fuite d'information est aussi utile à un
attaquant que le contenu lui-même.

Cela vaut aussi pour la comparaison des secrets de machine : une comparaison qui
s'arrête au premier octet différent est une fuite.

## C10 — Rien ne se lit sans autorisation nominative

**Il n'existe aucune requête de résolution qui rende quoi que ce soit hors d'une
connexion authentifiée par une clé de machine.** Pas de mode anonyme, pas de
jeton porteur qu'on se passe, pas de service « public » — l'accès est une arête
entre deux comptes (`modele.md` §2.5), et elle se révoque en la retirant.

La conséquence à tenir dans le code : **toute réponse de résolution se calcule à
partir du compte propriétaire de la machine qui demande**, jamais à partir de ce
que la requête désigne. Un chemin qui rendrait un service parce que son
identifiant a été fourni — plutôt que parce que le demandeur y a droit — serait
la faille entière de ce produit, et elle passerait tous les essais qui ne la
cherchent pas.

Un essai par chemin de lecture, avec un compte tiers non autorisé, est le seul
contrôle qui vaille. **À écrire avec le premier chemin de lecture.**

## C11 — Un annuaire n'accepte d'un pair que ce dont ce pair est l'autorité

**La seule chose qui sépare une fédération d'une pagaille** (`annuaires.md` §2).

Tout objet a exactement un annuaire d'autorité : celui où le compte a été créé.
Une assertion signée par un pair est vérifiée **contre son périmètre**, pas
seulement contre sa signature — une signature valide sur une affirmation hors
périmètre reste un refus.

Un annuaire qui reçoit une telle assertion la **refuse et la journalise**. Il ne
la corrige pas et ne l'ignore pas en silence : c'est soit un défaut, soit une
attaque, et les deux méritent d'être vus.

**Le contrôle qui compte est un essai avec un pair hostile** — un annuaire de
test qui affirme être l'autorité d'un compte qui ne lui appartient pas. Sans cet
essai, la contrainte n'est qu'une intention, et elle tombera le jour où quelqu'un
optimisera le chemin de vérification.

## C12 — La surface publique d'`asl-client` traverse une ABI C, et elle est stable

Les liaisons Python, Ruby, C++, Kotlin et Swift passent toutes par là. Cela
impose deux choses qu'une bibliothèque Rust ordinaire n'a pas à respecter :

- **Aucun type Rust ne traverse la frontière.** Ni `String`, ni `Result`, ni
  générique, ni trait. Des entiers, des pointeurs opaques, des tampons et des
  codes d'erreur.
- **La rupture est un événement de version majeure**, pour les cinq liaisons à
  la fois. Une signature retirée casse du code que nous ne voyons pas, dans cinq
  écosystèmes qui ne se mettent pas à jour au même rythme.

`check-abi.sh` devra comparer l'en-tête C généré à celui du dernier commit et
**exiger une justification écrite pour toute suppression**. Un ajout est libre ;
c'est le retrait qui casse.

## C13 — Aucune donnée personnelle hébergée, hors l'alias public choisi

**Pas de courriel, pas de numéro, pas de nom, pas de mot de passe.** Un compte
est un identifiant, un jeu de clés publiques, et rien d'autre.

Ce n'est pas une posture. Cet annuaire sait déjà où écoutent des services qui ne
publient pas leur port ; y ajouter une identité civile ferait de sa base la cible
la plus intéressante du produit. **Ce qu'on n'héberge pas ne fuit pas, ne se
réquisitionne pas, et ne se perd pas.**

La seule exception est l'**alias public**, et elle est choisie par l'utilisateur,
facultative, et publique par construction (`modele.md` §2.1). Il ne rend qu'un
identifiant — jamais une machine, jamais un service, jamais un état.

**Le contrôle est le schéma du magasin.** Une colonne qui porterait un courriel
« pour la récupération de compte » ou un nom « pour l'affichage » violerait cette
contrainte, et c'est par là qu'elle tombera si elle tombe — jamais par une
décision explicite, toujours par une commodité.

## C14 — Aucune authentification par secret partagé

**Des clés, et rien d'autre.** Ni mot de passe, ni jeton porteur durable, ni
secret d'API.

| Qui | Ce qu'il détient |
|---|---|
| Un utilisateur | Rien. Il n'a pas d'identifiants à retenir. |
| Un **appareil** | Une clé dans le matériel sécurisé du téléphone, débloquée par la biométrie. |
| Une **machine** | Une paire de clés Ed25519, générée sur place, dont la partie privée ne sort jamais. |
| Un **annuaire pair** | Sa clé de signature (C11). |

Un secret partagé a trois défauts qu'aucune précaution ne rattrape : il existe en
deux exemplaires au moins, il transite au moment où on le pose, et **quiconque
l'intercepte devient son porteur**. Une signature prouve la détention sans
transmettre ce qui est détenu.

**La seule chose qui ressemble à un secret partagé est le code d'enrôlement**
d'une machine, et il est nommé comme tel plutôt que déguisé : à usage unique,
valable quelques minutes, et il n'ouvre qu'une opération — lier une clé. Le
justificatif durable est la clé.

**Ed25519**, pur Rust, aucune dépendance C. Ce que cette contrainte ne couvre pas
encore : les signatures ne sont **pas** post-quantiques. L'échange de clés de
QUIC l'est — `air-mail-server` porte un KEX hybride X25519 + ML-KEM-768 — mais
signer avec ML-DSA est une décision à prendre, pas une case à cocher, et elle
n'est pas prise.

## C15 — La pile QUIC et HTTP/3 est celle d'`air-mail-server`, jamais réécrite

`ams-quic`, `ams-quic-crypto`, `ams-quic-tls`, `ams-proto-quic`, `ams-proto-h3`,
`ams-h3`, `ams-quic-client`. Poignée de main, chiffrement des paquets, flux,
contrôle de flux, QPACK, extinction en deux temps — écrits sur tokio, **sans une
ligne de C**, et déjà éprouvés par un autre produit.

**Réimplémenter QUIC est le genre de décision qui paraît raisonnable un
après-midi et coûte deux ans.** `check-pile.sh` devra refuser toute crate tierce
de QUIC ou de HTTP/3 dans le graphe, et refuser un module local qui en
réimplémenterait une partie.

**CES CRATES ONT VOCATION À MIGRER DANS `air`.** Elles sont tirées d'
`air-mail-server` aujourd'hui parce que c'est là qu'elles vivent ; le jour où
elles seront dans `air`, c'est la source qui change, pas le code. La dépendance
doit donc être épinglée et **documentée comme provisoire**, exactement comme
celle du dépôt client vers celui-ci.

## C16 — Une seule toolchain, celle d'Air, datée

`nightly-2026-07-11`, égale à `~/Code/air/rust-toolchain.toml`.

**Ce dépôt n'a besoin de rien de ce que nightly apporte**, et c'est justement ce
qui rend la contrainte facile à violer par inadvertance — quelqu'un remarquera
qu'il pourrait revenir sur stable, et aura raison localement.

Il aurait tort globalement, pour deux raisons :

1. **La pile QUIC migrera dans `air`** (C15), où elle sera compilée par cette
   toolchain-là. Deux pins, ce sont deux LLVM, et les profils de couverture que
   l'un écrit, l'autre ne sait pas les relire. **Air a payé cette panne le
   2026-08-15** avec trois toolchains dans un même dépôt.
2. **Il y aura une version `linux-air`** de tous ces composants, sur la
   bibliothèque standard de `linux-air`, une cible JSON custom et `-Z build-std`
   — ce qui ne compile QUE sur nightly. Découvrir ce jour-là que le code ne passe
   pas la toolchain d'Air serait le découvrir trop tard.

`check-toolchain.sh` devra comparer ce fichier à celui d'Air et échouer sur tout
écart. Il n'existe pas ; tant qu'il n'existe pas, la contrainte tient par la
lecture de ce document, ce qui est peu.

## C17 — Tout enregistrement porte son origine

**Une colonne sur tous les enregistrements, et une seule raison** : rompre une
relation de confiance efface tout ce qui en venait (`annuaires.md` §4.4). Sans
elle, la rupture serait approximative — il faudrait deviner ce qui venait de qui,
et ce qu'on ne saurait pas rattacher resterait.

Deux règles que le code doit tenir, et qu'un essai peut vérifier :

- **Aucun enregistrement n'entre sans origine.** Un chemin d'écriture qui la
  laisserait vide créerait un enregistrement que nulle rupture n'atteint. C'est
  la seule façon dont cette contrainte tombera, et elle tombera par un `INSERT`
  ajouté à la hâte, jamais par une décision.
- **Rompre efface, et l'essai qui compte le vérifie à l'envers** : après une
  rupture, aucun enregistrement ne doit subsister avec cette origine. Un essai
  qui se contenterait de compter ce qui a été supprimé ne verrait pas ce qui a
  été oublié.

### Le RETRAIT est une rupture partielle, et obéit aux mêmes règles

Un utilisateur peut retirer ses enregistrements d'une exposition
(`modele.md` §2.8). Le pair doit alors les effacer, exactement comme il efface
sur une rupture — le flux de synchronisation porte donc un **retrait** au même
titre qu'un ajout.

**Et la même limite s'applique** : on cesse d'affirmer, on demande l'effacement,
et un pair qui n'obéirait pas ne se distinguerait de rien. C'est pourquoi ce qui
compte n'est pas la mécanique du retrait mais **la retenue à l'exposition** :
n'exposer que ce qu'on a délibérément choisi d'exposer.

### L'exception, et il n'y en a qu'une : le JOURNAL

**Les lignes de journal survivent à une rupture** ([`journal.md`](journal.md)
§5 bis). Ce qui motive une rupture est souvent ce que le journal a enregistré —
un pair qui affirme hors de son autorité, un balayage, un volume anormal.
**Effacer le journal en rompant détruirait la preuve au moment précis où l'on
s'en sert.**

Cette exception doit être écrite dans l'essai de C17, et pas seulement ici. Un
essai qui vérifierait « plus rien de cette origine » sans l'exclure échouerait —
ou pire, ferait écrire le code qui efface les lignes de journal pour le
satisfaire.

**Elle est bornée par C18** : le journal survit à la rupture, mais il expire
quand même à quatre-vingt-dix jours. L'exception dure le temps d'une enquête,
pas le temps d'une archive.

**L'origine ne se déduit pas de l'autorité**, même si C11 fait aujourd'hui
coïncider les deux. Un champ qui repose sur l'invariant d'un autre se trompera le
jour où cet invariant bougera.

### L'anti-rejeu, qui est une exigence distincte et plus faible

Effacer par origine rend inutile la machinerie qu'on croyait devoir écrire —
assertions horodatées, révocations à date d'effet, tri du passé légitime et du
passé forgé. **Il n'y a rien à trier : on rompt, et tout part.**

Il reste un besoin, plus modeste : **empêcher le rejeu à l'intérieur d'une
relation vivante**. Sans marqueur monotone, une assertion signée et capturée peut
être rejouée plus tard et ressusciter un enregistrement retiré. Un numéro de
séquence **par relation**, et un récepteur qui refuse ce qui recule, suffisent.

C'est une exigence du flux de synchronisation, pas du modèle de confiance.

## C18 — Le journal est agrégé puis jeté, et n'ouvre aucun canal temporel

Toutes les requêtes sont journalisées, et les réplications aussi
([`journal.md`](journal.md)). C'est imposé, et c'est utile — statistiques,
détection d'abus, diagnostic, et la PREUVE qu'un pair a tenté d'affirmer hors de
son autorité (C11).

**Mais un journal de qui interroge quoi et quand est un actif à part, et cette
contrainte est ce qui l'empêche de devenir une archive comportementale.**

- **Les entrées brutes expirent à QUATRE-VINGT-DIX JOURS ; les agrégats
  survivent sans limite.** Un compteur « 4 812 résolutions cette semaine » ne
  nomme personne, et c'est pourtant lui qu'on regarde. Un trimestre couvre une
  saison et laisse le temps de découvrir un abus lent ; c'est aussi long pour un
  graphe d'usage horodaté, et c'est le prix assumé.
- **L'expiration s'exécute, et son ARRÊT est une alarme.** Une rétention qui
  repose sur une intention est une rétention infinie. La supervision doit porter
  sur **l'âge de l'entrée la plus ancienne**, jamais sur le fait que le travail
  « a tourné » : un travail qui tourne et n'efface rien passe tous les contrôles
  de la seconde sorte, et l'on découvre trois ans plus tard qu'on détenait trois
  ans.
- **La journalisation reste HORS du chemin de réponse.** Un chemin qui écrirait
  davantage sur un succès que sur un refus rendrait le temps de réponse
  dépendant du résultat, et rouvrirait exactement le canal que **C9** ferme.
  Aucune relecture n'attrape cette régression ; un essai de temporisation
  l'attrape.
- **Le journal n'est pas la porte par laquelle C13 tombe.** Une ligne qui
  emporterait un alias, un nom de machine ou un nom de service vers un système
  de statistiques externe hébergerait ailleurs ce qu'on refuse d'héberger ici.

**Ce qui n'est PAS retenu par défaut** : l'adresse source du demandeur, et les
candidats servis. Le premier est le champ le plus identifiant du lot ; le second
ferait du journal une carte historique de l'infrastructure de tout le monde,
alors que la base courante n'en garde que l'état présent. **C'est le réglage
qu'on peut relâcher plus tard ; l'inverse ne se rattrape pas.**

**« Aucune ligne de C » DANS LE SERVEUR.** Elle est posée pour `asl-client`
(C4), où elle est structurelle. Côté serveur elle ne l'est pas — et ce n'est pas
un oubli : elle dépend de la persistance, un SQLite lie du C, un magasin écrit
ici n'en lie pas. Le choix du magasin n'est pas fait (`modele.md` §6), et poser
la contrainte avant lui reviendrait à trancher par la bande une décision qui n'a
pas été prise.

Le jour où le magasin sera choisi, cette section devra dire lequel des deux a
gagné, et pourquoi.
