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

---

## C1 — Les étages 1 et 2 ne font aucune entrée-sortie

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

**Il n'existe aucune requête de résolution qui rende quoi que ce soit sans un
secret de machine valide.** Pas de mode anonyme, pas de jeton porteur qu'on se
passe, pas de service « public » — l'accès est une arête entre deux comptes
(`modele.md` §2.5), et elle se révoque en la retirant.

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

---

## Ce qui n'est PAS une contrainte de ce dépôt

**« Aucune ligne de C » DANS LE SERVEUR.** Elle est posée pour `asl-client`
(C4), où elle est structurelle. Côté serveur elle ne l'est pas — et ce n'est pas
un oubli : elle dépend de la persistance, un SQLite lie du C, un magasin écrit
ici n'en lie pas. Le choix du magasin n'est pas fait (`modele.md` §6), et poser
la contrainte avant lui reviendrait à trancher par la bande une décision qui n'a
pas été prise.

Le jour où le magasin sera choisi, cette section devra dire lequel des deux a
gagné, et pourquoi.
