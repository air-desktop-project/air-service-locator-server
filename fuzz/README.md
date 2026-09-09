# Le fuzz d'air-service-locator

**Ce que le fuzz attrape et que rien d'autre n'attrape** : une borne oubliée. Les
lints `deny` du workspace — `cast_possible_truncation`, `arithmetic_side_effects`
— voient une conversion douteuse ; ils ne voient jamais un index qui déborde d'un
cran sur une entrée que personne n'a imaginée. C'est la contrainte C3.

## Les cibles

| Cible | Graines | Ce qu'elle éprouve |
|---|---|---|
| `fuzz_asl_id_analyser` | `identifiant` | La LECTURE : des octets quelconques vers un identifiant, ou vers un refus. Aller-retour, canonicité, casse, rattrapage de Crockford, accord de `analyser_genre`. |
| `fuzz_asl_id_aller_retour` | `identifiant` | L'ÉCRITURE : seize octets quelconques vers un texte, et retour. C'est le sens qui compte en production — un identifiant naît d'un tirage. |
| `fuzz_asl_cle_signature` | `signature` | **Elle n'éprouve pas Ed25519** — `ed25519-dalek` s'en charge. Elle éprouve ce que NOTRE message lie : qu'aucun des quatre champs ne peut changer sans invalider la signature. Une faute de composition n'est attrapée par aucune bibliothèque de crypto. |
| `fuzz_asl_api_routage` | `routage` | Le chemin est **ce qu'un attaquant contrôle le plus complètement**. Aucun pourcent-encodage ne survit, aucun segment `.` ou `..` ne passe, et ce qu'on a compris se réécrit et se relit à l'identique. |
| `fuzz_asl_auth_decisions` | `decisions` | **La propriété dont la chute serait la faille entière du produit** : un service ne se rend qu'à qui y a droit. Le harnais RECALCULE la règle depuis les specs et la compare à la décision — appeler la même logique n'aurait vérifié que sa propre cohérence. |
| `fuzz_asl_annuaire_session` | `session` | **La seule qui n'éprouve pas un codec** : une MACHINE À ÉTATS, donc des invariants qui doivent tenir après n'importe quelle suite d'événements. Une session close reste close, l'expiration est monotone, et C6 tient quoi qu'il arrive. |
| `fuzz_asl_proto_valeurs` | `valeurs` | Les trois décodeurs du protocole : protocole, port, nom de service. Le port est celui où une faute coûte le plus cher — un `65536` tronqué vaudrait `0`. |
| `fuzz_asl_proto_cadrage` | `cadrage` | **La cible qui vaut le plus cher** : des octets ENTIÈREMENT contrôlés par un inconnu vers une annonce, et retour. Aller-retour, idempotence de l'écriture, bornes du tampon de sortie, et le refus des échappements vérifié sur l'entrée. |
| `fuzz_asl_proto_reponse` | `reponse` | Le message de réponse, et **C6 dans un type** : un point UDP n'est jamais dit joignable, un `joignable` porte toujours sa date, un bail tolère toujours un keepalive manqué. |
| `fuzz_asl_proto_poussee` | `poussee` | La poussée de verdict. Elle éprouve les MÊMES invariants que la réponse — et c'est le but : la validation est écrite une fois pour les deux, et une cible par message attrape le jour où quelqu'un en recopierait une version affaiblie. |
| `fuzz_asl_session_reponse` | `session-reponse` | **La seule qui compose au lieu de décoder** : une requête quelconque vers une réponse HTTP, dans un tampon dont la taille n'est pas garantie. Elle a trouvé sa première faute en vingt secondes — le corps mangeait la place du `content-length`, et un `GET` perdait un champ que le `HEAD` de la même ressource gardait (§9.3.2 de RFC 9110). |
| `fuzz_asl_proto_annonce` | `valeurs` | La VALIDATION d'une annonce. `Annonce::nouvelle` est le seul constructeur : une annonce qui existe est valide, et une seule brèche suffirait pour que les couches au-dessus héritent d'un invariant qu'elles croient tenu. |

**Deux cibles par crate, et ce n'est pas une redondance.**

Pour `asl-id`, elles partent des deux bouts et n'atteignent pas les mêmes
valeurs : la première n'explore que ce que le décodeur accepte, la seconde couvre
l'espace des seize octets, y compris ceux qu'aucune chaîne plausible ne produit.

Pour `asl-proto`, elles éprouvent deux choses différentes : les DÉCODEURS de
valeurs d'un côté, la VALIDATION d'un assemblage de l'autre. Un port bien lu ne
dit rien sur une annonce qui en porterait deux fois le même.

## La forme des propriétés

Elles se vérifient **sur le RÉSULTAT, jamais sur l'entrée**. Vérifier l'entrée
reviendrait à réécrire la validation dans le harnais et à comparer une fonction à
elle-même — ce qui passe toujours, y compris quand les deux sont fausses de la
même manière.

Et un refus est éprouvé lui aussi : la raison rendue doit **s'appliquer
vraiment**. Une erreur juste qui désigne la mauvaise cause est crue, donc pire
qu'une erreur vague.

## Lancer

```sh
# Ce que la CI lance : quelques secondes par cible, depuis les graines.
scripts/check-fuzz.sh --smoke

# Une vraie campagne, sans borne de temps.
cd fuzz && cargo fuzz run fuzz_asl_id_analyser corpus/fuzz_asl_id_analyser seeds/identifiant
```

**Le smoke-test N'EST PAS une campagne.** Quelques secondes par cible depuis un
corpus neuf n'explorent pas ce que des heures explorent : ce job attrape la
panique qu'un changement vient d'introduire sur un chemin déjà connu, et rien de
plus. S'en réclamer davantage serait affirmer une garantie qu'il n'a pas.

## Les graines

Chacune est **nommée pour ce qu'elle éprouve** — `debordement`,
`crockford-rattrape`, `symbole-u-refuse`. Une graine qu'on ne sait pas nommer est
une graine dont personne ne sait ce qu'elle apporte, et `check-fuzz.sh` refuse
les noms de quarante caractères hexadécimaux : ce sont des trouvailles brutes de
libFuzzer, dont la place est `corpus/`.

**Une trouvaille peut devenir une graine, à condition d'être renommée.**
`session/regression-keepalive-tardif` est l'entrée qui a fait tomber
`fuzz_asl_annuaire_session` à sa première campagne : une session expirée y
ressuscitait au premier keepalive. Elle est gardée pour que cela ne repasse
jamais — sous un nom qui dit ce qu'elle prouve, et non sous son SHA-1.

## Le corpus n'est pas versionné

libFuzzer garde **toute** entrée qui apporte un chemin nouveau, y compris des
milliers de variantes du même : sur `air-mail-server`, treize campagnes de vingt
secondes ont laissé 135 000 fichiers.

Le versionner avant d'avoir de quoi le réduire (`cargo fuzz cmin`) coûterait plus
qu'il n'apporterait — et l'historique garde ce qu'on y met. À reconsidérer le
jour où une campagne longue aura trouvé quelque chose qui mérite d'être gardé.

## Cette crate vit hors du workspace

Les trois raisons sont en tête de [`Cargo.toml`](Cargo.toml), et **aucune n'est
celle d'`air-mail-server`** : là-bas c'est un conflit de toolchain, ici le
workspace est déjà sur le nightly d'Air.

La conséquence, elle, est la même et elle a coûté cher là-bas : `cargo build
--workspace` ne touche pas cette crate. `scripts/check-compile.sh` et
`scripts/check-format.sh` couvrent donc les DEUX portées.
