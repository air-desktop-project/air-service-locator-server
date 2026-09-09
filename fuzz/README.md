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
| `fuzz_asl_proto_valeurs` | `valeurs` | Les trois décodeurs du protocole : protocole, port, nom de service. Le port est celui où une faute coûte le plus cher — un `65536` tronqué vaudrait `0`. |
| `fuzz_asl_proto_cadrage` | `cadrage` | **La cible qui vaut le plus cher** : des octets ENTIÈREMENT contrôlés par un inconnu vers une annonce, et retour. Aller-retour, idempotence de l'écriture, bornes du tampon de sortie, et le refus des échappements vérifié sur l'entrée. |
| `fuzz_asl_proto_reponse` | `reponse` | Le message de réponse, et **C6 dans un type** : un point UDP n'est jamais dit joignable, un `joignable` porte toujours sa date, un bail tolère toujours un keepalive manqué. |
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

Elles sont **écrites à la main**, et `check-fuzz.sh` le vérifie : un fichier dont
le nom est quarante caractères hexadécimaux est une trouvaille de libFuzzer, dont
la place est `corpus/` et non ici.

Chacune est nommée pour ce qu'elle éprouve — `debordement`, `crockford-rattrape`,
`symbole-u-refuse`. Une graine qu'on ne sait pas nommer est une graine dont
personne ne sait ce qu'elle apporte.

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
