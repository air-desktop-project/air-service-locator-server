# Les documents d'air-service-locator

| Document | Ce qu'il dit |
|---|---|
| [`modele.md`](modele.md) | Les objets, les candidats d'adresse, le bail, et ce que « joignable » veut dire exactement. |
| [`protocole.md`](protocole.md) | Les trois conversations : le daemon, les applications mobiles, et le client qui cherche un port. |
| [`contraintes.md`](contraintes.md) | Les neuf règles que le code doit tenir, et ce qui les fait respecter. |

**Ils sont dans CE dépôt, et pas dans les trois.** Le modèle et le protocole
gouvernent aussi les deux applications mobiles ; les recopier ferait trois
versions dont deux vieilliraient en silence. Les dépôts iOS et Android y
renvoient par lien.

## L'exigence qui gouverne tout

**Un daemon annoncé doit être joignable depuis l'Internet.** Une machine à
adresse publique tient cette exigence sans rien faire ; une machine derrière un
NAT ne la tient pas, et **comment l'y amener n'est pas décidé** — c'est la
question ouverte la plus lourde du produit (`modele.md` §6.3).

En attendant, l'annuaire **mesure** la joignabilité et la dit, plutôt que de la
supposer. C'est ce qui apprend à un administrateur que son daemon ne tient pas
l'exigence, au lieu qu'il l'apprenne le jour où quelqu'un s'en plaint.

## Ce qui reste ouvert

Rassemblé plutôt que dispersé : `modele.md` §6 — les sous-comptes d'entreprise,
le transfert d'une machine, la traversée de NAT, la rétention. Et le choix du
magasin de persistance, dont dépend la contrainte « aucune ligne de C » que ce
dépôt ne pose donc pas encore.
