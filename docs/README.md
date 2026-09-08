# Les documents d'air-service-locator

| Document | Ce qu'il dit |
|---|---|
| [`modele.md`](modele.md) | Les objets, les candidats d'adresse, le bail, et ce que « joignable » veut dire exactement. |
| [`protocole.md`](protocole.md) | Les trois conversations : le daemon, les applications mobiles, et le client qui cherche un port. |
| [`annuaires.md`](annuaires.md) | Réplication entre les racines, fédération avec les annuaires rattachés, et ce qui ne se synchronise surtout pas. |
| [`contraintes.md`](contraintes.md) | Les douze règles que le code doit tenir, et ce qui les fait respecter. |

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

## Le modèle d'autorisation, en une phrase

**Rien ne se lit anonymement : l'accès est une arête entre deux comptes.** A
saisit l'identifiant public de B — que B lui a transmis hors de l'annuaire — et
lui accorde une portée ; B est notifié, et ses machines déclarées peuvent
résoudre. Il n'y a aucun jeton porteur qui circule, donc rien à récupérer quand
on retire : on retire l'arête (`modele.md` §2.5).

Le corollaire tient dans le code : **toute réponse de résolution se calcule à
partir du compte propriétaire de la machine qui demande**, jamais à partir de ce
que la requête désigne (contrainte C10).

## Le transport, en une phrase

**HTTP/3 sur QUIC, IPv6 d'abord.** Le daemon TIENT une connexion et la maintient
par un keepalive : la connexion *est* le bail. Un arrêt propre est alors
instantané, le mapping NAT reste ouvert sans mécanisme séparé, et l'annuaire
peut parler au daemon — ce qui laisse ouverte la route du rendez-vous que le
perçage de NAT exigera (`protocole.md` §0).

## Ce qui reste ouvert

Rassemblé plutôt que dispersé : `modele.md` §6 — les sous-comptes d'entreprise,
le transfert d'une machine, la traversée de NAT, la rétention. Et le choix du
magasin de persistance, dont dépend la contrainte « aucune ligne de C » que ce
dépôt ne pose donc pas encore.
