# Les documents d'air-service-locator

**Ces trois documents sont VIDES DE DÉCISIONS.** Ils ne consignent pas ce qui a
été arrêté ; ils consignent ce qui ne l'est pas, question par question. C'est
délibéré : l'arborescence a été posée avant les spécifications, et un document
qui affirmerait des choix que personne n'a faits vaudrait moins que rien — il
serait cru.

| Document | Ce qu'il devra dire |
|---|---|
| [`contraintes.md`](contraintes.md) | Les règles que le découpage en crates doit tenir, et pourquoi. |
| [`modele.md`](modele.md) | Utilisateurs, machines, services, baux — ce qui existe et ce qui les lie. |
| [`protocole.md`](protocole.md) | Ce qu'un daemon dit à l'annuaire, et ce qu'un client lui demande. |

**Ils sont dans CE dépôt, et pas dans les trois.** Le modèle et le protocole
gouvernent aussi les deux applications mobiles ; les recopier ferait trois
versions dont deux vieilliraient en silence. Les dépôts iOS et Android y
renvoient par lien.
