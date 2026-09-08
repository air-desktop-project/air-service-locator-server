# Modèle — À ÉCRIRE

Ce que l'énoncé du projet pose déjà, et qui n'est pas encore une spécification :

- Un **utilisateur** — un particulier, ou un administrateur pour une entreprise —
  se crée un compte. La création produit un **identifiant public d'utilisateur**,
  unique.
- Cet identifiant permet de déclarer des **machines**, connues elles aussi par un
  **identifiant public de machine**. Une machine est en gestion par un
  utilisateur.
- L'identifiant de machine permet à un **daemon** quelconque tournant sur cette
  machine de s'enregistrer et de signaler son état.
- Un daemon annonce le **port UDP ou TCP** sur lequel il écoute. L'annuaire
  répond « en ligne » ou « hors ligne » à qui le demande.

## Les questions que cela laisse entières

**Sur les identités**

1. Un identifiant public est-il devinable ? S'il l'est, un inconnu peut énumérer
   les machines ; s'il ne l'est pas, il devient un demi-secret qu'on recopie à la
   main dans des fichiers de configuration.
2. Un utilisateur peut-il en gérer un autre — le cas « administrateur
   d'entreprise » suppose-t-il des comptes subordonnés, ou une seule identité ?
3. Une machine peut-elle changer de propriétaire ?

**Sur les services**

4. Qu'est-ce qui identifie un service ? Le triplet (machine, nom, protocole) ?
   Un identifiant propre ? Deux daemons du même nom sur une machine : conflit, ou
   remplacement ?
5. Une machine derrière un NAT annonce un port local qui ne veut rien dire de
   l'extérieur. L'annuaire enregistre-t-il l'adresse source qu'il OBSERVE, ou ce
   que le daemon lui DIT ? Les deux ne coïncident pas, et c'est le cas le plus
   fréquent en pratique.
6. Un daemon peut-il annoncer plusieurs ports ? Un en TCP, un en UDP ?

**Sur l'état, qui est la question centrale**

7. « En ligne » se déduit d'un **bail** : le daemon rafraîchit, et l'absence de
   rafraîchissement vaut hors ligne. Quelle durée ? Quelle cadence ? Le compromis
   est direct — un bail court détecte vite une panne et coûte du trafic ; un bail
   long fait l'inverse.
8. Un arrêt propre s'annonce-t-il ? Il le devrait, mais le silence doit suffire :
   une machine qu'on débranche ne dit rien.
9. Que voit un client pendant l'intervalle où le daemon est mort mais son bail
   court encore ? C'est une réponse FAUSSE, et il faut décider de son coût.

**Sur ce qui autorise**

10. Un daemon ne fait pas de biométrie. Par quoi s'authentifie-t-il, et comment
    ce secret arrive-t-il sur la machine — l'application mobile le pose-t-elle ?
11. Qui peut INTERROGER l'annuaire ? Le client d'un daemon est souvent une autre
    machine, qui n'a pas de compte. Un annuaire ouvert en lecture est un annuaire
    qu'on énumère.
