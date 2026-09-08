//! La bibliothèque des DEUX bouts : ce qu'un daemon lie pour s'annoncer, et ce
//! qu'un de ses clients lie pour retrouver le port où le joindre.
//!
//! # Le problème que tout ceci existe pour résoudre
//!
//! Un daemon qui n'a pas de numéro de port fixe est un daemon qu'on ne peut pas
//! joindre — sauf si quelque chose sait où il est. Cette crate est ce quelque
//! chose, vu des deux côtés :
//!
//! - au démarrage, le daemon obtient un port du système, puis l'ANNONCE ;
//! - plus tard, son client DEMANDE ce port et ouvre la connexion.
//!
//! # Ce qui contraint cette crate plus que les autres
//!
//! **Elle est liée par du code qui n'est pas le nôtre.** Sa surface publique est
//! donc un engagement, et son graphe de dépendances aussi : ce qu'elle tire, un
//! daemon tiers l'embarque. Elle ne doit jamais dépendre d'`asl-store` ni
//! d'`asl-annuaire` — s'annoncer ne doit pas coûter d'embarquer la base de
//! données du service.
//!
//! **Et elle doit survivre à l'annuaire.** Un service de découverte injoignable
//! ne doit pas empêcher un daemon de démarrer : ce qui se passe alors — réessai,
//! dernier port connu, abandon — est une décision de spécification, mais elle
//! sera prise ici.
//!
//! # Ce que le porteur doit poser sur la machine
//!
//! **Un secret de machine, `sm-…`, et rien d'autre** (`docs/modele.md` §2.3).
//! Le même objet des deux côtés : la machine qui héberge le daemon le porte avec
//! la capacité `annonce`, celle qui consomme le porte avec la capacité
//! `lecture`. Une machine n'est pas « une machine à daemon » — c'est n'importe
//! quelle machine d'un utilisateur.
//!
//! **Il n'y a aucun mode anonyme à implémenter** (contrainte C10) : une
//! résolution sans secret valide n'existe pas, et un client qui prévoirait un
//! chemin de repli « sans authentification » coderait une porte que le serveur
//! n'ouvre pas.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
