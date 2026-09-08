//! La persistance : comptes, machines, baux.
//!
//! # Étage 3, et ce que cela lui interdit
//!
//! Elle lit, elle écrit, elle attend. Elle ne décide de rien : les règles de
//! l'annuaire vivent dans `asl-annuaire`, qui ne sait pas qu'un disque existe.
//!
//! # Ce qui reste à trancher
//!
//! Le support n'est pas choisi, et il ne se choisit pas avant de savoir ce que
//! l'annuaire écrit et à quelle cadence. Un bail rafraîchi toutes les trente
//! secondes par mille daemons n'appelle pas le même magasin qu'un compte créé
//! une fois par mois.
//!
//! # État
//!
//! Vide.
