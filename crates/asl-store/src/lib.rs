//! La persistance : comptes, machines, baux.
//!
//! # Étage 3, et ce que cela lui interdit
//!
//! Elle lit, elle écrit, elle attend. Elle ne décide de rien : les règles de
//! l'annuaire vivent dans `asl-annuaire`, qui ne sait pas qu'un disque existe.
//!
//! # DEUX CONTRAINTES PÈSENT SUR LE SCHÉMA, ET C'EST ICI QU'ELLES TOMBERONT
//!
//! - **Aucune donnée personnelle** (contrainte C13). Ni courriel, ni numéro, ni
//!   nom. Une colonne ajoutée « pour la récupération de compte » ou « pour
//!   l'affichage » violerait la contrainte, et c'est ainsi qu'elle cédera si elle
//!   cède : jamais par une décision, toujours par une commodité.
//! - **Tout enregistrement porte son ORIGINE** (contrainte C17) — `locale`, ou la
//!   relation de confiance par laquelle il est entré. Rompre une relation efface
//!   tout ce qui en venait, et un chemin d'écriture qui laisserait l'origine vide
//!   créerait un enregistrement que nulle rupture n'atteint.
//!
//! **Et le JOURNAL est un troisième régime**, distinct des deux autres : écriture
//! en append à chaque requête, lecture rare, agrégation périodique, et
//! **expiration** (contrainte C18). Rien de tout cela ne ressemble à la
//! persistance d'un compte. Le confondre avec elle donnerait un magasin qui fait
//! mal les deux.
//!
//! **Il s'écrit HORS du chemin de réponse** : un journal qui coûterait plus cher
//! sur un succès que sur un refus rendrait le temps de réponse dépendant du
//! résultat, et rouvrirait le canal que C9 ferme.
//!
//! # Ce qui reste à trancher
//!
//! Le support n'est pas choisi, et il ne se choisit pas avant de savoir ce que
//! l'annuaire écrit et à quelle cadence. Le découpage aide : **l'état vivant —
//! baux, candidats, joignabilité — n'est PAS répliqué** (`annuaires.md` §3), et
//! seules les écritures durables, rares et humaines, passent par le quorum des
//! deux racines et de leur témoin. Ce sont deux régimes très différents, et rien
//! n'oblige à les servir avec le même magasin.
//!
//! # État
//!
//! Vide.
