//! La grammaire de l'API que les applications mobiles consomment : créer un
//! compte, déclarer une machine, lister les services et leur état.
//!
//! # Pourquoi elle est séparée d'`asl-proto`
//!
//! Ce sont DEUX publics et DEUX rythmes. `asl-proto` sert des daemons qu'on ne
//! met pas à jour souvent, et qui doivent rester compatibles longtemps ; cette
//! crate-ci sert deux applications qu'on republie quand on veut. Les mêler
//! ferait payer à un daemon installé chez un tiers le prix d'un écran ajouté
//! dans une application.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne sert rien. Elle décrit des requêtes et des réponses ; ce qui les
//! transporte est à l'étage 3, ce qui les autorise est dans `asl-auth`.
//!
//! # État
//!
//! Vide. Les écrans des deux applications ne sont pas arrêtés, et une API écrite
//! avant eux décrirait des besoins supposés.
