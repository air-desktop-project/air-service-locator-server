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
//! # Les verbes, arrêtés par `docs/protocole.md` §2
//!
//! Créer un compte, enrôler un appareil de plus, révoquer, déclarer une machine,
//! remplacer son secret de machine, lister les services, **accorder et révoquer
//! une autorisation à un autre compte**, et déposer un jeton de poussée.
//!
//! **Il n'y a pas de mot de passe dans ce produit.** Un compte est un jeu
//! d'appareils enrôlés, et toute requête est signée par une clé qui vit dans le
//! matériel sécurisé d'un téléphone. Aucun champ de cette API ne porte un
//! booléen d'authentification (contrainte C7).
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
