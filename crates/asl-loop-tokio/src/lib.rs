//! La boucle d'entrées-sorties sur tokio : sockets, horloge, et rien qui décide.
//!
//! # Pourquoi le moteur est dans le NOM de la crate
//!
//! Il n'y a AUCUNE abstraction d'exécution ici, et ce n'est pas un oubli. Le jour
//! où ce service tournera sur le stack Air, il aura une deuxième boucle — écrite
//! contre `air-async`, dans une autre crate — qui pilotera LA MÊME machine à
//! états. Rien à adapter, rien à maintenir entre les deux, et la logique du
//! service n'est écrite qu'une fois.
//!
//! Une couche d'abstraction, elle, devrait être maintenue pour les deux, et
//! finirait par ne convenir à aucun.
//!
//! # État
//!
//! Vide.
