//! La grammaire du protocole d'**annonce** : ce qu'un daemon dit à l'annuaire au
//! démarrage, et ce que l'annuaire lui répond.
//!
//! # Ce que cette crate fait, et ce qu'elle ne fait pas
//!
//! Des octets vers des messages, et retour. Elle ne connaît ni socket, ni
//! horloge, ni fichier. Le message « j'écoute en TCP sur le port 49152 » y est
//! une valeur ; DÉCIDER si cette annonce est recevable appartient à
//! `asl-annuaire`, et l'ÉMETTRE appartient à `asl-loop-tokio`.
//!
//! # La règle qui gouverne tout décodeur ici
//!
//! Les octets viennent du réseau, donc d'un inconnu. Une longueur annoncée ne
//! doit jamais servir à allouer avant d'avoir été bornée, et un numéro de port
//! hors de `1..=65535` se refuse — il ne se tronque pas. Les lints `deny` du
//! workspace (`cast_possible_truncation`, `arithmetic_side_effects`) sont là pour
//! cela : ils voient une conversion douteuse, jamais une borne oubliée.
//!
//! # Le cadrage, arrêté par `docs/protocole.md` §0
//!
//! **JSON sur HTTPS en v1**, pour les trois voies. La raison qui pèse le plus
//! n'est pas la simplicité : c'est que cette crate est liée par `asl-client`,
//! donc par des daemons tiers, et qu'un client HTTPS est ce qui coûte le moins
//! à imposer à quelqu'un qui voulait juste annoncer un numéro de port.
//!
//! Un cadrage binaire est nommé et repoussé (§4.3). **Cette crate est la seule
//! qui verrait la différence** — c'est exactement pourquoi elle est séparée.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
