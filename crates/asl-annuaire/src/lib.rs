//! L'annuaire lui-même : qui possède quoi, qui écoute où, et depuis quand.
//!
//! # Une machine à états, et pas un service
//!
//! Elle reçoit des messages déjà décodés et **l'heure** ; elle rend des réponses
//! et des ACTIONS. Elle n'attend jamais, n'ouvre rien, n'écrit nulle part.
//!
//! **L'heure est un paramètre, et c'est la décision de conception qui compte
//! ici.** L'état « en ligne » d'un daemon n'est pas un fait qu'on stocke, c'est
//! une conclusion qu'on tire d'un bail et d'une horloge : un daemon est en ligne
//! tant que son bail n'a pas expiré. Si l'horloge était un appel système au fond
//! d'une boucle, éprouver une expiration coûterait d'attendre réellement le
//! délai ; en paramètre, l'essai la pilote en trois lignes.
//!
//! # Ce qui reste à trancher, et qui ne peut pas l'être ici
//!
//! - Un daemon qui s'arrête proprement le dit-il, ou laisse-t-il son bail
//!   expirer ? Les deux, probablement — mais le silence doit alors suffire.
//! - Que vaut une annonce dont le port a changé depuis la précédente ?
//! - Deux daemons du même nom sur la même machine : conflit, ou remplacement ?
//!
//! Ces questions sont celles des spécifications (`docs/modele.md`).
//!
//! # État
//!
//! Vide.
