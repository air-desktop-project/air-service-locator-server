//! Les identifiants **publics** d'air-service-locator : utilisateur, machine,
//! service.
//!
//! # Pourquoi ils sont « publics », et ce que ce mot engage
//!
//! Un identifiant de machine circule : il est posé dans le fichier de
//! configuration d'un daemon, lu par un administrateur, parfois recopié à la
//! main. Il est donc VISIBLE, et le traiter comme un secret serait bâtir sur une
//! propriété qu'il n'a pas. Ce qui autorise une opération est un JETON
//! (`asl-auth`), jamais un identifiant.
//!
//! # Pourquoi cette crate est à l'étage 1
//!
//! Elle décrit une FORME — comment un identifiant s'écrit, se relit et se refuse
//! — et rien de plus. Elle ne tire aucun octet d'aléa elle-même : la génération
//! prend l'entropie en paramètre, ce qui la rend éprouvable depuis un essai et la
//! laisse hors de toute entrée-sortie.
//!
//! Elle est liée AUSSI BIEN par le serveur que par `asl-client`, donc par des
//! daemons tiers. Tout ce qu'on y met, un tiers l'embarque.
//!
//! # État
//!
//! Vide. La forme des identifiants n'est pas arrêtée — c'est une décision des
//! spécifications (`docs/modele.md`), pas de ce fichier.
