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
//! # La forme, arrêtée par `docs/modele.md` §2
//!
//! Un préfixe d'une lettre, un tiret, puis 26 caractères portant 128 bits :
//! `u-` utilisateur, `a-` appareil, `m-` machine, `s-` service, `g-`
//! autorisation.
//!
//! **Il n'y a PAS d'identifiant de secret dans cette liste**, et c'est le point :
//! aucune authentification de ce produit ne repose sur un secret partagé
//! (contrainte C14). Une machine détient une paire de clés Ed25519 ; ce qui se
//! recopie à la main est un CODE D'ENRÔLEMENT à usage unique, qui vit quelques
//! minutes et n'ouvre qu'une opération.
//!
//! **L'alphabet est le base32 de Crockford**, et ce n'est pas un goût : ces
//! chaînes se recopient à la main dans des fichiers de configuration. Crockford
//! retire `I`, `L`, `O` et `U` — les quatre que l'œil confond avec `1`, `0` et
//! `V` — et relit indifféremment la majuscule et la minuscule. Un base64 y
//! ferait perdre une machine sur une transcription.
//!
//! **128 bits ne se devinent pas**, ce qui ferme l'énumération. Mais un
//! identifiant N'EST PAS UN SECRET (voir ci-dessus) : ce qui autorise une
//! lecture est une AUTORISATION entre deux comptes, révocable — un identifiant,
//! lui, ne se change pas.
//!
//! **L'identifiant d'utilisateur a un emploi de plus, et il gouverne sa forme** :
//! il se transmet de la main à la main, par SMS ou à voix haute, pour qu'un ami
//! vous accorde l'accès à ses services. C'est celui des cinq qu'un humain
//! recopiera le plus souvent, et la raison pour laquelle l'alphabet compte.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
