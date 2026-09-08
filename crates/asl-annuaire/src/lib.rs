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
//! # Les trois règles arrêtées par `docs/modele.md`
//!
//! - **Une deuxième annonce du même nom REMPLACE la première** (§2.4). C'est ce
//!   qu'un redémarrage exige : un daemon qui revient avec un nouveau port doit
//!   pouvoir le dire, et non se heurter à son propre fantôme. Un conflit ferait
//!   échouer le cas nominal.
//! - **Le retrait est une politesse, jamais une condition** (§4.1). Une machine
//!   qu'on débranche ne dit rien ; le silence doit donc suffire.
//! - **Le mot « en ligne » est banni** (§4.2, contrainte C6). Trois états
//!   seulement : `annoncé` — le bail court, l'annuaire n'a rien vérifié ;
//!   `joignable` — l'annuaire a lui-même atteint tel candidat, à telle date ;
//!   `expiré`. Confondre les deux premiers ferait afficher « en ligne » pour un
//!   daemon derrière un NAT que personne ne peut joindre, et son administrateur
//!   chercherait le défaut partout sauf là où il est.
//!
//! **La sonde de joignabilité DÉCIDE ici et AGIT à l'étage 3** (contrainte C1) :
//! « faut-il sonder ce candidat, et que conclure du résultat ? » est une
//! décision pure ; « ouvrir une connexion TCP et voir » est une entrée-sortie.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
