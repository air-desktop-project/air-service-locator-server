//! Le binaire du service.
//!
//! Il n'a aucune logique à lui : il lit une configuration, assemble le magasin,
//! l'annuaire et la boucle, puis leur cède la main. Tout ce qui décide vit dans
//! les crates des étages 1 et 2, où des essais peuvent l'atteindre.
//!
//! # État
//!
//! Il ne fait rien, et il le dit — plutôt que de démarrer une boucle vide qui
//! aurait l'air de servir.

fn main() {
    println!(
        "air-service-locator : rien à servir — les spécifications ne sont pas écrites (docs/)."
    );
}
