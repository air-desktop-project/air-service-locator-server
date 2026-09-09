//! L'état VIVANT des annonces : ce qui n'existe qu'en mémoire.
//!
//! # POURQUOI RIEN DE CECI N'EST DANS L'ENTREPÔT
//!
//! **La connexion EST le bail** (`protocole.md` §1.2). Une annonce ne survit pas
//! à la connexion qui l'a faite, et l'écrire sur un disque créerait exactement
//! le mensonge que le transport tenu existe pour éviter : un annuaire qui, après
//! un redémarrage, annoncerait des ports que plus personne n'écoute.
//!
//! Un annuaire qui redémarre perd donc ses annonces, et c'est JUSTE — les
//! daemons se reconnectent, et l'état se reconstruit tout seul en un keepalive.
//!
//! # UNE ANNONCE APPARTIENT À SA CONNEXION
//!
//! Le vivier retient QUI a annoncé quoi. Sans cela, la fermeture d'une connexion
//! ne saurait pas ce qu'elle doit retirer — et il faudrait attendre l'expiration
//! du bail pour découvrir qu'un daemon arrêté proprement n'est plus là. C'est le
//! gain le plus net du transport tenu, et c'est cette carte qui le rend.

use std::collections::HashMap;

use asl_annuaire::{Etat, Instant, MotifDeDepart, Session};
use asl_id::Identifiant;

/// Une annonce vivante, et la connexion qui la porte.
struct Vivante {
    /// Ce qui décide de son état.
    session: Session,
    /// L'identifiant local de la connexion qui l'a faite.
    connexion: Vec<u8>,
}

/// Toutes les annonces vivantes de cet annuaire.
#[derive(Default)]
pub struct Vivier {
    /// Par identifiant de service.
    annonces: HashMap<Vec<u8>, Vivante>,
}

impl Vivier {
    /// Un vivier vide.
    #[must_use]
    pub fn nouveau() -> Self {
        Self::default()
    }

    /// Range cette annonce, au nom de cette connexion.
    ///
    /// **UNE RÉANNONCE DU MÊME SERVICE REMPLACE LA PRÉCÉDENTE** (`modele.md`
    /// §2.4), y compris depuis une AUTRE connexion : c'est la dernière qui a
    /// parlé qui dit la vérité, et garder les deux ferait annoncer un port et
    /// son fantôme.
    pub fn poser(&mut self, service: Identifiant, connexion: &[u8], session: Session) {
        self.annonces.insert(
            clef(service),
            Vivante {
                session,
                connexion: connexion.to_vec(),
            },
        );
    }

    /// L'annonce de ce service, si elle est vivante.
    #[must_use]
    pub fn annonce(&self, service: Identifiant) -> Option<&Session> {
        self.annonces.get(&clef(service)).map(|quoi| &quoi.session)
    }

    /// La connexion au nom de laquelle ce service est annoncé.
    ///
    /// **C'EST ELLE QUI RECEVRA LE VERDICT.** Une sonde rapporte un service ;
    /// pour pousser, il faut savoir par où.
    #[must_use]
    pub fn connexion_de(&self, service: Identifiant) -> Option<&[u8]> {
        self.annonces
            .get(&clef(service))
            .map(|quoi| quoi.connexion.as_slice())
    }

    /// Dit à toutes les annonces de cette connexion que le temps passe.
    ///
    /// # POURQUOI L'ÉCOUTE APPELLE LE KEEPALIVE, ET NON LE CLIENT
    ///
    /// `protocole.md` §1.2 : « il n'y a pas de verbe rafraîchir, le keepalive
    /// QUIC suffit ». Une connexion vivante EST la preuve que le daemon est là ;
    /// lui demander de le redire par-dessus serait un second mécanisme, avec sa
    /// propre façon de se désaccorder du premier.
    pub fn keepalive(&mut self, connexion: &[u8], maintenant: Instant) {
        for vivante in self.annonces.values_mut() {
            if vivante.connexion == connexion {
                // Une faute ici signifie une session déjà close : il n'y a rien
                // à rafraîchir, et rien à signaler.
                let _ = vivante.session.keepalive(maintenant);
            }
        }
    }

    /// Retire tout ce que cette connexion avait annoncé.
    ///
    /// **C'EST ICI QUE LE BAIL TOMBE.** Le motif distingue un arrêt propre d'une
    /// coupure, et `protocole.md` §1.3 insiste : ce sont deux choses que celui
    /// qui regarde ne traitera pas pareil.
    pub fn retirer(&mut self, connexion: &[u8], motif: MotifDeDepart) -> usize {
        let mut partis = 0_usize;
        self.annonces.retain(|_, vivante| {
            if vivante.connexion == connexion {
                vivante.session.fermer(motif);
                partis = partis.saturating_add(1);
                false
            } else {
                true
            }
        });
        partis
    }

    /// Applique le verdict d'une sonde.
    ///
    /// # UN VERDICT QUI ARRIVE TROP TARD NE RESSUSCITE RIEN
    ///
    /// Une sonde prend jusqu'à trois secondes ; le service qu'elle mesurait peut
    /// être parti entre-temps — sa connexion fermée, son annonce retirée. Le
    /// verdict tombe alors dans le vide, et `asl-annuaire` le refuse de
    /// lui-même : c'est la même règle que pour un keepalive tardif, et pour la
    /// même raison — un service qui clignote est pire qu'un service absent.
    ///
    /// Rend `true` si le verdict a changé quelque chose.
    pub fn appliquer(&mut self, verdict: &crate::sonde::Verdict) -> bool {
        let Some(vivante) = self.annonces.get_mut(&clef(verdict.service)) else {
            return false;
        };
        vivante
            .session
            .verdict_de_sonde(
                verdict.point,
                verdict.aboutie,
                verdict.quand,
                verdict.maintenant,
            )
            .unwrap_or(false)
    }

    /// Oublie ce qui a expiré.
    ///
    /// **UNE ANNONCE EXPIRÉE N'EST PAS UNE ANNONCE ABSENTE**, et c'est pour cela
    /// qu'on l'ôte plutôt que de la laisser : `asl-annuaire` la rendrait `parti
    /// (inactivité)`, ce qui est juste, mais la garder indéfiniment ferait
    /// grandir le vivier avec tout ce qui est passé.
    pub fn oublier_les_expirees(&mut self, maintenant: Instant) -> usize {
        let avant = self.annonces.len();
        self.annonces
            .retain(|_, vivante| !matches!(vivante.session.etat(maintenant), Etat::Parti { .. }));
        avant.saturating_sub(self.annonces.len())
    }

    /// Combien d'annonces vivent.
    #[must_use]
    pub fn combien(&self) -> usize {
        self.annonces.len()
    }
}

/// La clé d'un service : son genre, puis ses seize octets.
fn clef(service: Identifiant) -> Vec<u8> {
    let mut sortie = Vec::with_capacity(17);
    sortie.push(service.genre().prefixe());
    sortie.extend_from_slice(service.octets());
    sortie
}

#[cfg(test)]
mod tests {
    use asl_annuaire::{Instant, MotifDeDepart, Session};
    use asl_id::{Genre, Identifiant};
    use asl_proto::{Annonce, Bail, PointEcoute, Port, Protocole, VuDepuis};

    use super::Vivier;

    fn un(genre: Genre, graine: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [graine; 16])
    }

    /// Une session vivante sur ce service.
    fn vivante(service: Identifiant) -> Session {
        let machine = un(Genre::Machine, 1);
        let nom = asl_proto::NomService::analyser("imap").expect("un nom");
        let port = Port::depuis_u16(993).expect("un port");
        let points = [PointEcoute::nouveau(Protocole::Tcp, port)];
        let annonce = Annonce::nouvelle(machine, nom, &points, &[]).expect("une annonce");
        let vu = VuDepuis {
            adresse: core::net::IpAddr::V4(core::net::Ipv4Addr::new(203, 0, 113, 4)),
            port,
        };
        let (session, _) = Session::ouvrir(
            service,
            Bail::nouveau(15, 45).expect("un bail"),
            &annonce,
            vu,
            Instant::depuis_millisecondes(1_000),
        )
        .expect("une session");
        session
    }

    #[test]
    fn une_annonce_posee_se_retrouve() {
        let mut vivier = Vivier::nouveau();
        let service = un(Genre::Service, 1);
        vivier.poser(service, b"connexion-a", vivante(service));
        assert!(vivier.annonce(service).is_some());
        assert_eq!(vivier.combien(), 1);
    }

    #[test]
    fn un_service_jamais_annonce_est_absent() {
        let vivier = Vivier::nouveau();
        assert!(vivier.annonce(un(Genre::Service, 9)).is_none());
    }

    #[test]
    fn une_reannonce_remplace_la_precedente() {
        // **MÊME DEPUIS UNE AUTRE CONNEXION** : c'est la dernière qui a parlé
        // qui dit la vérité, et garder les deux ferait annoncer un port et son
        // fantôme.
        let mut vivier = Vivier::nouveau();
        let service = un(Genre::Service, 1);
        vivier.poser(service, b"connexion-a", vivante(service));
        vivier.poser(service, b"connexion-b", vivante(service));
        assert_eq!(vivier.combien(), 1);

        // Et c'est bien la SECONDE connexion qui la porte désormais.
        assert_eq!(vivier.retirer(b"connexion-a", MotifDeDepart::Volontaire), 0);
        assert_eq!(vivier.retirer(b"connexion-b", MotifDeDepart::Volontaire), 1);
    }

    #[test]
    fn fermer_une_connexion_retire_ses_annonces_et_elles_seules() {
        // **C'EST LE GAIN LE PLUS NET DU TRANSPORT TENU.** Un daemon arrêté
        // proprement disparaît tout de suite, sans attendre l'expiration.
        let mut vivier = Vivier::nouveau();
        let sien = un(Genre::Service, 1);
        let autre = un(Genre::Service, 2);
        vivier.poser(sien, b"connexion-a", vivante(sien));
        vivier.poser(autre, b"connexion-b", vivante(autre));

        assert_eq!(vivier.retirer(b"connexion-a", MotifDeDepart::Volontaire), 1);
        assert!(vivier.annonce(sien).is_none());
        assert!(
            vivier.annonce(autre).is_some(),
            "l'annonce d'une autre connexion a été emportée"
        );
    }

    #[test]
    fn fermer_une_connexion_qui_n_avait_rien_annonce_ne_fait_rien() {
        let mut vivier = Vivier::nouveau();
        vivier.poser(
            un(Genre::Service, 1),
            b"connexion-a",
            vivante(un(Genre::Service, 1)),
        );
        assert_eq!(vivier.retirer(b"connexion-z", MotifDeDepart::Volontaire), 0);
        assert_eq!(vivier.combien(), 1);
    }

    #[test]
    fn le_keepalive_ne_touche_que_les_annonces_de_sa_connexion() {
        // Sans ce filtre, une connexion vivante maintiendrait en vie les
        // annonces d'une connexion morte — exactement le mensonge que le
        // transport tenu existe pour éviter.
        let mut vivier = Vivier::nouveau();
        let sien = un(Genre::Service, 1);
        let orphelin = un(Genre::Service, 2);
        vivier.poser(sien, b"connexion-a", vivante(sien));
        vivier.poser(orphelin, b"connexion-b", vivante(orphelin));

        // Le bail : quarante-cinq secondes d'inactivité depuis l'ouverture, à
        // la milliseconde 1 000. L'une est rafraîchie à 40 s, l'autre non.
        vivier.keepalive(b"connexion-a", Instant::depuis_millisecondes(40_000));

        // À 50 s, celle qui n'a rien reçu a dépassé son bail ; l'autre a
        // jusqu'à 85 s.
        let apres = Instant::depuis_millisecondes(50_000);
        assert_eq!(
            vivier.oublier_les_expirees(apres),
            1,
            "seule l'annonce sans keepalive devait expirer"
        );
        assert!(vivier.annonce(sien).is_some());
        assert!(vivier.annonce(orphelin).is_none());
    }

    #[test]
    fn un_keepalive_arrive_trop_tard_ne_ressuscite_rien() {
        // **C'EST LA RÉGRESSION QUE LE FUZZ AVAIT TROUVÉE** dans `asl-annuaire`
        // : un bail expiré que rafraîchissait un keepalive tardif, et le service
        // repassait de `parti` à `annoncé`. Un service qui clignote est pire
        // qu'un service absent — celui qui regarde ne sait plus quoi en faire.
        let mut vivier = Vivier::nouveau();
        let service = un(Genre::Service, 1);
        vivier.poser(service, b"connexion-a", vivante(service));

        let bien_trop_tard = Instant::depuis_millisecondes(1_000_000);
        vivier.keepalive(b"connexion-a", bien_trop_tard);
        assert_eq!(
            vivier.oublier_les_expirees(bien_trop_tard),
            1,
            "un keepalive tardif a ressuscité une annonce"
        );
    }

    #[test]
    fn oublier_un_vivier_ou_rien_n_a_expire_ne_retire_rien() {
        let mut vivier = Vivier::nouveau();
        let service = un(Genre::Service, 1);
        vivier.poser(service, b"connexion-a", vivante(service));
        assert_eq!(
            vivier.oublier_les_expirees(Instant::depuis_millisecondes(1_100)),
            0
        );
        assert_eq!(vivier.combien(), 1);
    }
}
