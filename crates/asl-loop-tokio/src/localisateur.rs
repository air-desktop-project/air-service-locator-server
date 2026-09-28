//! Le localisateur détecté (`--locator auto`, décision 64) : la tâche qui
//! relit les adresses de la machine à la cadence de la fédération, et
//! republie le locateur quand il change.
//!
//! **Ce qui décide n'est pas ici** : le choix de l'adresse est
//! `asl_registre::localisateur::choisir`, une fonction pure des deux textes
//! que le noyau écrit, couverte et fuzzée. Ici, on lit ces textes, on
//! compose `[adresse]:port`, on publie dans [`LocateursPublies`] — que chaque
//! fédérateur surveille et pousse aussitôt à sa racine —, et on le dit au
//! journal.
//!
//! # QUAND IL N'Y A PLUS D'ADRESSE
//!
//! Un lien qui tombe, un préfixe retiré avant que le suivant n'arrive, une
//! machine qui n'est pas sous Linux : aucune adresse publiable. **On ne publie
//! rien**, et on le dit une fois. La dernière adresse publiée reste ce que les
//! racines tiennent : c'est la meilleure estimation qu'on ait, et un retrait
//! renverrait vers l'adresse déclarée à l'inscription, qui n'a aucune raison
//! d'être meilleure. Dès qu'une adresse revient, elle part.

use std::net::Ipv6Addr;
use std::sync::Arc;

use crate::federation::LocateursPublies;

/// Où le noyau Linux écrit les adresses IPv6 de la machine.
pub const ADRESSES: &str = "/proc/net/if_inet6";

/// Où il écrit ses routes IPv6.
pub const ROUTES: &str = "/proc/net/ipv6_route";

/// Lit les deux textes du noyau : les adresses, puis les routes.
///
/// # Errors
///
/// Le message de l'échec, si les adresses ne se lisent pas. Des routes
/// illisibles ne sont pas une faute : la règle se passe de la route par
/// défaut.
pub fn lire_le_noyau() -> Result<(String, String), String> {
    let adresses =
        std::fs::read_to_string(ADRESSES).map_err(|faute| format!("{ADRESSES} : {faute}"))?;
    let routes = std::fs::read_to_string(ROUTES).unwrap_or_default();
    Ok((adresses, routes))
}

/// Le locateur publié pour cette adresse et ce port.
#[must_use]
pub fn locateur(adresse: Ipv6Addr, port: u16) -> String {
    format!("[{adresse}]:{port}")
}

/// La tâche qui détecte le localisateur.
pub struct Detecteur {
    /// L'interface nommée (`--locator auto:<interface>`), s'il y en a une.
    pub interface: Option<String>,
    /// Le port d'écoute de cet annuaire.
    pub port: u16,
    /// Les locateurs fixes donnés à côté (`--locator <hôte:port>`), publiés
    /// après l'adresse détectée.
    pub fixes: Vec<String>,
    /// Là où l'on publie, et que les fédérateurs lisent.
    pub publies: Arc<LocateursPublies>,
    /// De quoi lire les deux textes du noyau ([`lire_le_noyau`] en service).
    pub lire: Box<dyn Fn() -> Result<(String, String), String> + Send + Sync>,
    /// Le journal d'exploitation.
    pub journal: Box<dyn Fn(String) + Send + Sync>,
    /// La cadence de relecture, en millisecondes — celle de la fédération.
    pub cadence_ms: u64,
}

/// Ce que le détecteur se rappelle d'un tour à l'autre.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Souvenir {
    /// La dernière adresse publiée.
    pub publiee: Option<Ipv6Addr>,
    /// L'absence d'adresse a-t-elle déjà été dite ?
    pub absence_dite: bool,
}

impl Detecteur {
    /// Un tour : lire, choisir, publier si l'adresse a changé, et le dire.
    pub fn un_tour(&self, souvenir: &mut Souvenir) {
        let lu = (self.lire)();
        let choisie = lu.as_ref().ok().and_then(|(adresses, routes)| {
            asl_registre::localisateur::choisir(adresses, routes, self.interface.as_deref())
        });
        match choisie {
            Some(adresse) => {
                souvenir.absence_dite = false;
                if souvenir.publiee == Some(adresse) {
                    return;
                }
                let nouveau = locateur(adresse, self.port);
                (self.journal)(match souvenir.publiee {
                    Some(avant) => {
                        format!("localisateur : {} → {nouveau}", locateur(avant, self.port))
                    }
                    None => format!("localisateur : {nouveau} (détecté)"),
                });
                let mut liste = vec![nouveau];
                liste.extend(self.fixes.iter().cloned());
                self.publies.publier(liste);
                souvenir.publiee = Some(adresse);
            }
            None if !souvenir.absence_dite => {
                let ou = self
                    .interface
                    .as_deref()
                    .map_or_else(String::new, |nom| format!(" sur {nom}"));
                let pourquoi = match &lu {
                    Err(faute) => format!(" ({faute})"),
                    Ok(_) => String::new(),
                };
                let garde = match souvenir.publiee {
                    Some(avant) => format!(
                        "la dernière connue, {}, reste publiée",
                        locateur(avant, self.port)
                    ),
                    None => {
                        "rien n'est publié, les racines gardent ce qu'elles tenaient".to_owned()
                    }
                };
                (self.journal)(format!(
                    "localisateur : aucune adresse IPv6 globale stable{ou}{pourquoi} — {garde}"
                ));
                souvenir.absence_dite = true;
            }
            None => {}
        }
    }

    /// Détecte sans fin, à la cadence, depuis rien.
    ///
    /// **CETTE FONCTION NE REND JAMAIS** tant que la tâche vit.
    pub async fn detecter_sans_fin(self) {
        let mut souvenir = Souvenir::default();
        self.un_tour(&mut souvenir);
        self.continuer_sans_fin(souvenir).await;
    }

    /// Attend la cadence, puis détecte, sans fin, depuis ce souvenir — celui
    /// d'un premier tour fait avant de lever les fédérateurs, pour que leur
    /// première ouverture publie déjà l'adresse.
    pub async fn continuer_sans_fin(self, mut souvenir: Souvenir) {
        loop {
            tokio::time::sleep(core::time::Duration::from_millis(self.cadence_ms.max(1))).await;
            self.un_tour(&mut souvenir);
        }
    }
}

#[cfg(test)]
mod essais {
    use super::*;
    use std::sync::Mutex;

    const ETHERNET: &str = "2a01cb190d272f003ac986fffe479d54 02 40 00 00 enp3s0f0\n";
    const RENUMEROTE: &str = "2a01cb190d99aa003ac986fffe479d54 02 40 00 00 enp3s0f0\n";

    /// Un détecteur dont le noyau est `noyau`, et dont le journal s'écrit
    /// dans `lignes`.
    fn detecteur(
        noyau: Arc<Mutex<Result<String, String>>>,
        lignes: Arc<Mutex<Vec<String>>>,
        interface: Option<&str>,
        fixes: &[&str],
    ) -> Detecteur {
        Detecteur {
            interface: interface.map(str::to_owned),
            port: 6630,
            fixes: fixes.iter().map(|&fixe| fixe.to_owned()).collect(),
            publies: Arc::new(LocateursPublies::inconnus()),
            lire: Box::new(move || {
                noyau
                    .lock()
                    .expect("le noyau")
                    .clone()
                    .map(|adresses| (adresses, String::new()))
            }),
            journal: Box::new(move |ligne| lignes.lock().expect("le journal").push(ligne)),
            cadence_ms: 10,
        }
    }

    #[test]
    fn une_adresse_qui_change_se_publie_et_se_dit_une_fois() {
        let noyau = Arc::new(Mutex::new(Ok(ETHERNET.to_owned())));
        let lignes = Arc::new(Mutex::new(Vec::new()));
        let detecteur = detecteur(
            Arc::clone(&noyau),
            Arc::clone(&lignes),
            None,
            &["192.0.2.51:6630"],
        );
        let mut souvenir = Souvenir::default();

        detecteur.un_tour(&mut souvenir);
        assert_eq!(
            detecteur.publies.lire(),
            (
                1,
                Some(vec![
                    "[2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630".to_owned(),
                    "192.0.2.51:6630".to_owned()
                ])
            )
        );
        // La même adresse : rien ne bouge, rien ne se dit.
        detecteur.un_tour(&mut souvenir);
        assert_eq!(detecteur.publies.version(), 1);

        // L'opérateur renumérote.
        *noyau.lock().expect("le noyau") = Ok(RENUMEROTE.to_owned());
        detecteur.un_tour(&mut souvenir);
        assert_eq!(detecteur.publies.version(), 2);
        assert_eq!(
            detecteur
                .publies
                .lire()
                .1
                .and_then(|liste| liste.first().cloned()),
            Some("[2a01:cb19:d99:aa00:3ac9:86ff:fe47:9d54]:6630".to_owned())
        );
        assert_eq!(
            *lignes.lock().expect("le journal"),
            [
                "localisateur : [2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630 (détecté)",
                "localisateur : [2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630 → \
                 [2a01:cb19:d99:aa00:3ac9:86ff:fe47:9d54]:6630",
            ]
        );
    }

    #[test]
    fn sans_adresse_rien_ne_se_publie_et_l_absence_se_dit_une_fois() {
        let noyau = Arc::new(Mutex::new(Err(format!("{ADRESSES} : absent"))));
        let lignes = Arc::new(Mutex::new(Vec::new()));
        let detecteur = detecteur(
            Arc::clone(&noyau),
            Arc::clone(&lignes),
            Some("enp3s0f0"),
            &[],
        );
        let mut souvenir = Souvenir::default();

        // Le noyau ne se lit pas : rien n'est publié.
        detecteur.un_tour(&mut souvenir);
        detecteur.un_tour(&mut souvenir);
        assert_eq!(detecteur.publies.lire(), (0, None));

        // Une adresse arrive, puis le lien tombe : la dernière reste publiée.
        *noyau.lock().expect("le noyau") = Ok(ETHERNET.to_owned());
        detecteur.un_tour(&mut souvenir);
        *noyau.lock().expect("le noyau") = Ok(String::new());
        detecteur.un_tour(&mut souvenir);
        detecteur.un_tour(&mut souvenir);
        assert_eq!(
            detecteur.publies.lire(),
            (
                1,
                Some(vec![
                    "[2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630".to_owned()
                ])
            )
        );
        // Elle revient, identique : rien ne se republie.
        *noyau.lock().expect("le noyau") = Ok(ETHERNET.to_owned());
        detecteur.un_tour(&mut souvenir);
        assert_eq!(detecteur.publies.version(), 1);
        assert_eq!(
            *lignes.lock().expect("le journal"),
            [
                "localisateur : aucune adresse IPv6 globale stable sur enp3s0f0 \
                 (/proc/net/if_inet6 : absent) — rien n'est publié, les racines gardent \
                 ce qu'elles tenaient",
                "localisateur : [2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630 (détecté)",
                "localisateur : aucune adresse IPv6 globale stable sur enp3s0f0 — la \
                 dernière connue, [2a01:cb19:d27:2f00:3ac9:86ff:fe47:9d54]:6630, reste publiée",
            ]
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn la_tache_relit_a_la_cadence() {
        let noyau = Arc::new(Mutex::new(Ok(String::new())));
        let lignes = Arc::new(Mutex::new(Vec::new()));
        let detecteur = detecteur(Arc::clone(&noyau), lignes, None, &[]);
        let publies = Arc::clone(&detecteur.publies);
        let tache = tokio::spawn(detecteur.detecter_sans_fin());
        tokio::time::sleep(core::time::Duration::from_millis(15)).await;
        assert_eq!(publies.version(), 0);
        *noyau.lock().expect("le noyau") = Ok(ETHERNET.to_owned());
        tokio::time::sleep(core::time::Duration::from_millis(20)).await;
        assert_eq!(publies.version(), 1);
        tache.abort();
    }
}
