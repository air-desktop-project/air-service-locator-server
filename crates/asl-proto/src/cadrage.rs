//! Le **cadrage** : les octets qui transportent les valeurs, et retour.
//!
//! JSON au-dessus de HTTP/3 (`docs/protocole.md` §0). C'est la seule partie de
//! cette crate qui changerait si l'on passait un jour à un format binaire — et
//! c'est pourquoi elle est un module à part.
//!
//! # RIEN N'EST ALLOUÉ, ET C'EST UNE PROPRIÉTÉ DE SÉCURITÉ
//!
//! La règle du produit dit qu'une longueur venue du réseau ne sert jamais à
//! allouer avant d'avoir été bornée. **La forme la plus forte de cette règle est
//! de ne pas allouer du tout**, et c'est celle qui est tenue ici : le décodeur
//! emprunte au tampon d'entrée, l'appelant fournit les tableaux de sortie
//! ([`Tampons`]), et l'encodeur écrit dans une tranche qu'on lui donne.
//!
//! Ce n'est pas de la coquetterie `no_std`. Cette crate est embarquée par
//! `asl-client` dans des processus qui ne sont pas les nôtres — un interpréteur
//! Python, une JVM. Un analyseur qui y allouerait au gré d'un message reçu
//! ferait porter à l'hôte un risque qu'il n'a pas choisi.
//!
//! # TROIS REFUS, ET CHACUN A SON PRIX
//!
//! ## 1. Aucun échappement dans une chaîne
//!
//! Les valeurs de ce message — identifiant, nom de service, protocole, adresse —
//! n'emploient **aucun caractère qui demande un échappement**. Un `a` à la
//! place d'un `a` serait donc soit une deuxième écriture de la même valeur, soit
//! une tentative de faire passer un caractère que l'alphabet refuse.
//!
//! C'est exactement la règle qui refuse `0080` pour `80`, appliquée au cadrage.
//! Elle supprime au passage tout le décodage UTF-16 et ses paires de
//! substitution, c'est-à-dire la moitié des failles historiques des analyseurs
//! JSON.
//!
//! **Le prix, et il est réel** : le jour où un champ portera du texte libre — le
//! nom d'affichage d'une machine, par exemple — ce décodeur devra apprendre les
//! échappements. Ce sera une décision, pas un oubli.
//!
//! ## 2. Aucun champ inconnu
//!
//! Un champ qu'on ignore est un champ que l'émetteur croit avoir transmis. Un
//! daemon qui annoncerait une propriété nouvelle à un annuaire plus ancien
//! croirait l'avoir posée, et rien ne le détromperait.
//!
//! **Le prix** : ajouter un champ casse les lecteurs existants, et relève donc
//! d'une nouvelle version de l'API — `/v2/`, pas `/v1/`. C'est le sens du
//! préfixe de version. **Ce refus se relâche plus tard ; l'inverse ne se
//! resserre jamais** sans casser ceux qui s'étaient habitués à la tolérance.
//!
//! ## 3. Aucun champ en double
//!
//! JSON ne l'interdit pas, et c'est précisément le problème : deux analyseurs
//! qui ne choisissent pas le même gagnant lisent deux messages différents dans
//! les mêmes octets. C'est une famille entière de contournements
//! d'autorisation, et elle se ferme en refusant.
//!
//! # Les nombres sont des ENTIERS NON SIGNÉS, et rien d'autre
//!
//! Aucun champ de ce protocole n'a de sens en virgule flottante. Accepter
//! `49152.0` obligerait à décider d'un arrondi — donc à faire un choix que
//! personne n'a demandé, dans un décodeur.

use core::fmt;
use core::net::IpAddr;

use asl_id::{Genre, Identifiant};

use crate::{
    ADRESSES_MAX, Annonce, Bail, Candidat, Erreur, Horodatage, Joignabilite, NomService, Origine,
    POINTS_MAX, PointEcoute, Port, Protocole, RaisonNonSonde, Reponse, Verdict, VerdictNat,
    VuDepuis,
};

/// La taille maximale d'un message d'annonce, en octets.
///
/// **Une borne existe parce que la longueur vient du réseau.** Quatre kibioctets
/// laissent largement la place à huit points d'écoute et huit adresses ; au-delà,
/// l'émetteur est cassé ou hostile.
pub const MESSAGE_MAX: usize = 4_096;

/// Les tableaux que l'appelant prête au décodeur.
///
/// **C'est ainsi qu'on décode sans allouer.** Le message emprunte ses tranches à
/// cette structure, qui doit donc vivre aussi longtemps que lui.
#[derive(Debug, Clone, Copy)]
pub struct Tampons {
    points: [PointEcoute; POINTS_MAX],
    adresses: [IpAddr; ADRESSES_MAX],
}

impl Tampons {
    /// Des tampons neufs.
    ///
    /// Leur contenu initial n'a aucun sens et n'est jamais lu : le décodeur ne
    /// rend que le préfixe qu'il a réellement rempli.
    #[must_use]
    pub const fn nouveaux() -> Self {
        Self {
            points: [PointEcoute::nouveau(Protocole::Tcp, Port::UN); POINTS_MAX],
            adresses: [IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED); ADRESSES_MAX],
        }
    }
}

impl Default for Tampons {
    fn default() -> Self {
        Self::nouveaux()
    }
}

// ── Le lecteur ──────────────────────────────────────────────────────────────

/// Un curseur sur les octets du message.
struct Lecteur<'a> {
    octets: &'a [u8],
    position: usize,
}

impl<'a> Lecteur<'a> {
    const fn nouveau(octets: &'a [u8]) -> Self {
        Self {
            octets,
            position: 0,
        }
    }

    /// L'octet courant, sans avancer.
    fn regarder(&self) -> Option<u8> {
        self.octets.get(self.position).copied()
    }

    /// Avance d'un octet.
    fn avancer(&mut self) {
        self.position = self.position.saturating_add(1);
    }

    /// Saute les blancs que JSON autorise, et **eux seuls**.
    ///
    /// Ni tabulation verticale, ni page suivante, ni espace insécable : RFC 8259
    /// §2 en nomme quatre, et en accepter un cinquième ferait diverger ce lecteur
    /// de tout autre.
    fn sauter_blancs(&mut self) {
        while matches!(self.regarder(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.avancer();
        }
    }

    /// Exige un octet précis, blancs sautés d'abord.
    fn attendre(&mut self, octet: u8, attendu: &'static str) -> Result<(), Erreur> {
        self.sauter_blancs();
        if self.regarder() == Some(octet) {
            self.avancer();
            Ok(())
        } else {
            Err(Erreur::JsonAttendu {
                position: self.position,
                attendu,
            })
        }
    }

    /// Lit une chaîne JSON.
    ///
    /// **Aucun échappement, aucun octet de contrôle, aucun non-ASCII.** Les
    /// raisons sont en tête de ce module ; ce qui compte ici est que le résultat
    /// emprunte au tampon d'entrée, sans copie ni transformation — donc ce qu'on
    /// rend est littéralement ce qui a été reçu.
    fn chaine(&mut self) -> Result<&'a str, Erreur> {
        self.attendre(b'"', "une chaîne")?;
        let debut = self.position;

        loop {
            let Some(octet) = self.regarder() else {
                return Err(Erreur::JsonAttendu {
                    position: self.position,
                    attendu: "la fin d'une chaîne",
                });
            };
            match octet {
                b'"' => break,
                b'\\' => {
                    return Err(Erreur::EchappementRefuse {
                        position: self.position,
                    });
                }
                // Les octets de contrôle DOIVENT être échappés en JSON ; ici les
                // échappements sont refusés, donc ils ne peuvent pas apparaître.
                // Le non-ASCII l'est aussi : aucune valeur de ce protocole n'en
                // porte, et l'accepter ouvrirait des écritures équivalentes que
                // seule une normalisation Unicode saurait rapprocher.
                0x00..=0x1F | 0x7F..=0xFF => {
                    return Err(Erreur::CaractereBrutRefuse {
                        position: self.position,
                    });
                }
                _ => self.avancer(),
            }
        }

        let fin = self.position;
        self.avancer();

        // ── DEUX CHEMINS IMPOSSIBLES, ET ILS NE SONT PAS DES ERREURS ────────
        //
        // `debut <= fin <= octets.len()` par construction — `position` ne fait
        // qu'avancer, et la boucle ci-dessus s'arrête sur un octet qui existe.
        // Et chaque octet de la tranche a été vérifié ASCII imprimable.
        //
        // Une variante `ok_or(...)?` aurait produit deux branches d'erreur que
        // rien ne peut atteindre : du code mort sur un chemin d'analyse, que
        // personne n'éprouvera jamais et que tout le monde croira éprouvé.
        //
        // Le repli est le vide, et il est SÛR : une chaîne vide fait échouer
        // l'analyseur de nom, d'identifiant ou d'adresse qui la reçoit. Un
        // chemin impossible qui se produirait quand même n'ouvrirait donc rien.
        let tranche = self.octets.get(debut..fin).unwrap_or(&[]);
        Ok(core::str::from_utf8(tranche).unwrap_or(""))
    }

    /// Lit un entier non signé.
    ///
    /// **Une seule écriture par nombre** : pas de signe, pas de zéro en tête,
    /// pas de fraction, pas d'exposant. C'est la même règle que pour les ports
    /// écrits en texte, et pour la même raison.
    ///
    /// **Il rend un `u64`, et ce sont les APPELANTS qui bornent.** Un
    /// horodatage d'époque en millisecondes dépasse largement un `u32` ; un port
    /// n'en occupe que seize bits. Un lecteur unique qui rendrait la borne la
    /// plus étroite obligerait à contourner ailleurs.
    fn entier(&mut self) -> Result<u64, Erreur> {
        self.sauter_blancs();
        let debut = self.position;

        let mut valeur: u64 = 0;
        let mut chiffres = 0_usize;
        while let Some(octet) = self.regarder() {
            if !octet.is_ascii_digit() {
                break;
            }
            valeur = valeur
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(octet.wrapping_sub(b'0'))))
                .ok_or(Erreur::NombreHorsBornes { position: debut })?;
            chiffres = chiffres.saturating_add(1);
            self.avancer();
        }

        if chiffres == 0 {
            return Err(Erreur::JsonAttendu {
                position: debut,
                attendu: "un entier",
            });
        }
        // `0` seul est canonique ; `01` et `007` ne le sont pas.
        if chiffres > 1 && self.octets.get(debut) == Some(&b'0') {
            return Err(Erreur::NombreNonCanonique { position: debut });
        }
        // Ce qui suit un entier ne peut être ni une fraction ni un exposant :
        // ce protocole n'a aucun champ qui ait un sens en virgule flottante.
        if matches!(self.regarder(), Some(b'.' | b'e' | b'E')) {
            return Err(Erreur::NombreNonEntier { position: debut });
        }

        Ok(valeur)
    }

    /// Plus rien après le message ?
    ///
    /// **Des octets en trop ne sont jamais anodins** : deux messages collés dans
    /// un tampon, c'est un lecteur qui en voit un et un autre qui en voit deux.
    fn fin(&mut self) -> Result<(), Erreur> {
        self.sauter_blancs();
        if self.position < self.octets.len() {
            return Err(Erreur::DonneesEnTrop {
                position: self.position,
            });
        }
        Ok(())
    }
}

// ── L'écrivain ──────────────────────────────────────────────────────────────

/// Une tranche où l'on écrit, qui compte ce qu'elle refuse.
///
/// `fmt::Write` ne sait rendre qu'une erreur sans détail ; on garde donc le
/// débordement à part, pour distinguer « le tampon est trop petit » de tout le
/// reste.
struct Ecrivain<'a> {
    sortie: &'a mut [u8],
    ecrits: usize,
    deborde: bool,
}

impl<'a> Ecrivain<'a> {
    fn nouveau(sortie: &'a mut [u8]) -> Self {
        Self {
            sortie,
            ecrits: 0,
            deborde: false,
        }
    }

    fn pousser(&mut self, octets: &[u8]) {
        let fin = self.ecrits.saturating_add(octets.len());
        match self.sortie.get_mut(self.ecrits..fin) {
            Some(place) => {
                place.copy_from_slice(octets);
                self.ecrits = fin;
            }
            None => self.deborde = true,
        }
    }

    fn achever(self) -> Result<usize, Erreur> {
        if self.deborde {
            Err(Erreur::TamponTropPetit)
        } else {
            Ok(self.ecrits)
        }
    }
}

impl fmt::Write for Ecrivain<'_> {
    fn write_str(&mut self, texte: &str) -> fmt::Result {
        self.pousser(texte.as_bytes());
        Ok(())
    }
}

// ── Le message d'annonce ────────────────────────────────────────────────────

/// Les champs attendus, dans l'ordre où l'encodeur les écrit.
const CHAMPS: [&str; 4] = ["machine", "service", "points", "adresses_locales"];

impl<'a> Annonce<'a> {
    /// Décode une annonce.
    ///
    /// Les champs peuvent venir **dans n'importe quel ordre** — ce message se
    /// débogue avec `curl`, et exiger un ordre rendrait illisible ce qu'on
    /// gagnerait en simplicité. En revanche, **aucun doublon et aucun inconnu**
    /// (voir le module).
    ///
    /// `adresses_locales` est le seul champ facultatif : son absence vaut liste
    /// vide.
    ///
    /// # Erreurs
    ///
    /// Toutes celles du cadrage, plus celles de [`Annonce::nouvelle`] — la
    /// validation est faite ici aussi, et c'est ce qui garantit qu'une annonce
    /// décodée est une annonce valide.
    pub fn decoder(octets: &'a [u8], tampons: &'a mut Tampons) -> Result<Self, Erreur> {
        if octets.len() > MESSAGE_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }

        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut vus = 0_u8;
        let mut machine: Option<Identifiant> = None;
        let mut service: Option<NomService<'a>> = None;
        let mut nombre_points = 0_usize;
        let mut nombre_adresses = 0_usize;

        lecteur.sauter_blancs();
        if lecteur.regarder() != Some(b'}') {
            loop {
                let position_cle = lecteur.position;
                let cle = lecteur.chaine()?;
                let rang =
                    CHAMPS
                        .iter()
                        .position(|champ| *champ == cle)
                        .ok_or(Erreur::ChampInconnu {
                            position: position_cle,
                        })?;

                // Un champ en double : deux analyseurs qui ne choisiraient pas
                // le même gagnant liraient deux messages dans les mêmes octets.
                let bit = 1_u8 << rang;
                if vus & bit != 0 {
                    return Err(Erreur::ChampEnDouble {
                        position: position_cle,
                    });
                }
                vus |= bit;

                lecteur.attendre(b':', "deux-points")?;

                match rang {
                    0 => {
                        let position = lecteur.position;
                        let texte = lecteur.chaine()?;
                        machine = Some(
                            Identifiant::analyser_genre(Genre::Machine, texte)
                                .map_err(|_| Erreur::IdentifiantInvalide { position })?,
                        );
                    }
                    1 => service = Some(NomService::analyser(lecteur.chaine()?)?),
                    2 => nombre_points = decoder_points(&mut lecteur, &mut tampons.points)?,
                    _ => nombre_adresses = decoder_adresses(&mut lecteur, &mut tampons.adresses)?,
                }

                // L'ACCOLADE SE CONSOMME ICI, là où on la voit. Un
                // `attendre(b'}')` après la boucle aurait été une vérification
                // qui ne peut pas échouer — on n'y arrive qu'en ayant lu une
                // accolade —, donc une branche d'erreur inatteignable de plus.
                lecteur.sauter_blancs();
                match lecteur.regarder() {
                    Some(b',') => lecteur.avancer(),
                    Some(b'}') => {
                        lecteur.avancer();
                        break;
                    }
                    _ => {
                        return Err(Erreur::JsonAttendu {
                            position: lecteur.position,
                            attendu: "une virgule ou la fin de l'objet",
                        });
                    }
                }
            }
        } else {
            lecteur.avancer();
        }

        lecteur.fin()?;

        let machine = machine.ok_or(Erreur::ChampManquant { nom: CHAMPS[0] })?;
        let service = service.ok_or(Erreur::ChampManquant { nom: CHAMPS[1] })?;
        if vus & 0b100 == 0 {
            return Err(Erreur::ChampManquant { nom: CHAMPS[2] });
        }

        // Les deux comptes sont bornés par la taille des tampons, vérifiée
        // AVANT chaque écriture. Le repli est le vide, et il est sûr : une
        // liste de points vide fait échouer la validation sur `AucunPoint`.
        let points = tampons.points.get(..nombre_points).unwrap_or(&[]);
        let adresses = tampons.adresses.get(..nombre_adresses).unwrap_or(&[]);

        Self::nouvelle(machine, service, points, adresses)
    }

    /// Encode une annonce dans la tranche fournie, et rend le nombre d'octets
    /// écrits.
    ///
    /// **L'écriture est canonique** : champs dans l'ordre de [`CHAMPS`], aucun
    /// blanc superflu, aucun échappement. Deux annonces égales s'écrivent donc
    /// de la même façon, ce qui rend un journal comparable à lui-même.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`] si la tranche ne suffit pas.
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        use fmt::Write as _;

        let mut ecrivain = Ecrivain::nouveau(sortie);
        // `write!` sur cet écrivain ne peut pas échouer : le débordement est
        // retenu à part et rendu par `achever`.
        let _ = write!(
            ecrivain,
            "{{\"machine\":\"{}\",\"service\":\"{}\",\"points\":[",
            self.machine.texte(),
            self.service
        );
        for (rang, point) in self.points.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            let _ = write!(
                ecrivain,
                "{{\"protocole\":\"{}\",\"port\":{}}}",
                point.protocole,
                point.port.valeur()
            );
        }
        ecrivain.pousser(b"],\"adresses_locales\":[");
        for (rang, adresse) in self.adresses_locales.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            let _ = write!(ecrivain, "\"{adresse}\"");
        }
        ecrivain.pousser(b"]}");

        ecrivain.achever()
    }
}

/// Décode le tableau des points d'écoute.
fn decoder_points(lecteur: &mut Lecteur<'_>, sortie: &mut [PointEcoute]) -> Result<usize, Erreur> {
    lecteur.attendre(b'[', "un tableau")?;
    let mut compte = 0_usize;

    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b']') {
        lecteur.avancer();
        return Ok(0);
    }

    loop {
        lecteur.attendre(b'{', "un objet")?;

        let mut protocole: Option<Protocole> = None;
        let mut port: Option<Port> = None;

        loop {
            let position_cle = lecteur.position;
            let cle = lecteur.chaine()?;
            lecteur.attendre(b':', "deux-points")?;
            match cle {
                "protocole" if protocole.is_none() => {
                    protocole = Some(Protocole::analyser(lecteur.chaine()?)?);
                }
                "port" if port.is_none() => {
                    let position = lecteur.position;
                    let brut = lecteur.entier()?;
                    let borne =
                        u16::try_from(brut).map_err(|_| Erreur::NombreHorsBornes { position })?;
                    port = Some(Port::depuis_u16(borne)?);
                }
                "protocole" | "port" => {
                    return Err(Erreur::ChampEnDouble {
                        position: position_cle,
                    });
                }
                _ => {
                    return Err(Erreur::ChampInconnu {
                        position: position_cle,
                    });
                }
            }

            lecteur.sauter_blancs();
            match lecteur.regarder() {
                Some(b',') => lecteur.avancer(),
                Some(b'}') => {
                    lecteur.avancer();
                    break;
                }
                _ => {
                    return Err(Erreur::JsonAttendu {
                        position: lecteur.position,
                        attendu: "une virgule ou la fin de l'objet",
                    });
                }
            }
        }

        let protocole = protocole.ok_or(Erreur::ChampManquant { nom: "protocole" })?;
        let port = port.ok_or(Erreur::ChampManquant { nom: "port" })?;

        // LA BORNE EST VÉRIFIÉE AVANT D'ÉCRIRE, jamais après : c'est ce qui fait
        // qu'un tableau de mille éléments ne coûte pas mille écritures.
        let place = sortie.get_mut(compte).ok_or(Erreur::TropDePoints {
            obtenu: compte.saturating_add(1),
        })?;
        *place = PointEcoute::nouveau(protocole, port);
        compte = compte.saturating_add(1);

        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b']') => {
                lecteur.avancer();
                break;
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position,
                    attendu: "une virgule ou la fin du tableau",
                });
            }
        }
    }

    Ok(compte)
}

/// Décode le tableau des adresses locales.
fn decoder_adresses(lecteur: &mut Lecteur<'_>, sortie: &mut [IpAddr]) -> Result<usize, Erreur> {
    lecteur.attendre(b'[', "un tableau")?;
    let mut compte = 0_usize;

    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b']') {
        lecteur.avancer();
        return Ok(0);
    }

    loop {
        let position = lecteur.position;
        let texte = lecteur.chaine()?;
        let adresse: IpAddr = texte
            .parse()
            .map_err(|_| Erreur::AdresseInvalide { position })?;

        let place = sortie.get_mut(compte).ok_or(Erreur::TropDAdresses {
            obtenu: compte.saturating_add(1),
        })?;
        *place = adresse;
        compte = compte.saturating_add(1);

        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b']') => {
                lecteur.avancer();
                break;
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position,
                    attendu: "une virgule ou la fin du tableau",
                });
            }
        }
    }

    Ok(compte)
}

// ── Le message de réponse ───────────────────────────────────────────────────

/// Les champs de la réponse, dans l'ordre où l'encodeur les écrit.
const CHAMPS_REPONSE: [&str; 5] = [
    "service",
    "keepalive_secondes",
    "inactivite_secondes",
    "vu_depuis",
    "joignabilite",
];

/// Les tampons que l'appelant prête au décodeur de réponse.
#[derive(Debug, Clone, Copy)]
pub struct TamponsReponse {
    joignabilite: [Joignabilite; POINTS_MAX],
}

impl TamponsReponse {
    /// Des tampons neufs.
    #[must_use]
    pub const fn nouveaux() -> Self {
        Self {
            joignabilite: [Joignabilite {
                point: PointEcoute::nouveau(Protocole::Tcp, Port::UN),
                verdict: Verdict::EnCours,
            }; POINTS_MAX],
        }
    }
}

impl Default for TamponsReponse {
    fn default() -> Self {
        Self::nouveaux()
    }
}

impl<'a> Reponse<'a> {
    /// Décode une réponse.
    ///
    /// Les mêmes trois refus que l'annonce : aucun échappement, aucun champ
    /// inconnu, aucun champ en double.
    ///
    /// **Et un quatrième, propre à ce message : aucun champ HORS DE PROPOS.**
    /// Une date sur un `en_cours`, un candidat sur un `non_sonde` — l'émetteur
    /// dit alors quelque chose que le verdict ne peut pas porter, et le lire
    /// « au mieux » reviendrait à décider à sa place.
    ///
    /// # Erreurs
    ///
    /// Celles du cadrage, plus celles de [`Reponse::nouvelle`].
    pub fn decoder(octets: &'a [u8], tampons: &'a mut TamponsReponse) -> Result<Self, Erreur> {
        if octets.len() > MESSAGE_MAX {
            return Err(Erreur::MessageTropLong {
                obtenue: octets.len(),
            });
        }

        let mut lecteur = Lecteur::nouveau(octets);
        lecteur.attendre(b'{', "un objet")?;

        let mut vus = 0_u8;
        let mut service: Option<Identifiant> = None;
        let mut keepalive: Option<u16> = None;
        let mut inactivite: Option<u16> = None;
        let mut vu_depuis: Option<VuDepuis> = None;
        let mut derriere_nat: Option<VerdictNat> = None;
        let mut compte = 0_usize;

        lecteur.sauter_blancs();
        if lecteur.regarder() != Some(b'}') {
            loop {
                let position_cle = lecteur.position;
                let cle = lecteur.chaine()?;
                let rang = if cle == "derriere_nat" {
                    // Rang 5 : il n'est pas dans `CHAMPS_REPONSE`, dont l'ordre
                    // sert l'écriture, mais il compte pour les doublons.
                    5
                } else {
                    CHAMPS_REPONSE
                        .iter()
                        .position(|champ| *champ == cle)
                        .ok_or(Erreur::ChampInconnu {
                            position: position_cle,
                        })?
                };

                let bit = 1_u8 << rang;
                if vus & bit != 0 {
                    return Err(Erreur::ChampEnDouble {
                        position: position_cle,
                    });
                }
                vus |= bit;

                lecteur.attendre(b':', "deux-points")?;

                match rang {
                    0 => {
                        let position = lecteur.position;
                        let texte = lecteur.chaine()?;
                        service = Some(
                            Identifiant::analyser_genre(Genre::Service, texte)
                                .map_err(|_| Erreur::IdentifiantInvalide { position })?,
                        );
                    }
                    1 => keepalive = Some(secondes(&mut lecteur)?),
                    2 => inactivite = Some(secondes(&mut lecteur)?),
                    3 => vu_depuis = Some(decoder_vu_depuis(&mut lecteur)?),
                    4 => {
                        compte = decoder_joignabilite(&mut lecteur, &mut tampons.joignabilite)?;
                    }
                    _ => derriere_nat = Some(VerdictNat::analyser(lecteur.chaine()?)?),
                }

                lecteur.sauter_blancs();
                match lecteur.regarder() {
                    Some(b',') => lecteur.avancer(),
                    Some(b'}') => {
                        lecteur.avancer();
                        break;
                    }
                    _ => {
                        return Err(Erreur::JsonAttendu {
                            position: lecteur.position,
                            attendu: "une virgule ou la fin de l'objet",
                        });
                    }
                }
            }
        } else {
            lecteur.avancer();
        }
        lecteur.fin()?;

        let service = service.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_REPONSE[0],
        })?;
        let keepalive = keepalive.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_REPONSE[1],
        })?;
        let inactivite = inactivite.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_REPONSE[2],
        })?;
        let vu_depuis = vu_depuis.ok_or(Erreur::ChampManquant {
            nom: CHAMPS_REPONSE[3],
        })?;
        if vus & 0b1_0000 == 0 {
            return Err(Erreur::ChampManquant {
                nom: CHAMPS_REPONSE[4],
            });
        }
        let derriere_nat = derriere_nat.ok_or(Erreur::ChampManquant {
            nom: "derriere_nat",
        })?;

        let bail = Bail::nouveau(keepalive, inactivite)?;
        let joignabilite = tampons.joignabilite.get(..compte).unwrap_or(&[]);

        Self::nouvelle(service, bail, vu_depuis, derriere_nat, joignabilite)
    }

    /// Encode une réponse, et rend le nombre d'octets écrits.
    ///
    /// **Chaque verdict n'écrit QUE les champs qu'il porte** : le décodeur
    /// refusant les champs hors de propos, écrire une date sur un `en_cours`
    /// produirait un message que nous-mêmes ne saurions pas relire.
    ///
    /// # Erreurs
    ///
    /// [`Erreur::TamponTropPetit`].
    pub fn encoder(&self, sortie: &mut [u8]) -> Result<usize, Erreur> {
        use fmt::Write as _;

        let mut ecrivain = Ecrivain::nouveau(sortie);
        let _ = write!(
            ecrivain,
            "{{\"service\":\"{}\",\"keepalive_secondes\":{},\"inactivite_secondes\":{},\
             \"vu_depuis\":{{\"adresse\":\"{}\",\"port\":{}}},\"derriere_nat\":\"{}\",\
             \"joignabilite\":[",
            self.service.texte(),
            self.bail.keepalive_secondes(),
            self.bail.inactivite_secondes(),
            self.vu_depuis.adresse,
            self.vu_depuis.port.valeur(),
            self.derriere_nat,
        );

        for (rang, entree) in self.joignabilite.iter().enumerate() {
            if rang > 0 {
                ecrivain.pousser(b",");
            }
            let _ = write!(
                ecrivain,
                "{{\"protocole\":\"{}\",\"port\":{},\"verdict\":\"{}\"",
                entree.point.protocole,
                entree.point.port.valeur(),
                entree.verdict.texte(),
            );
            match entree.verdict {
                Verdict::Joignable { candidat, a } => {
                    let _ = write!(
                        ecrivain,
                        ",\"candidat\":\"{candidat}\",\"origine\":\"{}\",\"a\":{a}",
                        candidat.origine
                    );
                }
                Verdict::Injoignable { a } => {
                    let _ = write!(ecrivain, ",\"a\":{a}");
                }
                Verdict::NonSonde { raison } => {
                    let _ = write!(ecrivain, ",\"raison\":\"{raison}\"");
                }
                Verdict::EnCours => {}
            }
            ecrivain.pousser(b"}");
        }
        ecrivain.pousser(b"]}");

        ecrivain.achever()
    }
}

/// Lit un nombre de secondes, borné à `u16`.
fn secondes(lecteur: &mut Lecteur<'_>) -> Result<u16, Erreur> {
    let position = lecteur.position;
    let brut = lecteur.entier()?;
    u16::try_from(brut).map_err(|_| Erreur::NombreHorsBornes { position })
}

/// Décode l'objet `vu_depuis`.
fn decoder_vu_depuis(lecteur: &mut Lecteur<'_>) -> Result<VuDepuis, Erreur> {
    lecteur.attendre(b'{', "un objet")?;

    let mut adresse: Option<IpAddr> = None;
    let mut port: Option<Port> = None;

    loop {
        let position_cle = lecteur.position;
        let cle = lecteur.chaine()?;
        lecteur.attendre(b':', "deux-points")?;
        match cle {
            "adresse" if adresse.is_none() => {
                let position = lecteur.position;
                adresse = Some(
                    lecteur
                        .chaine()?
                        .parse()
                        .map_err(|_| Erreur::AdresseInvalide { position })?,
                );
            }
            "port" if port.is_none() => {
                let position = lecteur.position;
                let brut = lecteur.entier()?;
                let borne =
                    u16::try_from(brut).map_err(|_| Erreur::NombreHorsBornes { position })?;
                port = Some(Port::depuis_u16(borne)?);
            }
            "adresse" | "port" => {
                return Err(Erreur::ChampEnDouble {
                    position: position_cle,
                });
            }
            _ => {
                return Err(Erreur::ChampInconnu {
                    position: position_cle,
                });
            }
        }

        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b'}') => {
                lecteur.avancer();
                break;
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position,
                    attendu: "une virgule ou la fin de l'objet",
                });
            }
        }
    }

    Ok(VuDepuis {
        adresse: adresse.ok_or(Erreur::ChampManquant { nom: "adresse" })?,
        port: port.ok_or(Erreur::ChampManquant { nom: "port" })?,
    })
}

/// Décode le tableau des verdicts.
fn decoder_joignabilite(
    lecteur: &mut Lecteur<'_>,
    sortie: &mut [Joignabilite],
) -> Result<usize, Erreur> {
    lecteur.attendre(b'[', "un tableau")?;
    let mut compte = 0_usize;

    lecteur.sauter_blancs();
    if lecteur.regarder() == Some(b']') {
        lecteur.avancer();
        return Ok(0);
    }

    loop {
        let entree = decoder_un_verdict(lecteur)?;

        let place = sortie.get_mut(compte).ok_or(Erreur::TropDeJoignabilites {
            obtenu: compte.saturating_add(1),
        })?;
        *place = entree;
        compte = compte.saturating_add(1);

        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b']') => {
                lecteur.avancer();
                break;
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position,
                    attendu: "une virgule ou la fin du tableau",
                });
            }
        }
    }

    Ok(compte)
}

/// Décode un objet de verdict.
///
/// **Les champs sont lus d'abord, le verdict assemblé ensuite**, parce que
/// `verdict` peut arriver après `a` ou `candidat`. C'est l'assemblage qui refuse
/// les champs hors de propos — au moment où l'on sait de quel verdict il s'agit.
fn decoder_un_verdict(lecteur: &mut Lecteur<'_>) -> Result<Joignabilite, Erreur> {
    lecteur.attendre(b'{', "un objet")?;

    let mut protocole: Option<Protocole> = None;
    let mut port: Option<Port> = None;
    let mut nom_verdict: Option<&str> = None;
    let mut candidat: Option<(core::net::SocketAddr, usize)> = None;
    let mut origine: Option<Origine> = None;
    let mut instant: Option<Horodatage> = None;
    let mut raison: Option<RaisonNonSonde> = None;
    let mut position_candidat = 0_usize;
    let mut position_origine = 0_usize;
    let mut position_a = 0_usize;
    let mut position_raison = 0_usize;

    loop {
        let position_cle = lecteur.position;
        let cle = lecteur.chaine()?;
        lecteur.attendre(b':', "deux-points")?;

        let deja = match cle {
            "protocole" => protocole.is_some(),
            "port" => port.is_some(),
            "verdict" => nom_verdict.is_some(),
            "candidat" => candidat.is_some(),
            "origine" => origine.is_some(),
            "a" => instant.is_some(),
            "raison" => raison.is_some(),
            _ => {
                return Err(Erreur::ChampInconnu {
                    position: position_cle,
                });
            }
        };
        if deja {
            return Err(Erreur::ChampEnDouble {
                position: position_cle,
            });
        }

        match cle {
            "protocole" => protocole = Some(Protocole::analyser(lecteur.chaine()?)?),
            "port" => {
                let position = lecteur.position;
                let brut = lecteur.entier()?;
                let borne =
                    u16::try_from(brut).map_err(|_| Erreur::NombreHorsBornes { position })?;
                port = Some(Port::depuis_u16(borne)?);
            }
            "verdict" => nom_verdict = Some(lecteur.chaine()?),
            "candidat" => {
                position_candidat = position_cle;
                let position = lecteur.position;
                let adresse: core::net::SocketAddr = lecteur
                    .chaine()?
                    .parse()
                    .map_err(|_| Erreur::CandidatInvalide { position })?;
                candidat = Some((adresse, position));
            }
            "origine" => {
                position_origine = position_cle;
                origine = Some(Origine::analyser(lecteur.chaine()?)?);
            }
            "a" => {
                position_a = position_cle;
                instant = Some(Horodatage::depuis_millisecondes(lecteur.entier()?));
            }
            _ => {
                position_raison = position_cle;
                raison = Some(RaisonNonSonde::analyser(lecteur.chaine()?)?);
            }
        }

        lecteur.sauter_blancs();
        match lecteur.regarder() {
            Some(b',') => lecteur.avancer(),
            Some(b'}') => {
                lecteur.avancer();
                break;
            }
            _ => {
                return Err(Erreur::JsonAttendu {
                    position: lecteur.position,
                    attendu: "une virgule ou la fin de l'objet",
                });
            }
        }
    }

    let protocole = protocole.ok_or(Erreur::ChampManquant { nom: "protocole" })?;
    let port = port.ok_or(Erreur::ChampManquant { nom: "port" })?;
    let nom_verdict = nom_verdict.ok_or(Erreur::ChampManquant { nom: "verdict" })?;

    // ── L'ASSEMBLAGE, ET C'EST LUI QUI REFUSE LE HORS-PROPOS ────────────────
    //
    // Chaque verdict exige exactement ses champs, et n'en tolère aucun autre.
    let verdict = match nom_verdict {
        "joignable" => {
            let (adresse, _) = candidat.ok_or(Erreur::ChampManquant { nom: "candidat" })?;
            let origine = origine.ok_or(Erreur::ChampManquant { nom: "origine" })?;
            let a = instant.ok_or(Erreur::ChampManquant { nom: "a" })?;
            if raison.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_raison,
                });
            }
            Verdict::Joignable {
                candidat: Candidat {
                    protocole,
                    adresse: adresse.ip(),
                    port: Port::depuis_u16(adresse.port())?,
                    origine,
                },
                a,
            }
        }
        "injoignable" => {
            let a = instant.ok_or(Erreur::ChampManquant { nom: "a" })?;
            if candidat.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_candidat,
                });
            }
            if origine.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_origine,
                });
            }
            if raison.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_raison,
                });
            }
            Verdict::Injoignable { a }
        }
        "non_sonde" => {
            let raison = raison.ok_or(Erreur::ChampManquant { nom: "raison" })?;
            if candidat.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_candidat,
                });
            }
            if origine.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_origine,
                });
            }
            if instant.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_a,
                });
            }
            Verdict::NonSonde { raison }
        }
        "en_cours" => {
            if candidat.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_candidat,
                });
            }
            if origine.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_origine,
                });
            }
            if instant.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_a,
                });
            }
            if raison.is_some() {
                return Err(Erreur::ChampHorsPropos {
                    position: position_raison,
                });
            }
            Verdict::EnCours
        }
        _ => return Err(Erreur::VerdictInconnu),
    };

    Ok(Joignabilite {
        point: PointEcoute::nouveau(protocole, port),
        verdict,
    })
}
