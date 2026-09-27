//! Ce que la voie de l'annuaire local porte (`docs/protocole.md` §3 ter ;
//! `docs/replication.md` décision 52).
//!
//! # DEUX SENS, DEUX FORMES — ET AUCUN SECOND FORMAT D'ENREGISTREMENT
//!
//! **Descendant** — les racines rendent à l'annuaire local les machines
//! rattachées aux domaines qu'il héberge. Chacune voyage comme
//! [`MachineFederee`] : son identifiant, puis **l'enregistrement [`Machine`]
//! tel que l'entrepôt le range**. L'annuaire local en tire la clé qui
//! authentifie un daemon, et ses capacités ; il n'a pas de second décodeur à
//! tenir, et un champ ajouté demain à la machine voyagera sans qu'on touche à
//! ce module. La taille est fixe : aucune longueur ne vient du réseau.
//!
//! **Montant** — l'annuaire local rend aux racines l'état de ses services,
//! une [`EntreeDEtat`] par service : l'identifiant du service, sa machine, son
//! nom, et **sa réponse d'annonce quand il est vivant** — l'objet
//! `asl_proto::Reponse` déjà encodé, celui qu'une racine rend à
//! `GET /v1/ou` pour un service qu'elle voit elle-même. L'adresse de la
//! machine et le port de connexion y sont (les candidats), avec ce que
//! l'annuaire local en a mesuré ; les racines le rendent VERBATIM, comme
//! `GET /v1/machines/{m}/services` réémet déjà la réponse sous `annonce`. Un
//! second objet pour dire la même chose aurait été un second contrat.
//!
//! # LA SEULE LONGUEUR QUI VIENT DU FIL, ET SA BORNE
//!
//! La réponse d'annonce a une taille variable. Elle est précédée de deux
//! octets gros-boutistes, et **bornée par [`REPONSE_FEDEREE_OCTETS_MAX`]** —
//! la même borne que le message d'annonce lui-même
//! (`asl_proto::cadrage::MESSAGE_MAX`, que l'étage 3 compare à celle-ci).
//! Une longueur au-delà est refusée avant de lire un octet de plus.

use asl_id::{Genre, Identifiant};

use crate::{
    Faute, IDENTIFIANT_OCTETS, MACHINE_OCTETS, Machine, NOM_OCTETS_MAX, NomRange,
    ecrire_identifiant, lire_identifiant, poser, poser_un,
};

// ── Descendant : les machines ───────────────────────────────────────────────

/// Ce qu'une machine fédérée occupe : son identifiant, puis son enregistrement.
pub const MACHINE_FEDEREE_OCTETS: usize = IDENTIFIANT_OCTETS + MACHINE_OCTETS;

/// Une machine rattachée à un domaine que l'annuaire local héberge, telle que
/// les racines la lui transmettent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineFederee {
    /// Son identifiant.
    pub machine: Identifiant,
    /// Son enregistrement, tel que l'entrepôt des racines le range.
    pub enregistrement: Machine,
}

impl MachineFederee {
    /// L'écrit.
    pub fn ecrire(&self, sortie: &mut [u8; MACHINE_FEDEREE_OCTETS]) {
        ecrire_identifiant(
            self.machine,
            sortie.get_mut(..IDENTIFIANT_OCTETS).unwrap_or_default(),
        );
        let mut enregistrement = [0_u8; MACHINE_OCTETS];
        self.enregistrement.ecrire(&mut enregistrement);
        poser(
            sortie.get_mut(IDENTIFIANT_OCTETS..).unwrap_or_default(),
            &enregistrement,
        );
    }

    /// La relit.
    ///
    /// # Errors
    ///
    /// [`Faute`] si l'identifiant n'est pas celui d'une machine, ou si
    /// l'enregistrement ne se lit pas.
    pub fn lire(octets: &[u8; MACHINE_FEDEREE_OCTETS]) -> Result<Self, Faute> {
        let machine = lire_identifiant(
            octets.get(..IDENTIFIANT_OCTETS).unwrap_or_default(),
            Genre::Machine,
        )?;
        let mut enregistrement = [0_u8; MACHINE_OCTETS];
        poser(
            &mut enregistrement,
            octets.get(IDENTIFIANT_OCTETS..).unwrap_or_default(),
        );
        Ok(Self {
            machine,
            enregistrement: Machine::lire(&enregistrement)?,
        })
    }
}

// ── Montant : l'état des services ───────────────────────────────────────────

/// La plus longue réponse d'annonce qu'une entrée d'état peut porter.
///
/// **C'est `asl_proto::cadrage::MESSAGE_MAX`**, la borne du message d'annonce
/// que l'annuaire local a reçu, et dont cette réponse est l'écho : ce module
/// ne tire pas `asl-proto`, et l'étage 3 tient l'égalité.
pub const REPONSE_FEDEREE_OCTETS_MAX: usize = 4_096;

/// Ce qu'une entrée occupe au moins : service, machine, la longueur du nom,
/// le drapeau de vie.
pub const ENTREE_D_ETAT_OCTETS_MIN: usize = IDENTIFIANT_OCTETS + IDENTIFIANT_OCTETS + 1 + 1;

/// Ce qu'une entrée occupe au plus.
pub const ENTREE_D_ETAT_OCTETS_MAX: usize =
    ENTREE_D_ETAT_OCTETS_MIN + NOM_OCTETS_MAX + 2 + REPONSE_FEDEREE_OCTETS_MAX;

/// Le drapeau d'un service qu'aucun daemon ne tient en ce moment.
const PARTI: u8 = 0;

/// Le drapeau d'un service vivant — sa réponse suit.
const VIVANT: u8 = 1;

/// L'état d'un service, tel que l'annuaire local le rapporte à une racine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntreeDEtat<'a> {
    /// Le service, tel que l'annuaire local l'a déclaré.
    pub service: Identifiant,
    /// Sa machine.
    pub machine: Identifiant,
    /// Son nom.
    pub nom: NomRange,
    /// Sa réponse d'annonce, s'il est vivant ; rien s'il est parti.
    pub reponse: Option<&'a [u8]>,
}

impl<'a> EntreeDEtat<'a> {
    /// Ce qu'elle occupe écrite.
    #[must_use]
    pub fn octets(&self) -> usize {
        ENTREE_D_ETAT_OCTETS_MIN
            .saturating_add(self.nom.longueur())
            .saturating_add(
                self.reponse
                    .map_or(0, |reponse| reponse.len().saturating_add(2)),
            )
    }

    /// L'écrit au début de `sortie`, et rend ce qu'elle occupe.
    ///
    /// # Errors
    ///
    /// [`Faute::Longueur`] pour une réponse au-delà de
    /// [`REPONSE_FEDEREE_OCTETS_MAX`], ou une sortie trop courte.
    pub fn ecrire(&self, sortie: &mut [u8]) -> Result<usize, Faute> {
        if let Some(reponse) = self.reponse
            && reponse.len() > REPONSE_FEDEREE_OCTETS_MAX
        {
            return Err(Faute::Longueur {
                annoncee: reponse.len(),
                maximum: REPONSE_FEDEREE_OCTETS_MAX,
            });
        }
        let total = self.octets();
        if sortie.len() < total {
            return Err(Faute::Longueur {
                annoncee: total,
                maximum: sortie.len(),
            });
        }
        let mut curseur = 0_usize;
        let mut tranche = |combien: usize| {
            let debut = curseur;
            curseur = curseur.saturating_add(combien);
            debut..curseur
        };
        ecrire_identifiant(
            self.service,
            sortie
                .get_mut(tranche(IDENTIFIANT_OCTETS))
                .unwrap_or_default(),
        );
        ecrire_identifiant(
            self.machine,
            sortie
                .get_mut(tranche(IDENTIFIANT_OCTETS))
                .unwrap_or_default(),
        );
        // La longueur du nom tient sur un octet : NOM_OCTETS_MAX vaut 64.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "le nom est borné par NOM_OCTETS_MAX, soixante-quatre"
        )]
        poser_un(
            sortie.get_mut(tranche(1)).unwrap_or_default(),
            self.nom.longueur() as u8,
        );
        poser(
            sortie
                .get_mut(tranche(self.nom.longueur()))
                .unwrap_or_default(),
            self.nom.octets(),
        );
        match self.reponse {
            None => poser_un(sortie.get_mut(tranche(1)).unwrap_or_default(), PARTI),
            Some(reponse) => {
                poser_un(sortie.get_mut(tranche(1)).unwrap_or_default(), VIVANT);
                // Bornée ci-dessus par REPONSE_FEDEREE_OCTETS_MAX : elle tient
                // sur deux octets.
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "la réponse est bornée par REPONSE_FEDEREE_OCTETS_MAX"
                )]
                let longueur = (reponse.len() as u16).to_be_bytes();
                poser(sortie.get_mut(tranche(2)).unwrap_or_default(), &longueur);
                poser(
                    sortie.get_mut(tranche(reponse.len())).unwrap_or_default(),
                    reponse,
                );
            }
        }
        Ok(total)
    }

    /// Lit une entrée au début de `octets`, et rend ce qu'elle occupe.
    ///
    /// # Errors
    ///
    /// [`Faute::Tronquee`] si les octets s'arrêtent avant la fin de l'entrée ;
    /// [`Faute::Genre`] pour un identifiant d'un autre genre ;
    /// [`Faute::Longueur`] pour un nom ou une réponse au-delà de leur borne ;
    /// [`Faute::Vide`] pour un nom vide ; [`Faute::Etiquette`] pour un
    /// drapeau de vie inconnu.
    pub fn lire(octets: &'a [u8]) -> Result<(Self, usize), Faute> {
        let exiger = |jusqua: usize| {
            if octets.len() < jusqua {
                Err(Faute::Tronquee {
                    attendus: jusqua,
                    obtenus: octets.len(),
                })
            } else {
                Ok(())
            }
        };
        exiger(ENTREE_D_ETAT_OCTETS_MIN)?;
        let service = lire_identifiant(
            octets.get(..IDENTIFIANT_OCTETS).unwrap_or_default(),
            Genre::Service,
        )?;
        let deux = IDENTIFIANT_OCTETS.saturating_mul(2);
        let machine = lire_identifiant(
            octets.get(IDENTIFIANT_OCTETS..deux).unwrap_or_default(),
            Genre::Machine,
        )?;
        let longueur_du_nom = usize::from(octets.get(deux).copied().unwrap_or(0));
        if longueur_du_nom == 0 {
            return Err(Faute::Vide);
        }
        let debut_du_nom = deux.saturating_add(1);
        let fin_du_nom = debut_du_nom.saturating_add(longueur_du_nom);
        // Le nom, puis le drapeau.
        exiger(fin_du_nom.saturating_add(1))?;
        let nom = core::str::from_utf8(octets.get(debut_du_nom..fin_du_nom).unwrap_or_default())
            .map_err(|_| Faute::NonNormalise)?;
        // La borne du nom : c'est `NomRange::nouveau` qui la tient.
        let nom = NomRange::nouveau(nom)?;
        match octets.get(fin_du_nom).copied().unwrap_or(0) {
            PARTI => Ok((
                Self {
                    service,
                    machine,
                    nom,
                    reponse: None,
                },
                fin_du_nom.saturating_add(1),
            )),
            VIVANT => {
                let debut_longueur = fin_du_nom.saturating_add(1);
                let debut_reponse = debut_longueur.saturating_add(2);
                exiger(debut_reponse)?;
                let mut deux_octets = [0_u8; 2];
                poser(
                    &mut deux_octets,
                    octets
                        .get(debut_longueur..debut_reponse)
                        .unwrap_or_default(),
                );
                let longueur = usize::from(u16::from_be_bytes(deux_octets));
                if longueur > REPONSE_FEDEREE_OCTETS_MAX {
                    return Err(Faute::Longueur {
                        annoncee: longueur,
                        maximum: REPONSE_FEDEREE_OCTETS_MAX,
                    });
                }
                let fin = debut_reponse.saturating_add(longueur);
                exiger(fin)?;
                Ok((
                    Self {
                        service,
                        machine,
                        nom,
                        reponse: Some(octets.get(debut_reponse..fin).unwrap_or_default()),
                    },
                    fin,
                ))
            }
            lue => Err(Faute::Etiquette { lue }),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{CleLiee, Estampille, Provenance};

    fn id(genre: Genre, octet: u8) -> Identifiant {
        Identifiant::depuis_entropie(genre, [octet; 16])
    }

    fn estampille(compteur: u64) -> Estampille {
        Estampille {
            compteur,
            racine: id(Genre::Annuaire, 9),
        }
    }

    fn machine() -> Machine {
        Machine {
            provenance: Provenance::Ici,
            estampille: estampille(3),
            proprietaire: id(Genre::Utilisateur, 1),
            cle: Some(CleLiee {
                cle: [7; 32],
                liaison: estampille(4),
                code: estampille(2),
            }),
            annonce: true,
            lecture: false,
            capacites_estampille: estampille(3),
            nom: NomRange::nouveau("grenier").expect("il tient"),
            nom_estampille: estampille(3),
        }
    }

    #[test]
    fn une_machine_federee_fait_l_aller_retour() {
        let federee = MachineFederee {
            machine: id(Genre::Machine, 5),
            enregistrement: machine(),
        };
        let mut octets = [0_u8; MACHINE_FEDEREE_OCTETS];
        federee.ecrire(&mut octets);
        assert_eq!(MachineFederee::lire(&octets), Ok(federee));
    }

    #[test]
    fn une_machine_federee_exige_son_genre_et_un_enregistrement_lisible() {
        let federee = MachineFederee {
            machine: id(Genre::Machine, 5),
            enregistrement: machine(),
        };
        let mut octets = [0_u8; MACHINE_FEDEREE_OCTETS];
        federee.ecrire(&mut octets);
        let mut autre = octets;
        autre[0] = Genre::Service.prefixe();
        assert_eq!(
            MachineFederee::lire(&autre),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );
        let mut illisible = octets;
        // La provenance : une étiquette qui n'en est pas une.
        illisible[IDENTIFIANT_OCTETS] = 9;
        assert!(MachineFederee::lire(&illisible).is_err());
    }

    fn entree(reponse: Option<&[u8]>) -> EntreeDEtat<'_> {
        EntreeDEtat {
            service: id(Genre::Service, 2),
            machine: id(Genre::Machine, 5),
            nom: NomRange::nouveau("depot").expect("il tient"),
            reponse,
        }
    }

    #[test]
    fn une_entree_vivante_et_une_partie_font_l_aller_retour() {
        let reponse = br#"{"service":"s-x"}"#;
        for voulue in [entree(None), entree(Some(reponse.as_slice()))] {
            let mut sortie = [0_u8; 256];
            let ecrit = voulue.ecrire(&mut sortie);
            assert_eq!(ecrit, Ok(voulue.octets()));
            let lue = EntreeDEtat::lire(sortie.get(..voulue.octets()).unwrap_or_default());
            assert_eq!(lue, Ok((voulue, voulue.octets())));
        }
    }

    #[test]
    fn deux_entrees_se_suivent_sans_enveloppe() {
        let reponse = b"{}";
        let premiere = entree(Some(reponse.as_slice()));
        let seconde = entree(None);
        let mut sortie = [0_u8; 256];
        let a = premiere.ecrire(&mut sortie).unwrap_or_default();
        let b = seconde
            .ecrire(sortie.get_mut(a..).unwrap_or_default())
            .unwrap_or_default();
        let (lue, occupe) = EntreeDEtat::lire(sortie.get(..a + b).unwrap_or_default())
            .expect("deux entrées se lisent");
        assert_eq!((lue, occupe), (premiere, a));
        assert_eq!(
            EntreeDEtat::lire(sortie.get(a..a + b).unwrap_or_default()),
            Ok((seconde, b))
        );
    }

    #[test]
    fn l_ecriture_refuse_une_reponse_trop_longue_et_une_sortie_trop_courte() {
        let trop = [b'x'; REPONSE_FEDEREE_OCTETS_MAX + 1];
        let mut sortie = [0_u8; ENTREE_D_ETAT_OCTETS_MAX + 8];
        assert_eq!(
            entree(Some(trop.as_slice())).ecrire(&mut sortie),
            Err(Faute::Longueur {
                annoncee: REPONSE_FEDEREE_OCTETS_MAX + 1,
                maximum: REPONSE_FEDEREE_OCTETS_MAX,
            })
        );
        let mut court = [0_u8; 10];
        assert_eq!(
            entree(None).ecrire(&mut court),
            Err(Faute::Longueur {
                annoncee: entree(None).octets(),
                maximum: 10,
            })
        );
        // La plus longue passe, et tient dans la borne annoncée.
        let pleine = [b'x'; REPONSE_FEDEREE_OCTETS_MAX];
        let longue = EntreeDEtat {
            nom: NomRange::nouveau(&"n".repeat(NOM_OCTETS_MAX)).expect("il tient"),
            ..entree(Some(pleine.as_slice()))
        };
        assert_eq!(longue.octets(), ENTREE_D_ETAT_OCTETS_MAX);
        assert_eq!(longue.ecrire(&mut sortie), Ok(ENTREE_D_ETAT_OCTETS_MAX));
    }

    #[test]
    fn la_lecture_refuse_ce_qui_n_est_pas_une_entree() {
        let mut sortie = [0_u8; 64];
        let reponse = b"{}";
        let bonne = entree(Some(reponse.as_slice()));
        let n = bonne.ecrire(&mut sortie).unwrap_or_default();
        let octets = sortie.get(..n).unwrap_or_default();

        // Trop court, à chaque étape.
        assert_eq!(
            EntreeDEtat::lire(octets.get(..10).unwrap_or_default()),
            Err(Faute::Tronquee {
                attendus: ENTREE_D_ETAT_OCTETS_MIN,
                obtenus: 10,
            })
        );
        assert_eq!(
            EntreeDEtat::lire(octets.get(..40).unwrap_or_default()),
            Err(Faute::Tronquee {
                attendus: 41,
                obtenus: 40,
            })
        );
        assert_eq!(
            EntreeDEtat::lire(octets.get(..n - 2).unwrap_or_default()),
            Err(Faute::Tronquee {
                attendus: n,
                obtenus: n - 2,
            })
        );
        let sans_longueur = IDENTIFIANT_OCTETS * 2 + 1 + 5 + 1;
        assert_eq!(
            EntreeDEtat::lire(octets.get(..sans_longueur).unwrap_or_default()),
            Err(Faute::Tronquee {
                attendus: sans_longueur + 2,
                obtenus: sans_longueur,
            })
        );

        // Genres.
        let mut v = octets.to_vec();
        v[0] = Genre::Machine.prefixe();
        assert_eq!(
            EntreeDEtat::lire(&v),
            Err(Faute::Genre {
                attendu: Genre::Service
            })
        );
        let mut v = octets.to_vec();
        v[IDENTIFIANT_OCTETS] = Genre::Service.prefixe();
        assert_eq!(
            EntreeDEtat::lire(&v),
            Err(Faute::Genre {
                attendu: Genre::Machine
            })
        );

        // Le nom : vide, trop long, pas de l'UTF-8.
        let mut v = octets.to_vec();
        v[IDENTIFIANT_OCTETS * 2] = 0;
        assert_eq!(EntreeDEtat::lire(&v), Err(Faute::Vide));
        // Un nom d'un octet de trop, entier : la borne, pas la troncature.
        let mut v = octets
            .get(..IDENTIFIANT_OCTETS * 2)
            .unwrap_or_default()
            .to_vec();
        v.push(65);
        v.extend_from_slice(&[b'n'; NOM_OCTETS_MAX + 1]);
        v.push(PARTI);
        assert_eq!(
            EntreeDEtat::lire(&v),
            Err(Faute::Longueur {
                annoncee: NOM_OCTETS_MAX + 1,
                maximum: NOM_OCTETS_MAX,
            })
        );
        let mut v = octets.to_vec();
        v[IDENTIFIANT_OCTETS * 2 + 1] = 0xFF;
        assert_eq!(EntreeDEtat::lire(&v), Err(Faute::NonNormalise));

        // Le drapeau.
        let mut v = octets.to_vec();
        v[IDENTIFIANT_OCTETS * 2 + 1 + 5] = 7;
        assert_eq!(EntreeDEtat::lire(&v), Err(Faute::Etiquette { lue: 7 }));

        // Une réponse annoncée au-delà de la borne.
        let mut v = octets.to_vec();
        let place = IDENTIFIANT_OCTETS * 2 + 1 + 5 + 1;
        v[place] = 0x10;
        v[place + 1] = 0x01;
        assert_eq!(
            EntreeDEtat::lire(&v),
            Err(Faute::Longueur {
                annoncee: 0x1001,
                maximum: REPONSE_FEDEREE_OCTETS_MAX,
            })
        );
    }
}
