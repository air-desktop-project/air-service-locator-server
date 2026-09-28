//! Les machines qu'un annuaire local reçoit des racines (`docs/annuaires.md`
//! §2 bis, `docs/protocole.md` §3 ter ; `docs/replication.md` décision 52).
//!
//! # UNE TABLE À PART, HORS DU JOURNAL, ET C'EST CE QUI LA REND SÛRE
//!
//! Un annuaire local n'écrit aucune machine : elles appartiennent à des
//! comptes qui vivent aux racines, et c'est là qu'on les déclare, qu'on les
//! enrôle, qu'on les révoque. Il en reçoit une COPIE — celles des domaines
//! qu'il héberge —, pour authentifier les annonces de leurs daemons.
//!
//! Cette copie **ne va pas dans la table des machines**, et trois raisons le
//! tranchent :
//!
//! - **Elle ne se réplique pas.** Rangée parmi les machines, elle partirait
//!   dans l'instantané que l'annuaire local sert à son second membre, qui la
//!   tiendrait alors comme une écriture à lui — et ne saurait plus qu'elle
//!   vient des racines le jour où les racines la retirent. Chaque membre de la
//!   paire tire sa propre copie, de sa propre voie.
//! - **Elle se REMPLACE en bloc.** Ce que les racines rendent est l'ensemble
//!   vrai en ce moment ; une machine qui n'y est plus est retirée ici, sans
//!   estampille ni règle de conflit : ce n'est pas un fait qui converge, c'est
//!   un miroir qu'on rafraîchit.
//! - **Elle n'est jamais écrite par une racine.** Aux racines, la table reste
//!   vide, et la lecture d'une machine ne la regarde que quand la table des
//!   machines n'a rien — un accès de plus sur un identifiant inconnu, rien
//!   d'autre.
//!
//! [`Entrepot::machine`] lit donc les deux ; et un service répliqué entre les
//! deux membres d'une paire se range si sa machine est dans l'une ou l'autre.
//!
//! # UN SERVICE DU PAIR QUI ARRIVE AVANT SA MACHINE ATTEND ICI (0.36.0)
//!
//! Les deux membres d'une paire se répliquent leurs services ; chacun tire
//! ses machines des racines, par sa propre voie. Les deux voies ne vont pas
//! au même pas : un membre neuf — pas encore accepté, ou dont le fédérateur
//! n'a pas fait son premier tour — tire le journal de son pair AVANT d'avoir
//! reçu les machines de ses domaines. Jusqu'à la 0.35.3, l'opération
//! `service` d'une machine inconnue était ignorée, **et le curseur avançait** :
//! elle ne revenait jamais (`docs/annuaires.md` §2 ter, décision 69).
//!
//! Elle est désormais **gardée** dans [`SERVICES_EN_ATTENTE`], et
//! [`Entrepot::ranger_les_machines_federees`] la **rejoue** — avec la règle
//! ordinaire, « le plus ancien reste » — quand sa machine arrive. Pourquoi
//! garder plutôt que de retenir le curseur : une opération qui ne
//! s'appliquerait jamais (une machine sortie de nos domaines pour de bon)
//! figerait tout le flux derrière elle ; gardée à part, elle ne retient
//! qu'elle-même. Et pourquoi pas l'écrire quand même parmi les services :
//! un service sans machine serait publié aux racines, qui le refuseraient
//! (C11) — et le rapport ENTIER avec lui.
//!
//! **Une seule par `(machine, nom)`** : la plus ancienne, puisque c'est elle
//! qui gagnerait au rejeu. La table ne grandit donc pas avec les relivraisons,
//! et reste bornée par ce que le pair a déclaré.

use asl_id::Identifiant;
use asl_registre::{
    IDENTIFIANT_OCTETS, MACHINE_OCTETS, Machine, MachineFederee, NOM_OCTETS_MAX, SERVICE_OCTETS,
    Service,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, WriteTransaction};

use crate::{EffetsVivants, Entrepot, Faute, clef, clef_de_nom, depuis_clef};

/// Les machines reçues des racines, par identifiant — le même encodage que
/// la table des machines.
pub(crate) const MACHINES_FEDEREES: TableDefinition<'_, &[u8], &[u8; MACHINE_OCTETS]> =
    TableDefinition::new("machines-federees");

/// Les services du pair qui attendent leur machine (0.36.0, décision 69) :
/// `machine ‖ nom` vers `identifiant (17) ‖ service`. Vide chez une racine.
pub(crate) const SERVICES_EN_ATTENTE: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("services-en-attente");

/// Ce qu'un rangement des machines reçues a donné.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Rangement {
    /// Les machines qui sont sorties de nos domaines : leurs connexions
    /// doivent tomber ici.
    pub sorties: Vec<Identifiant>,
    /// Combien de services du pair, gardés en attente de leur machine, ont été
    /// rejoués parce qu'elle vient d'arriver.
    pub rejoues: usize,
    /// Ce que ces rejeux font à l'état vivant — un `s-…` qui perd la règle du
    /// plus ancien, et la session à déplacer.
    pub effets: EffetsVivants,
}

/// Garde ce service du pair, dont la machine n'est pas encore reçue — le plus
/// ancien seulement, pour son `(machine, nom)`.
pub(crate) fn garder_en_attente(
    ecriture: &WriteTransaction,
    quel: Identifiant,
    enregistrement: &Service,
) -> Result<(), Faute> {
    let clef_nom = clef_de_nom(enregistrement.machine, enregistrement.nom.octets());
    let mut table = ecriture.open_table(SERVICES_EN_ATTENTE)?;
    if let Some(tenu) = table.get(clef_nom.as_slice())? {
        let (_, deja) = lire_en_attente(tenu.value())?;
        if deja.estampille <= enregistrement.estampille {
            return Ok(());
        }
    }
    let mut valeur = clef(quel).to_vec();
    let mut octets = [0_u8; SERVICE_OCTETS];
    enregistrement.ecrire(&mut octets);
    valeur.extend_from_slice(&octets);
    table.insert(clef_nom.as_slice(), valeur.as_slice())?;
    Ok(())
}

/// Re-dérive le `s-…` de chaque service en attente (la migration de la
/// décision 72). La clé — `machine ‖ nom` — ne change pas. Rend combien ont
/// changé.
pub(crate) fn rederiver_les_services_en_attente(
    ecriture: &WriteTransaction,
) -> Result<usize, Faute> {
    let mut table = ecriture.open_table(SERVICES_EN_ATTENTE)?;
    let mut changees = Vec::new();
    for entree in table.iter()? {
        let (tenue, valeur) = entree?;
        let (quel, service) = lire_en_attente(valeur.value())?;
        let derive = asl_registre::service_derive(service.machine, service.nom.octets());
        if quel != derive {
            let mut neuve = clef(derive).to_vec();
            neuve.extend_from_slice(valeur.value().get(IDENTIFIANT_OCTETS..).unwrap_or_default());
            changees.push((tenue.value().to_vec(), neuve));
        }
    }
    for (tenue, neuve) in &changees {
        table.insert(tenue.as_slice(), neuve.as_slice())?;
    }
    Ok(changees.len())
}

/// Relit une entrée en attente : l'identifiant, puis le service.
fn lire_en_attente(octets: &[u8]) -> Result<(Identifiant, Service), Faute> {
    let (tete, corps) = octets
        .split_at_checked(IDENTIFIANT_OCTETS)
        .ok_or(Faute::Longueur {
            obtenue: octets.len(),
        })?;
    let corps: &[u8; SERVICE_OCTETS] = corps.try_into().map_err(|_| Faute::Longueur {
        obtenue: octets.len(),
    })?;
    Ok((depuis_clef(tete)?, Service::lire(corps)?))
}

impl Entrepot {
    /// Remplace les machines reçues des racines par celles-ci, rend celles
    /// qui en sont sorties, et rejoue les services du pair qui attendaient
    /// l'une d'elles.
    ///
    /// **Ce qui sort est rendu** pour que l'étage 3 ferme les connexions de
    /// leurs daemons : une machine qui n'est plus dans un domaine hébergé ici
    /// — détachée, révoquée, son domaine rendu aux racines — n'annonce plus
    /// ici.
    ///
    /// **Ce qui attendait est rejoué dans la même transaction** (0.36.0,
    /// décision 69) : une machine qui arrive fait ranger, par la règle
    /// ordinaire, les services que le pair avait déclarés pour elle avant
    /// qu'on la connaisse.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn ranger_les_machines_federees(
        &self,
        machines: &[MachineFederee],
    ) -> Result<Rangement, Faute> {
        let ecriture = self.base.begin_write()?;
        let mut sorties = Vec::new();
        {
            let mut table = ecriture.open_table(MACHINES_FEDEREES)?;
            let voulues: Vec<Vec<u8>> = machines
                .iter()
                .map(|federee| clef(federee.machine).to_vec())
                .collect();
            let mut tenues = Vec::new();
            for entree in table.iter()? {
                let (tenue, _) = entree?;
                tenues.push(tenue.value().to_vec());
            }
            for tenue in tenues {
                if !voulues.contains(&tenue) {
                    table.remove(tenue.as_slice())?;
                    sorties.push(identifiant_de_clef(&tenue));
                }
            }
            for federee in machines {
                let mut octets = [0_u8; MACHINE_OCTETS];
                federee.enregistrement.ecrire(&mut octets);
                table.insert(clef(federee.machine).as_slice(), &octets)?;
            }
        }
        let mut rangement = Rangement {
            sorties,
            ..Rangement::default()
        };
        // **LES SERVICES QUI ATTENDAIENT CES MACHINES**, rejoués comme s'ils
        // arrivaient maintenant : la machine est là, la règle s'applique.
        let mut a_rejouer = Vec::new();
        {
            let attente = ecriture.open_table(SERVICES_EN_ATTENTE)?;
            for federee in machines {
                let (debut, fin) = intervalle_de_machine(federee.machine);
                for entree in attente.range(debut.as_slice()..fin.as_slice())? {
                    let (tenue, valeur) = entree?;
                    a_rejouer.push((tenue.value().to_vec(), lire_en_attente(valeur.value())?));
                }
            }
        }
        for (tenue, (quel, service)) in a_rejouer {
            ecriture
                .open_table(SERVICES_EN_ATTENTE)?
                .remove(tenue.as_slice())?;
            crate::appliquer_service(&ecriture, quel, &service, true, &mut rangement.effets)?;
            rangement.rejoues = rangement.rejoues.saturating_add(1);
        }
        ecriture.commit()?;
        Ok(rangement)
    }

    /// Combien de services du pair attendent encore leur machine.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`].
    pub fn services_en_attente(&self) -> Result<usize, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(SERVICES_EN_ATTENTE)?;
        let mut combien = 0_usize;
        for entree in table.iter()? {
            let _ = entree?;
            combien = combien.saturating_add(1);
        }
        Ok(combien)
    }

    /// Les machines reçues des racines, en ce moment.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`] ou [`Faute::Enregistrement`].
    pub fn machines_federees(&self) -> Result<Vec<(Identifiant, Machine)>, Faute> {
        let lecture = self.base.begin_read()?;
        let table = lecture.open_table(MACHINES_FEDEREES)?;
        let mut rendues = Vec::new();
        for entree in table.iter()? {
            let (tenue, valeur) = entree?;
            rendues.push((
                identifiant_de_clef(tenue.value()),
                Machine::lire(valeur.value())?,
            ));
        }
        Ok(rendues)
    }
}

/// Les bornes des clefs `machine ‖ nom` de cette machine : sa clef, puis sa
/// clef suivie de l'octet le plus grand — un nom est plus court que la table.
fn intervalle_de_machine(machine: Identifiant) -> (Vec<u8>, Vec<u8>) {
    let debut = clef(machine).to_vec();
    let mut fin = debut.clone();
    fin.extend_from_slice(&[0xFF; NOM_OCTETS_MAX + 1]);
    (debut, fin)
}

/// L'identifiant d'une clef de table : son genre, puis ses seize octets.
///
/// Ces clefs ont été écrites par [`clef`] : la forme est la nôtre, et un
/// genre inconnu ne s'y trouve pas — la machine qu'elle désignerait n'aurait
/// de toute façon pas pu être rangée.
fn identifiant_de_clef(octets: &[u8]) -> Identifiant {
    let mut entropie = [0_u8; 16];
    for (place, octet) in entropie.iter_mut().zip(octets.iter().skip(1)) {
        *place = *octet;
    }
    Identifiant::depuis_entropie(asl_id::Genre::Machine, entropie)
}
