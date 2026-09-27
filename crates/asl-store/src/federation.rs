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

use asl_id::Identifiant;
use asl_registre::{MACHINE_OCTETS, Machine, MachineFederee};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::{Entrepot, Faute, clef};

/// Les machines reçues des racines, par identifiant — le même encodage que
/// la table des machines.
pub(crate) const MACHINES_FEDEREES: TableDefinition<'_, &[u8], &[u8; MACHINE_OCTETS]> =
    TableDefinition::new("machines-federees");

impl Entrepot {
    /// Remplace les machines reçues des racines par celles-ci, et rend
    /// celles qui en sont sorties.
    ///
    /// **Ce qui sort est rendu** pour que l'étage 3 ferme les connexions de
    /// leurs daemons : une machine qui n'est plus dans un domaine hébergé ici
    /// — détachée, révoquée, son domaine rendu aux racines — n'annonce plus
    /// ici.
    ///
    /// # Errors
    ///
    /// [`Faute::Base`].
    pub fn ranger_les_machines_federees(
        &self,
        machines: &[MachineFederee],
    ) -> Result<Vec<Identifiant>, Faute> {
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
        ecriture.commit()?;
        Ok(sorties)
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
