//! Les identifiants de service DÉRIVÉS, et la migration qui y amène les
//! entrepôts d'hier (`docs/annuaires.md` §2 ter ; `docs/replication.md`
//! décisions 66 et 72 ; 0.37.0).
//!
//! # CE QUI CHANGE : LE `s-…` NE SE TIRE PLUS, IL SE CALCULE
//!
//! `s-…` = [`asl_registre::service_derive`]`(machine, nom)`. L'entrepôt le
//! calcule lui-même à la déclaration ([`Entrepot::declarer_service`]) et à
//! l'application d'une opération `service` venue d'un pair — **le `s-…` que
//! porte le fil n'y est qu'indicatif** : deux entrepôts qui ont vu le même
//! `(machine, nom)` rangent le même `s-…`, sans se parler, quel que soit
//! l'ordre et quel que soit celui des deux qui l'a vu le premier.
//!
//! # LA MIGRATION : UNE FOIS, SEULE, DANS UNE TRANSACTION
//!
//! Un entrepôt d'avant la 0.37.0 porte des `s-…` tirés au hasard. À sa
//! première ouverture par un binaire qui dérive (format 3 → 4), chacun de ses
//! services passe sous son `s-…` dérivé, **avec tout ce qui le nomme** :
//!
//! - la table des services, et l'index `services-par-nom`, reconstruit ;
//! - les droits dont l'élément est ce service, et leur index par élément ;
//! - les services du pair qui attendent leur machine (`services-en-attente`,
//!   0.36.0) ;
//! - et une **correspondance** ancien → dérivé ([`SERVICES_RENOMMES`]), que
//!   l'application d'une opération `droit` d'un pair pas encore migré lit
//!   pour retrouver le service qu'elle nomme.
//!
//! Chaque entrepôt — les deux racines, chaque membre d'une paire — fait la
//! sienne sans parler aux autres, et arrive au même résultat. Le journal
//! d'opérations N'EST PAS réécrit : une opération `service` ancienne est
//! re-dérivée par qui l'applique ; une opération `droit` ancienne nomme un
//! `s-…` que la correspondance du lecteur connaît (le sien d'hier, ou celui
//! que l'opération `service` du pair lui a appris) ; et un pair encore en
//! 0.36.0, qui tient toujours les anciens `s-…`, les retrouve tels quels.
//!
//! # CE QUE LA MIGRATION REFUSE
//!
//! Deux services qui dériveraient au même `s-…`. Il n'y en a que deux
//! façons : **deux enregistrements pour le même `(machine, nom)`**, que
//! l'entrepôt n'aurait jamais dû tenir (`declarer_service` et la règle du plus
//! ancien l'interdisent), ou une collision de SHA-256 sur 128 bits. Dans les
//! deux cas, l'ouverture échoue en nommant les deux — [`Faute::Doublon`],
//! [`Faute::Collision`] — et rien n'est écrit : réparer l'entrepôt est un
//! geste d'exploitant, pas un choix que la migration ferait en silence.

use asl_id::{Genre, Identifiant};
use asl_registre::{SERVICE_OCTETS, Service, service_derive};
use redb::{ReadableTable, TableDefinition, WriteTransaction};

use crate::{
    EffetsVivants, Faute, SERVICES, SERVICES_PAR_NOM, clef, clef_de_nom, depuis_clef, droits,
    federation,
};

/// La correspondance des `s-…` d'hier : ancien → dérivé.
///
/// **Écrite par la migration** (nos propres `s-…` d'avant la 0.37.0) **et par
/// l'application** d'une opération `service` dont le `s-…` n'est pas le
/// dérivé (celui d'un pair pas encore migré). **Lue par l'application d'un
/// droit** : son élément peut nommer l'un d'eux. Elle ne se réplique pas, ne
/// se vide pas — quelques entrées par service ancien —, et ne change rien à
/// ce que l'entrepôt rend : aucune lecture ne la regarde.
pub(crate) const SERVICES_RENOMMES: TableDefinition<'_, &[u8], &[u8]> =
    TableDefinition::new("services-renommes");

/// Ce que la migration a fait (`docs/replication.md` décision 72).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MigrationDesIdentifiants {
    /// Combien de services tenus étaient rangés.
    pub services: usize,
    /// Combien d'entre eux ont changé de `s-…` — tous, sauf ceux qui étaient
    /// déjà sous leur dérivé (aucun, en pratique : un aléa ne tombe pas sur
    /// un condensat).
    pub reidentifies: usize,
    /// Combien de droits visaient l'un d'eux, et le visent sous le dérivé.
    pub droits: usize,
    /// Combien de services du pair, en attente de leur machine, ont été
    /// re-dérivés.
    pub en_attente: usize,
}

/// Note que `ancien` se dit désormais `derive`.
pub(crate) fn noter_le_renommage(
    ecriture: &WriteTransaction,
    ancien: Identifiant,
    derive: Identifiant,
) -> Result<(), Faute> {
    ecriture
        .open_table(SERVICES_RENOMMES)?
        .insert(clef(ancien).as_slice(), clef(derive).as_slice())?;
    Ok(())
}

/// Le service que cet identifiant nomme AUJOURD'HUI : lui-même s'il est tenu,
/// ou n'est pas un service ; son dérivé s'il est un `s-…` d'hier que la
/// correspondance connaît ; lui-même sinon — l'appelant jugera, comme avant.
pub(crate) fn traduire(
    ecriture: &WriteTransaction,
    quel: Identifiant,
) -> Result<Identifiant, Faute> {
    if quel.genre() != Genre::Service
        || ecriture
            .open_table(SERVICES)?
            .get(clef(quel).as_slice())?
            .is_some()
    {
        return Ok(quel);
    }
    match ecriture
        .open_table(SERVICES_RENOMMES)?
        .get(clef(quel).as_slice())?
    {
        Some(derive) => depuis_clef(derive.value()),
        None => Ok(quel),
    }
}

/// Passe ce service, rangé sous `ancien`, sous `derive` : l'enregistrement,
/// son entrée d'index, les droits qui le visent, la correspondance. Rend
/// combien de droits ont suivi.
///
/// **Pour un service encore tenu sous un `s-…` qui n'est pas son dérivé** au
/// moment où une opération du pair le nomme — ce qui n'arrive pas après la
/// migration, mais ne doit rien casser si cela arrivait.
pub(crate) fn renommer(
    ecriture: &WriteTransaction,
    ancien: Identifiant,
    derive: Identifiant,
    service: &Service,
) -> Result<usize, Faute> {
    let mut octets = [0_u8; SERVICE_OCTETS];
    service.ecrire(&mut octets);
    {
        let mut services = ecriture.open_table(SERVICES)?;
        services.remove(clef(ancien).as_slice())?;
        services.insert(clef(derive).as_slice(), &octets)?;
    }
    ecriture.open_table(SERVICES_PAR_NOM)?.insert(
        clef_de_nom(service.machine, service.nom.octets()).as_slice(),
        clef(derive).as_slice(),
    )?;
    noter_le_renommage(ecriture, ancien, derive)?;
    droits::renommer_l_element(ecriture, ancien, derive)
}

/// La migration de la décision 72 : chaque service passe sous son `s-…`
/// dérivé, avec ce qui le nomme. **Dans la transaction de l'ouverture** —
/// interrompue, elle n'a pas eu lieu, et recommencera.
///
/// **Idempotente** : un service déjà sous son dérivé ne bouge pas. C'est le
/// format 4 qui dit qu'elle a eu lieu ; la relancer ne changerait rien.
///
/// # Errors
///
/// [`Faute::Doublon`], [`Faute::Collision`] (voir l'en-tête), et les fautes de
/// la base.
pub(crate) fn migrer(ecriture: &WriteTransaction) -> Result<MigrationDesIdentifiants, Faute> {
    let mut tenus = Vec::new();
    for entree in ecriture.open_table(SERVICES)?.iter()? {
        let (quel, valeur) = entree?;
        tenus.push((depuis_clef(quel.value())?, Service::lire(valeur.value())?));
    }
    // **L'INVARIANT D'ABORD, AVANT D'ÉCRIRE QUOI QUE CE SOIT** : un `(machine,
    // nom)` par service, et un dérivé par `(machine, nom)`.
    let mut par_derive: std::collections::BTreeMap<Identifiant, (Identifiant, &Service)> =
        std::collections::BTreeMap::new();
    for (quel, service) in &tenus {
        let derive = service_derive(service.machine, service.nom.octets());
        if let Some((premier, deja)) = par_derive.insert(derive, (*quel, service)) {
            return Err(
                if deja.machine == service.machine && deja.nom == service.nom {
                    Faute::Doublon {
                        machine: service.machine,
                        services: (premier, *quel),
                    }
                } else {
                    Faute::Collision {
                        derive,
                        services: (premier, *quel),
                    }
                },
            );
        }
    }
    let mut faite = MigrationDesIdentifiants {
        services: tenus.len(),
        ..MigrationDesIdentifiants::default()
    };
    // **LES DEUX TABLES SE RÉÉCRIVENT EN ENTIER** : tout est relevé, tout est
    // retiré, tout est rangé sous son dérivé. Une entrée d'index orpheline —
    // un nom qui pointerait vers un service absent — ne survit pas, et aucun
    // rangement ne peut écraser un service pas encore déplacé.
    {
        let mut ouverte = ecriture.open_table(SERVICES_PAR_NOM)?;
        let clefs: Vec<Vec<u8>> = ouverte
            .iter()?
            .map(|entree| entree.map(|(tenue, _)| tenue.value().to_vec()))
            .collect::<Result<_, _>>()?;
        for tenue in &clefs {
            ouverte.remove(tenue.as_slice())?;
        }
    }
    {
        let mut services = ecriture.open_table(SERVICES)?;
        for (quel, _) in &tenus {
            services.remove(clef(*quel).as_slice())?;
        }
    }
    for (quel, service) in &tenus {
        let derive = service_derive(service.machine, service.nom.octets());
        let mut octets = [0_u8; SERVICE_OCTETS];
        service.ecrire(&mut octets);
        ecriture
            .open_table(SERVICES)?
            .insert(clef(derive).as_slice(), &octets)?;
        ecriture.open_table(SERVICES_PAR_NOM)?.insert(
            clef_de_nom(service.machine, service.nom.octets()).as_slice(),
            clef(derive).as_slice(),
        )?;
        if *quel != derive {
            noter_le_renommage(ecriture, *quel, derive)?;
            faite.droits = faite
                .droits
                .saturating_add(droits::renommer_l_element(ecriture, *quel, derive)?);
            faite.reidentifies = faite.reidentifies.saturating_add(1);
        }
    }
    faite.en_attente = federation::rederiver_les_services_en_attente(ecriture)?;
    Ok(faite)
}

/// `service` venu d'un pair — **ré-identifié par dérivation** : le `s-…` du fil
/// n'est qu'indicatif. S'il n'est pas le dérivé, c'est un pair d'avant la
/// 0.37.0 : on le note (la correspondance, pour ses droits ; les effets, pour
/// le journal) et l'on range sous le dérivé.
///
/// Rend le `s-…` sous lequel le service se range.
pub(crate) fn reidentifier(
    ecriture: &WriteTransaction,
    sur_le_fil: Identifiant,
    enregistrement: &Service,
    effets: &mut EffetsVivants,
) -> Result<Identifiant, Faute> {
    let derive = service_derive(enregistrement.machine, enregistrement.nom.octets());
    if sur_le_fil != derive {
        noter_le_renommage(ecriture, sur_le_fil, derive)?;
        effets.reidentifies.push((sur_le_fil, derive));
    }
    Ok(derive)
}
