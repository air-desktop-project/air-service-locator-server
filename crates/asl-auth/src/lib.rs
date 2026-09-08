//! Ce qui autorise : jetons, portées, et le lien entre une session et l'appareil
//! qui l'a ouverte.
//!
//! # La contrainte du produit, énoncée là où elle s'applique
//!
//! Les applications mobiles ne s'installent que sur des appareils capables de
//! confirmer localement l'identité de leur porteur — Face ID, Touch ID, ou leur
//! équivalent Android. **Cette vérification a lieu SUR L'APPAREIL, et le serveur
//! ne la voit jamais.** Aucune empreinte, aucun gabarit facial ne traverse le
//! réseau ; ces données ne quittent pas l'enclave sécurisée du téléphone, et le
//! système d'exploitation ne les rend pas.
//!
//! Ce que le serveur peut donc constater n'est PAS « cet humain est bien lui »,
//! mais « cette requête est signée par une clé qui vit dans le matériel
//! sécurisé d'un appareil enrôlé, et que cet appareil n'a débloquée qu'après
//! une confirmation biométrique ». La nuance n'est pas rhétorique : elle dit
//! exactement ce que le protocole doit transporter — une signature et une
//! attestation, pas un résultat de comparaison.
//!
//! Confondre les deux mènerait à un serveur qui croit vérifier une identité
//! alors qu'il fait confiance à un booléen envoyé par le client.
//!
//! # Ce qui est arrêté par `docs/protocole.md` §2 et `docs/modele.md` §2
//!
//! - **L'attestation manquante ou en échec fait REFUSER** en v1, et c'est
//!   journalisé. Un refus se relâche plus tard ; une acceptation ne se resserre
//!   jamais sans casser des comptes déjà ouverts.
//! - **Un daemon ne fait pas de biométrie.** Sa machine détient une **paire de
//!   clés Ed25519**, générée sur place, dont la partie privée ne sort jamais.
//!   L'annuaire ne connaît que la partie publique. Elle est par MACHINE et non
//!   par daemon — l'énoncé du produit veut qu'un daemon quelconque puisse
//!   s'annoncer sans avoir été déclaré d'avance. Le prix : tout daemon de cette
//!   machine capable de lire la clé peut s'annoncer sous n'importe quel nom.
//! - **AUCUN SECRET PARTAGÉ** (contrainte C14). Un jeton porteur existe en deux
//!   exemplaires au moins, transite au moment où on le pose, et quiconque
//!   l'intercepte devient son porteur. Une signature prouve la détention sans
//!   transmettre ce qui est détenu. La seule exception est le **code
//!   d'enrôlement**, nommé comme tel plutôt que déguisé : à usage unique,
//!   valable quelques minutes, et il n'ouvre qu'une opération — lier une clé.
//! - **La même clé sert à LIRE**, quand la machine porte la capacité `lecture`.
//!   Les deux capacités ne sont pas cumulées par défaut : une machine qui porte
//!   les deux laisse, si elle est prise, énumérer tout ce que son propriétaire a
//!   le droit de voir, y compris les services que des amis lui ont accordés sur
//!   des machines qui ne sont pas les siennes.
//! - **L'authentification est portée par la CONNEXION, pas par la requête.** La
//!   clé est prouvée une fois à l'établissement de la connexion QUIC, et toutes
//!   les requêtes en héritent. Pas de jeton à joindre, donc pas de jeton à
//!   intercepter ni à rejouer.
//! - **Rien ne se lit sans autorisation nominative** (contrainte C10). Toute
//!   réponse de résolution se calcule à partir du compte propriétaire de la
//!   machine qui demande, JAMAIS à partir de ce que la requête désigne. Un
//!   chemin qui rendrait un service parce que son identifiant a été fourni
//!   serait la faille entière de ce produit, et il passerait tous les essais qui
//!   ne la cherchent pas.
//! - **Un appareil ne peut pas se révoquer lui-même.** Sinon un téléphone volé
//!   et déverrouillé révoque les autres et confisque le compte.
//!
//! # Les comparaisons se font en temps constant (contrainte C9)
//!
//! Une clé inconnue et un service inexistant rendent la même réponse après le
//! même délai. L'annuaire sait où écoutent des services qui ne publient pas leur
//! port : un écart de temps de réponse dit à un inconnu qu'une machine existe,
//! et c'est tout ce qu'il cherchait.
//!
//! # État
//!
//! Vide. Spécifié, pas écrit.
