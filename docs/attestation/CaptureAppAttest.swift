// CaptureAppAttest.swift
//
// Un bout de code JETABLE, qui n'a qu'un but : produire UNE attestation App
// Attest réelle sur un vrai appareil, et en imprimer de quoi la rejouer côté
// serveur. Il ne fait pas partie d'un produit ; on le colle dans une app de
// test, on le lance une fois, on copie ce qu'il imprime, on l'oublie.
//
// PRÉ-REQUIS, ET AUCUN N'EST FACULTATIF :
//   • un APPAREIL RÉEL (iPhone/iPad), iOS 14+. App Attest NE MARCHE PAS au
//     simulateur : `isSupported` y est faux.
//   • un compte au programme développeur Apple (un Team ID à 10 caractères).
//   • l'app lancée DEPUIS XCODE donnera une attestation d'environnement
//     « développement » (aaguid « appattestdevelop »). C'est le cas le plus
//     simple, et celui qu'on veut pour la première capture.
//
// CE QU'IL FAUT NOTER pour le serveur, et que ce code imprime :
//   • ATTESTATION_B64 — l'objet d'attestation.
//   • DEFI_B64        — le défi que l'app a haché ; le serveur le rejoue tel quel.
//   • APP_ID          — <Team ID>.<bundle id> ; il faut le compléter à la main
//                       (Xcode ne donne pas le Team ID à l'exécution).

import CryptoKit
import DeviceCheck
import Foundation

/// Fabrique une attestation et imprime de quoi la vérifier côté serveur.
///
/// À appeler UNE FOIS, par exemple depuis `applicationDidBecomeActive` ou un
/// bouton. Le résultat part dans la console d'Xcode.
func capturerUneAttestation() {
    let service = DCAppAttestService.shared
    guard service.isSupported else {
        print("APP ATTEST INDISPONIBLE — appareil réel requis (pas le simulateur).")
        return
    }

    // 1. LE DÉFI. Trente-deux octets d'aléa suffisent pour une capture : on ne
    //    lie rien ici, on valide le FORMAT. Le serveur rejouera EXACTEMENT ces
    //    octets, donc on les imprime.
    var defi = Data(count: 32)
    let tire = defi.withUnsafeMutableBytes { brut in
        SecRandomCopyBytes(kSecRandomDefault, 32, brut.baseAddress!)
    }
    guard tire == errSecSuccess else {
        print("le tirage du défi a échoué")
        return
    }

    // 2. UNE CLÉ NEUVE, dans le matériel sécurisé. Neuve, parce qu'une
    //    attestation est la PREMIÈRE signature d'une clé : son compteur doit
    //    être à zéro.
    service.generateKey { identifiantCle, erreur in
        guard let identifiantCle else {
            print("generateKey a échoué : \(String(describing: erreur))")
            return
        }

        // 3. clientDataHash = SHA256(defi). C'est ce qu'Apple hache dans le
        //    nonce ; le serveur recompose SHA256(authData ‖ clientDataHash).
        let clientDataHash = Data(SHA256.hash(data: defi))

        // 4. L'ATTESTATION.
        service.attestKey(identifiantCle, clientDataHash: clientDataHash) { attestation, erreur in
            guard let attestation else {
                print("attestKey a échoué : \(String(describing: erreur))")
                return
            }

            // 5. DE QUOI LA REJOUER.
            print("──────── CAPTURE APP ATTEST ────────")
            print("ATTESTATION_B64=\(attestation.base64EncodedString())")
            print("DEFI_B64=\(defi.base64EncodedString())")
            print("KEY_ID_B64=\(identifiantCle)")
            print("APP_ID=<TeamID à 10 caractères>.\(Bundle.main.bundleIdentifier ?? "<bundle inconnu>")")
            print("ENVIRONNEMENT=developpement   // 'production' si TestFlight/App Store")
            print("────────────────────────────────────")
        }
    }
}
