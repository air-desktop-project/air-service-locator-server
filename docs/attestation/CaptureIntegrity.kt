// CaptureIntegrity.kt
//
// Un bout de code JETABLE, qui n'a qu'un but : produire UN jeton Play Integrity
// réel sur un vrai appareil Android, et l'imprimer. On le colle dans une app de
// test, on le lance une fois, on copie ce qu'il imprime, on l'oublie. Il ne
// fait pas partie d'un produit.
//
// PRÉ-REQUIS, ET AUCUN N'EST FACULTATIF :
//   • un APPAREIL RÉEL, avec les services Google Play. Play Integrity ne marche
//     ni sur un émulateur sans Play, ni hors d'un appareil certifié.
//   • un projet Google Cloud, et l'API Play Integrity activée dessus.
//   • l'app liée à ce projet dans la Google Play Console (App integrity), avec
//     les CLÉS DE CHIFFREMENT DE RÉPONSE en mode « gérées et téléchargées par
//     moi » — c'est ce qui permet de déchiffrer le jeton SANS appeler Google.
//   • la dépendance Gradle :
//         implementation("com.google.android.play:integrity:1.4.0")
//
// CE QU'IL FAUT NOTER pour le serveur : le jeton (imprimé), le défi (imprimé),
// et — depuis la Play Console, une seule fois — les deux clés de chiffrement de
// réponse et le nom du paquet.

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import java.security.SecureRandom

// Le NUMÉRO du projet Google Cloud (pas son identifiant textuel).
private const val NUMERO_PROJET_CLOUD = 0L // ← à remplir

/// Fabrique un jeton et imprime de quoi le vérifier côté serveur.
///
/// À appeler UNE FOIS, par exemple depuis un bouton. Le résultat part dans
/// Logcat, étiquette « CAPTURE ».
fun capturerUnJeton(contexte: Context) {
    // 1. LE DÉFI. Trente-deux octets d'aléa, encodés en base64 URL-safe sans
    //    remplissage — la forme qu'un nonce Play Integrity accepte. On le
    //    RÉUTILISERA tel quel côté serveur, donc on l'imprime.
    val octets = ByteArray(32)
    SecureRandom().nextBytes(octets)
    val defi = Base64.encodeToString(octets, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    // 2. LA DEMANDE (API « classique » : la plus simple pour une capture).
    val gestionnaire = IntegrityManagerFactory.create(contexte)
    gestionnaire
        .requestIntegrityToken(
            IntegrityTokenRequest.builder()
                .setNonce(defi)
                .setCloudProjectNumber(NUMERO_PROJET_CLOUD)
                .build()
        )
        .addOnSuccessListener { reponse ->
            // 3. LE JETON — un JWE compact, déjà du texte base64url.
            Log.i("CAPTURE", "──────── CAPTURE PLAY INTEGRITY ────────")
            Log.i("CAPTURE", "JETON=${reponse.token()}")
            Log.i("CAPTURE", "DEFI=$defi")
            Log.i("CAPTURE", "PAQUET=${contexte.packageName}")
            Log.i("CAPTURE", "────────────────────────────────────────")
        }
        .addOnFailureListener { faute ->
            Log.e("CAPTURE", "la demande a échoué : $faute")
        }
}
