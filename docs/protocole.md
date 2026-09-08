# Protocole — À ÉCRIRE

Deux conversations, deux publics, et il n'est pas acquis qu'elles partagent un
transport.

## 1. Le daemon et l'annuaire (`asl-proto`, `asl-client`)

Ce que le daemon doit pouvoir dire : « je démarre, voici mon port », « je suis
toujours là », « je m'arrête ». Ce que l'annuaire doit pouvoir répondre : accusé
de réception, et la durée du bail qu'il accorde.

Questions ouvertes :

- **Le transport.** HTTPS tient sur tout ce qui existe et traverse les proxys ;
  un protocole binaire sur UDP coûte moins cher pour un rafraîchissement toutes
  les trente secondes. Le second suppose de gérer soi-même la retransmission.
- **La reprise après coupure.** L'annuaire injoignable ne doit pas empêcher un
  daemon de démarrer. Réessai avec quel recul ? Combien de temps avant d'y
  renoncer ?
- **L'adresse observée contre l'adresse annoncée** (cf. `modele.md`, question 5).

## 2. Les applications mobiles et l'annuaire (`asl-api`)

Créer un compte, déclarer une machine, lister les services et leur état,
révoquer.

Questions ouvertes :

- **L'enrôlement d'un appareil.** L'application prouve qu'elle détient une clé
  vivant dans le matériel sécurisé du téléphone, et que cette clé n'a été
  débloquée qu'après une confirmation biométrique locale. Quelle attestation
  exige-t-on, et que fait-on quand elle manque ?
- **Ce que le serveur ne verra jamais** : aucune empreinte, aucun gabarit facial.
  Le système d'exploitation ne les rend pas, et le protocole ne doit donc pas
  faire semblant de les transporter.
- **La perte d'un appareil.** Que révoque-t-on, et depuis quoi — un second
  appareil, un courriel, rien ?

## 3. La découverte, du côté du client d'un daemon

Le troisième public, et le moins évident : le programme qui veut JOINDRE un
daemon. Il n'a pas de compte, tourne peut-être sur une autre machine, et n'a
d'autre besoin que « donne-moi le port ».

- Par quoi s'autorise-t-il ? La réponse gouverne à elle seule si l'annuaire est
  énumérable.
- Que fait-il quand l'annuaire ne répond pas — dernier port connu, échec ?
