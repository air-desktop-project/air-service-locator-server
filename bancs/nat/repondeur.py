#!/usr/bin/env python3
"""Le côté ANNUAIRE du banc : il attend, puis il rappelle.

CE QU'IL MESURE, ET POURQUOI PAS AUTRE CHOSE
============================================

La question à laquelle ce banc répond est : **combien de temps un daemon peut-il
se taire avant que l'annuaire ne puisse plus le joindre ?**

C'est le sens ENTRANT qui compte, et lui seul. Un datagramme SORTANT passe
toujours — il crée un mappage au passage —, donc vérifier qu'il arrive ne dit
rien d'un NAT. Ce qui casse est le retour : la poussée de verdict, que
`protocole.md` §1.4 fait voyager sur la connexion tenue, et qui part de
l'annuaire vers un daemon qui n'a rien demandé depuis un moment.

Ce répondeur reçoit donc une demande, **se tait pendant le délai demandé**, puis
répond à l'adresse d'où la demande venait. Si la réponse arrive, le mappage a
tenu ; si elle se perd, il est mort entre-temps.

POURQUOI PAS LA VRAIE PILE
==========================

`asl-client-tokio` annonce soixante secondes d'inactivité, et QUIC ferme au plus
court des deux bouts. Mesurer avec elle plafonnerait donc à ce que NOUS avons
décidé, et non à ce que le réseau tolère — on lirait notre propre minuterie.

Ce banc mesure le RÉSEAU, en UDP nu. Les minuteries du produit se choisissent
ENSUITE, contre le nombre qu'il rend.

USAGE
=====

    python3 repondeur.py [port]          # défaut : 16630

Il écrit une ligne par événement sur la sortie standard, et ne s'arrête que sur
interruption.
"""

import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 16630
# Au-delà, ce n'est plus une demande de ce banc : on n'attend pas une heure
# parce qu'un paquet égaré le demandait.
DELAI_MAX = 900


def dire(*quoi):
    print(f"{time.strftime('%H:%M:%S')} " + " ".join(str(x) for x in quoi), flush=True)


def rappeler(prise, ou, delai, etiquette):
    """Se tait `delai` secondes, puis répond à `ou`."""
    time.sleep(delai)
    # **L'ADRESSE VUE EST DANS LA RÉPONSE.** Elle dit au sondeur sous quel port
    # l'annuaire le voyait AU MOMENT DE LA DEMANDE : un port qui aurait changé
    # entre-temps se verrait au tour suivant.
    message = f"RETOUR {etiquette} {ou[0]} {ou[1]}".encode()
    try:
        prise.sendto(message, ou)
        dire(f"rappel  {etiquette:>6} après {delai:>4} s → {ou[0]}:{ou[1]}")
    except OSError as quoi:
        dire(f"rappel  {etiquette:>6} IMPOSSIBLE : {quoi}")


def main():
    # `AF_INET6` avec `IPV6_V6ONLY` à zéro : une seule socket pour les deux
    # familles, comme l'annuaire lui-même (voir `asl-server::socket`).
    prise = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    prise.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    prise.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    prise.bind(("::", PORT))
    dire(f"répondeur sur [::]:{PORT} (double pile) — Ctrl-C pour finir")

    while True:
        try:
            donnees, ou = prise.recvfrom(1500)
        except KeyboardInterrupt:
            dire("fini")
            return
        morceaux = donnees.decode("utf-8", "replace").split()
        # **L'ÉCHO RÉPOND TOUT DE SUITE**, et c'est ce qui rend la mesure juste :
        # un pare-feu à état ne traite pas de la même façon un flux qui n'a
        # jamais rien reçu et un flux ÉTABLI. Linux, par exemple, garde le
        # premier trente secondes et le second cent vingt (`nf_conntrack_udp_*`).
        # Une connexion QUIC est bidirectionnelle dès la poignée de main : c'est
        # le second cas qu'il faut mesurer, pas le premier.
        if len(morceaux) >= 1 and morceaux[0] == "ECHO":
            prise.sendto(b"ECHO " + " ".join(morceaux[1:]).encode(), ou)
            dire(f"écho    de {ou[0]}:{ou[1]}")
            continue
        if len(morceaux) != 3 or morceaux[0] != "DELAI":
            dire(f"ignoré  de {ou[0]}:{ou[1]} : {donnees[:40]!r}")
            continue
        try:
            delai = min(int(morceaux[1]), DELAI_MAX)
        except ValueError:
            dire(f"ignoré  de {ou[0]}:{ou[1]} : délai illisible")
            continue
        etiquette = morceaux[2][:16]
        dire(f"demande {etiquette:>6} de {ou[0]}:{ou[1]} — rappel dans {delai} s")
        threading.Thread(
            target=rappeler, args=(prise, ou, delai, etiquette), daemon=True
        ).start()


if __name__ == "__main__":
    main()
