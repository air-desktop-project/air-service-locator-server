#!/usr/bin/env python3
"""Le côté DAEMON du banc : il demande à être rappelé, puis il se tait.

Voir `repondeur.py` pour ce que ce banc mesure et pourquoi.

UNE SOCKET PAR DÉLAI, ET TOUTES EN MÊME TEMPS
=============================================

Chaque délai a besoin de son PROPRE mappage : une fois qu'un mappage est mort,
tout ce qui passerait par la même socket en créerait un neuf, et l'on mesurerait
ce neuf-là. Les sondes sont donc lancées ensemble, chacune sur sa socket, et le
banc dure le plus long des délais au lieu de leur somme.

USAGE
=====

    python3 sondeur.py <hôte> [--port 16630] [--delais 15,30,45,...] [--famille 4|6]
"""

import argparse
import select
import socket
import sys
import time


def dire(*quoi):
    print(f"{time.strftime('%H:%M:%S')} " + " ".join(str(x) for x in quoi), flush=True)


def main():
    analyseur = argparse.ArgumentParser(description=__doc__)
    analyseur.add_argument("hote")
    analyseur.add_argument("--port", type=int, default=16630)
    analyseur.add_argument("--delais", default="15,30,45,60,90,120,180,240,300")
    analyseur.add_argument("--famille", choices=("4", "6"), default="6")
    analyseur.add_argument(
        "--sans-echauffement",
        action="store_true",
        help="ne pas établir le flux avant de se taire (cas pessimiste)",
    )
    analyseur.add_argument(
        "--marge",
        type=int,
        default=20,
        help="secondes d'attente au-delà du plus long délai",
    )
    args = analyseur.parse_args()

    famille = socket.AF_INET6 if args.famille == "6" else socket.AF_INET
    infos = socket.getaddrinfo(args.hote, args.port, famille, socket.SOCK_DGRAM)
    cible = infos[0][4]
    delais = [int(x) for x in args.delais.split(",")]

    dire(f"cible {cible[0]}:{cible[1]} en IPv{args.famille}")
    dire(f"délais : {', '.join(str(d) for d in delais)} s")

    if args.sans_echauffement:
        dire("SANS échauffement : le flux n'aura jamais rien reçu (cas pessimiste)")
    else:
        dire("échauffement : un aller-retour d'abord, pour que le flux soit ÉTABLI")

    prises = {}
    for delai in delais:
        prise = socket.socket(famille, socket.SOCK_DGRAM)
        prise.bind(("::", 0) if famille == socket.AF_INET6 else ("0.0.0.0", 0))
        etiquette = f"t{delai}"
        # **L'ALLER-RETOUR D'ABORD.** Un pare-feu à état distingue un flux qui
        # n'a jamais rien reçu d'un flux établi, et leur donne des durées de vie
        # très différentes. Une connexion QUIC est bidirectionnelle dès la
        # poignée de main : c'est le second cas qui décrit notre produit.
        if not args.sans_echauffement:
            prise.sendto(f"ECHO {etiquette}".encode(), cible)
            prise.settimeout(3)
            try:
                prise.recvfrom(1500)
            except OSError:
                dire(f"  échauffement de {etiquette} SANS RÉPONSE — le répondeur répond-il ?")
            prise.settimeout(None)
        prise.sendto(f"DELAI {delai} {etiquette}".encode(), cible)
        prises[prise.fileno()] = (prise, delai, etiquette, prise.getsockname()[1])
        dire(f"  sonde {etiquette:>6} partie du port local {prise.getsockname()[1]}")

    # **PLUS RIEN N'EST ENVOYÉ À PARTIR D'ICI.** C'est tout l'objet du banc : le
    # silence est ce qu'on mesure, et un seul datagramme le rafraîchirait.
    dire("silence — on attend les rappels")

    recus = {}
    fin = time.monotonic() + max(delais) + args.marge
    while time.monotonic() < fin and len(recus) < len(prises):
        reste = fin - time.monotonic()
        prets, _, _ = select.select([p[0] for p in prises.values()], [], [], min(reste, 5))
        for prise in prets:
            donnees, _ = prise.recvfrom(1500)
            _, delai, etiquette, port_local = prises[prise.fileno()]
            morceaux = donnees.decode("utf-8", "replace").split()
            vu = f"{morceaux[2]}:{morceaux[3]}" if len(morceaux) >= 4 else "?"
            recus[etiquette] = vu
            dire(f"  RAPPEL {etiquette:>6} reçu après {delai} s — l'annuaire nous voyait en {vu}")

    print()
    print("── ce que le réseau tolère " + "─" * 44)
    survecu = []
    for _, (_, delai, etiquette, port_local) in sorted(
        prises.items(), key=lambda kv: kv[1][1]
    ):
        vu = recus.get(etiquette)
        etat = "TENU  " if vu else "PERDU "
        if vu:
            survecu.append(delai)
        print(f"  {delai:>4} s de silence : {etat} (port local {port_local}"
              + (f", vu en {vu})" if vu else ")"))
    print()
    if not survecu:
        print("  AUCUN délai n'a tenu — le répondeur est-il joignable ?")
        return 1
    if len(survecu) == len(delais):
        print(f"  Tous ont tenu, jusqu'à {max(delais)} s. La borne est AILLEURS que")
        print("  dans l'intervalle éprouvé : recommencer avec des délais plus longs.")
    else:
        print(f"  Le plus long silence qui tienne est {max(survecu)} s ;")
        print(f"  le plus court qui casse est {min(d for d in delais if d not in survecu)} s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
