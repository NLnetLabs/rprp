#!/usr/bin/env python3.9

"""
DNS backend for PowerDNS
Requires Python 3.9 or higher!
"""
import ipaddress
import sqlite3
import sys


base_folder = "/var/rpki/rsync"
prefix_length = 56
prefix = "2a01:7e01:e002:b900::"

default_domain = "rpki.koenvh.nl"
default_ipv6 = "2a01:7e01::f03c:92ff:fef0:f1c2"
default_ipv4 = "172.104.238.35"
default_ns = [
    "rpki-ns1.koenvh.nl.",
    "rpki-ns2.koenvh.nl."
]
letsencrypt_keys = [
    "KHlUSYMapXuDRxoJFGJUTJ_kOpE4CEUXollE35y0n0M",
    "ZbpHsaTLctHGcADMZUcJuZBegIrMYEn1IIviKXVTgl8"
]

def stdin():
    line = sys.stdin.readline()
    line = line.strip()
    return line.split("\t")

def stdout(text):
    text = "\t".join(text) + "\n"
    sys.stdout.write(text)
    sys.stdout.flush()

if __name__ == "__main__":
    handshake = stdin()
    stdout(["OK", "Ready for action"])

    while True:
        query = stdin()
        if query[0] == "CMD":
            stdout(["END"])
        elif query[0] == "Q":
            (_, qname, qclass, qtype, id, remote_ip_address) = query

            if qtype == "SOA":
                stdout(["DATA", qname, "IN", "SOA", "300", "1", "rpki-ns1.koenvh.nl"])
            elif qname == default_domain:
                if qtype == "A" or qtype == "ANY":
                    stdout(["DATA", qname, "IN", "A", "300", "1", str(default_ipv4)])
                if qtype == "AAAA" or qtype == "ANY":
                    stdout(["DATA", qname, "IN", "AAAA", "300", "1", str(default_ipv6)])
                if qtype == "NS" or qtype == "ANY":
                    for ns in default_ns:
                        stdout(["DATA", qname, "IN", "NS", "300", "1", str(ns)])   
            elif qname == "_acme-challenge." + default_domain:
                if qtype == "TXT" or qtype == "ANY":
                    for key in letsencrypt_keys:
                        stdout(["DATA", qname, "IN", "TXT", "60", "1", f"\"{key}\""])
            elif (qtype == "AAAA" or qtype == "ANY") and default_domain in qname:
                connection = sqlite3.connect(f"{base_folder}/rsync.db")
                cursor = connection.cursor()
                cursor.execute("INSERT OR IGNORE INTO rsync (host) VALUES (:host);", {"host": qname})
                connection.commit()
                cursor.execute("SELECT rowid FROM rsync WHERE host = :host;", {"host": qname})
                ip_id = cursor.fetchone()[0]

                ip_suffix_binary = format(ip_id, f"0{128 - prefix_length}b")
                ip_prefix_binary = "{:#b}".format(ipaddress.IPv6Address(prefix))[2:prefix_length + 2]
                ip_address = ipaddress.IPv6Address(int(f"{ip_prefix_binary}{ip_suffix_binary}", 2))

                stdout(["DATA", qname, "IN", "AAAA", "300", "1", str(ip_address)])

            stdout(["END"])

            
