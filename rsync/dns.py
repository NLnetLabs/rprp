#!/usr/bin/env python3

"""
DNS backend for PowerDNS
Requires Python 3.9 or higher!
"""
import ipaddress
import sqlite3
import sys


base_folder = "/var/rpki/rsync"
prefix_length = 64
prefix = "2a01:4f8:1c1b:ad75::"

default_domain = "rprp.nlnetlabs.net"
default_ipv6 = "2a01:4f8:1c1b:ad75:ffff::1"
default_ipv4 = "167.235.64.7"
default_ns = [
    "rprp-ns1.nlnetlabs.net.",
    "rprp-ns2.nlnetlabs.net."
]
letsencrypt_keys = [
    "5TuapR2-ZWrIR9xdYjhfc2Z_NSU9lv9k9O5dzvLBxyQ",
    "8oUYt7iZi46imGkwAe3EJ6cOrFPxzIHf7f6aFZnToY0"
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
                stdout(["DATA", qname, "IN", "SOA", "300", "1", "rprp-ns1.nlnetlabs.net. koen.nlnetlabs.nl 2008080300 1800 3600 604800 3600"])
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

            