#!/usr/bin/env python3

import base64
import ipaddress
import os
import psutil
import shutil
import sqlite3
import subprocess
import sys
from xml.etree import ElementTree

import requests


ip = ""
host = ""
base_folder = ""
prefix_length = 64

def start():
    try:
        os.makedirs(f"{base_folder}/{host}")
        os.makedirs(f"{base_folder}/{host}/repository")
        os.makedirs(f"{base_folder}/{host}/ta")
    except FileExistsError as e:
        print(e)
        if os.path.exists(f"{base_folder}/{host}/locked"):
            return
        elif os.path.exists(f"{base_folder}/{host}/rsyncd.pid"):
            pid = open(f"{base_folder}/{host}/rsyncd.pid", "r").read()
            if psutil.pid_exists(int(pid)):
                return

        shutil.rmtree(f"{base_folder}/{host}")
        pass

    open(f"{base_folder}/{host}/locked", "w").write("LOCKED")

    try:
        config = f"""
pid file = {base_folder}/{host}/rsyncd.pid
lock file = {base_folder}/{host}/rsync.lock
log file = {base_folder}/{host}/rsync.log
port = 873

[repository]
path = {base_folder}/{host}/repository
comment = rprp.nlnetlabs.net dummy rsync daemon
read only = true
timeout = 300

[ta]
path = {base_folder}/{host}/ta
comment = rprp.nlnetlabs.net dummy rsync daemon
read only = true
timeout = 300
"""

        with open(f"{base_folder}/{host}/rsync.conf", "w") as f:
            f.write(config)

        print("Fetching TAL...")
        requests.get(f"https://{host}/tal.tal")
        ta = requests.get(f"https://{host}/ta/ta.cer")
        with open(f"{base_folder}/{host}/ta/ta.cer", "wb") as f:
            f.write(ta.content)
        print("Fetching notification...")
        notification = requests.get(f"https://{host}/notification.xml").content
        notification = ElementTree.fromstring(notification)
        print("Fetching snapshot...")
        snapshot = notification[0].attrib["uri"]
        snapshot = requests.get(snapshot).content
        snapshot = ElementTree.fromstring(snapshot)
        for publish in snapshot:
            filename = publish.attrib["uri"].split("/")[-1]
            content = base64.b64decode(publish.text)
            with open(f"{base_folder}/{host}/repository/{filename}", "wb") as f:
                f.write(content)

        print("Starting rsync...")
        subprocess.Popen(f"rsync --daemon --config={base_folder}/{host}/rsync.conf --ipv6 --address={ip}", shell=True)
        subprocess.run(f"ip6tables -I INPUT -p tcp --destination-port 873 -d {ip} -j ACCEPT", shell=True)

    finally:
        os.remove(f"{base_folder}/{host}/locked")

def stop():
    subprocess.run(f"ip6tables -D INPUT -p tcp --destination-port 873 -d {ip} -j ACCEPT", shell=True)
    pid = open(f"{base_folder}/{host}/rsyncd.pid").read()
    subprocess.run(f"kill {pid}", shell=True)
    shutil.rmtree(f"{base_folder}/{host}")

if __name__ == "__main__":
    ip = sys.argv[2]
    base_folder = "/var/rpki/rsync"
    # We have a /64, so we only care about the last 64 bits
    ip_id = '{:#b}'.format(ipaddress.IPv6Address(ip))[(128 - prefix_length) + 2:]
    ip_id = int(ip_id, 2)

    connection = sqlite3.connect(f"{base_folder}/rsync.db")
    cursor = connection.cursor()
    cursor.execute("SELECT host FROM rsync WHERE rowid=:id", {"id": ip_id})
    host = cursor.fetchone()[0]

    print(host)

    if sys.argv[1] == "start":
        start()
    elif sys.argv[1] == "stop":
        stop()
