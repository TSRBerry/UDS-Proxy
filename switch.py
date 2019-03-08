import _thread
import os
import shutil
import socket
import subprocess
import time

from scapy.all import *
from scapy.layers.dot11 import RadioTap


def send_proxy(packet):
    global sockets, mac
    try:  # TODO: clean garbage
        if not mac:
            mac = bssids[dec-1]
    except NameError:
        mac = bssids[dec - 1]
    if coh == 1:
        print(packet.show())
    try:
        addr1 = packet.addr1
        addr2 = packet.addr2
    except Exception:
        print("most likely no addr2")
    if addr2:
        if addr1 == mac or addr2 == mac:
            print("-----------------------")
            print(packet.show())
            print(raw(packet))
            print("-----------------------")
            for skt in sockets:
                skt.sendall(raw(packet))
    else:
        if addr1 == mac:
            print("-----------------------")
            print(packet.show())
            print(raw(packet))
            print("-----------------------")
            for skt in sockets:
                skt.sendall(raw(packet))


def proxysniffer():
    sniff(iface="monp0", prn=send_proxy)

    
def get_pkts(skt):
    while True:
        pkt = skt.recv(2048)
        if len(pkt) == 0:
            print("Shutting down...")
            sock.close()
            subprocess.Popen(["iw", "monp0", "del"])
            time.sleep(2)
            exit()
        print("+++++++++++++++++++++++")
        print(RadioTap(pkt).show())  # unsure
        print("+++++++++++++++++++++++")
        sendp(RadioTap(pkt), iface="monp0")
    

def get_client(skt):
    global sockets
    print("Server online.")
    while True:
        try:
            c, addr = skt.accept()
            sockets.append(c)
            print("Neue Verbindung: " + str(addr))
            _thread.start_new_thread(get_pkts, (c,))
        except KeyboardInterrupt:  # TODO: OSError happens due to Interrupt.. How should I handle that?
            print("Shutting down...")
            skt.close()
            subprocess.Popen(["iw", "monp0", "del"])
            time.sleep(2)


print("1) Host - Creates the server")
print("2) Client - Joins a server")
coh = input("Pick a number from the list: ")
if not coh.isnumeric():
    print("That's not a number..")
    exit()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sockets = []
subprocess.Popen(["airmon-ng"])
time.sleep(2)
adapter = input("Enter the phy device you want to use: ")
subprocess.Popen(["iw", "phy", adapter, "interface", "add", "monp0", "type", "monitor"])
time.sleep(2)
subprocess.Popen(["ifconfig", "monp0", "promisc", "up"])
time.sleep(2)
if os.path.isdir("cap"):
    shutil.rmtree("cap")
    os.mkdir("cap")
else:
    os.mkdir("cap")
dump = "airodump-ng monp0 -w cap/cap"
choose = []
bssids = []
essid = {}
with subprocess.Popen(dump.split()) as cmd:
    time.sleep(10)
    cmd.terminate()
with open("cap/cap-01.csv", "r") as file:
    text = file.readlines()
del (text[0])
del (text[0])
del (text[len(text) - 1])
for line in text:
    if ":" in line:
        choose.append(line)
for line in choose:
    comma = 0
    for test in line:
        if test == ",":
            comma = comma + 1
    if comma == 14:
        csv = line.split(",")
        for item in csv:
            if ":" in item:
                if "-" not in item:
                    if item.split()[0] not in bssids:
                        bssids.append(item)
                        essid[item] = csv[len(csv)-2]
i = 1
for bssid in bssids:
    print(str(i) + ") " + bssid + " - " + essid[bssid] + " - Length: " + str(len(essid[bssid])))
    i = i + 1
print("m) Enter BSSID manually")
done = False
while not done:
    dec = input("Choose a BSSID from the list: ")
    try:
        if dec.lower() == "m":
            mac = input("Enter BSSID: ")
            stage = False
            done = True
        else:
            dec = int(dec)
            stage = True
    except ValueError:
        stage = False
    if stage:
        if dec <= len(bssids):
            done = True
if coh == "1":
    print("Staring Server..")
    sock.bind(("0.0.0.0", 3333))
    sock.listen(1)
    _thread.start_new_thread(proxysniffer, ())
    get_client(sock)
else:
    ip = input("Enter the IP you want to join: ")
    print("Connecting to " + ip)
    sock.connect((ip, 3333))
    sockets.append(sock)
    _thread.start_new_thread(proxysniffer, ())
    _thread.start_new_thread(get_pkts, (sock,))
    print("Client online.")
    while True:
        try:
            pass
        except KeyboardInterrupt:
            print("Shutting down...")
            sock.close()
            subprocess.Popen(["iw", "monp0", "del"])
            time.sleep(2)
