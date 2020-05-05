#!/bin/python3
import binascii

from scapy.all import *
import socket
import subprocess
import platform
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import traceback
import _thread


def proxy_mac_in():
    try:
        auto_mac = ""
        while auto_mac != "y" and auto_mac != "n":
            auto_mac = input("Use a random generated MAC-Address? [y/n]").lower()
        if auto_mac == "y":
            auto_mac = True
        else:
            auto_mac = False

        if auto_mac:
            random_letters = [x for x in "abcdef"]
            random_numbers = [str(x) for x in range(0, 10)]
            proxy_mac = original_mac[:-5]
            proxy_mac += random.choice(random_letters)
            proxy_mac += random.choice(random_numbers)
            proxy_mac += ":"
            proxy_mac += random.choice(random_letters)
            proxy_mac += random.choice(random_numbers)
        else:
            proxy_mac = input("Please enter the MAC-Address you want to use instead: ").lower()
        return proxy_mac
    except Exception as e:
        print("Auto_MAC failed. ", e)
        traceback.print_exc()
        print("Restoring MTU...")
        command = ["ifconfig", use_interface, "mtu", mtu_current]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        print("MTU restored.")
        print("Stopping monitor mode...")
        command = ["airmon-ng", "stop", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        pg.communicate()
        print("Stopped monitor mode.")
        input("Press enter to close this window")
        exit(1)


def recv_pkt(pkt):
    global use_interface, use_channel, frequencies
    try:
        if pkt.haslayer(RadioTap) and use_channel == "":
            print("Channel not set.")
            command = ["iw", use_interface, "set", "channel", frequencies[str(pkt[RadioTap].ChannelFrequency)]]
            print("Using channel " + frequencies[str(pkt[RadioTap].ChannelFrequency)] + " now.")
            pg = subprocess.Popen(command, stdout=subprocess.PIPE)
            pg.communicate()
            use_channel = frequencies[str(pkt[RadioTap].ChannelFrequency)]
            print("Channel set.")
        sendp(pkt, iface=use_interface)
    except Exception as e:
        print("Recv_PKT failed. ", e)
        pkt.show()
        print(len(raw(pkt)))
        traceback.print_exc()
        print("Restoring MTU...")
        command = ["ifconfig", use_interface, "mtu", mtu_current]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        print("MTU restored.")
        print("Stopping monitor mode...")
        command = ["airmon-ng", "stop", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        pg.communicate()
        print("Stopped monitor mode.")
        input("Press enter to close this window")
        exit(1)


def recv(s, key):
    try:
        new_recv = False
        data = b""
        while True:
            if new_recv:
                if "START" not in data.decode():
                    data = b""
                new_recv = False
            data += s.recv(1024)
            if "START" in data.decode() and "STOP" in data.decode():
                working_data = data.replace(b"START", b"").split(b"STOP")[0]
                data = data.split(b"STOP")[1]
                new_recv = True
                decoded_data = base64.b64decode(working_data)
                json_data = json.loads(decoded_data)
                json_k = ["nonce", "header", "ciphertext", "tag"]
                jv = {k: base64.b64decode(json_data[k]) for k in json_k}
                cipher = AES.new(key, AES.MODE_GCM, nonce=jv["nonce"])
                cipher.update(jv["header"])
                packet = cipher.decrypt_and_verify(jv["ciphertext"], jv["tag"])

                recv_pkt(RadioTap(packet))
    except json.decoder.JSONDecodeError as e:
        print(e)
        print("sock_RECV corrupted packet. Skipping.")
        recv(s, key)
    except UnicodeDecodeError as e:
        print(e)
        print("sock_RECV corrupted packet. Skipping.")
        recv(s, key)
    except binascii.Error as e:
        print(e)
        print("sock_RECV corrupted packet. Skipping.")
        recv(s, key)
    except ValueError as e:
        print("sock_RECV failed.")
        print(e)
        traceback.print_exc()
        print("Restoring MTU...")
        command = ["ifconfig", use_interface, "mtu", mtu_current]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        print("MTU restored.")
        print("Stopping monitor mode...")
        command = ["airmon-ng", "stop", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        pg.communicate()
        print("Stopped monitor mode.")
        input("Press enter to close this window")
        exit(1)

    except Exception as e:
        print("sock_RECV failed. ", e)
        traceback.print_exc()
        print("Restoring MTU...")
        command = ["ifconfig", use_interface, "mtu", mtu_current]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        print("MTU restored.")
        print("Stopping monitor mode...")
        command = ["airmon-ng", "stop", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        pg.communicate()
        print("Stopped monitor mode.")
        input("Press enter to close this window")
        exit(1)


def send_pkt(pkt):
    global list_send_pkts, original_mac
    try:
        if pkt[Dot11].addr2.lower() == original_mac.lower():
            # del pkt.fcs
            list_send_pkts.append(pkt)
    except AttributeError:
        print("sock_PKT faulty packet.")
        pkt.show()
        # list_send_pkts.append(pkt)
    except Exception as e:
        print("sock_PKT failed. ", e)
        traceback.print_exc()
        print("Restoring MTU...")
        command = ["ifconfig", use_interface, "mtu", mtu_current]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        print("MTU restored.")
        print("Stopping monitor mode...")
        command = ["airmon-ng", "stop", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        pg.communicate()
        print("Stopped monitor mode.")
        input("Press enter to close this window")
        exit(1)


def send(s, key):
    global list_send_pkts, proxy_mac, host
    try:
        while True:
            if len(list_send_pkts) != 0:
                for pkt in list_send_pkts:
                    # pkt[Dot11].addr2 = proxy_mac
                    # if host:
                    #     pkt[Dot11].addr3 = proxy_mac

                    header = b"Nintendo_Proxy_Tool"
                    nonce = get_random_bytes(12)
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    cipher.update(header)
                    ciphertext, tag = cipher.encrypt_and_digest(raw(pkt))
                    json_k = ["nonce", "header", "ciphertext", "tag"]
                    json_v = [base64.b64encode(x).decode() for x in [cipher.nonce, header, ciphertext, tag]]
                    decoded_data = json.dumps(dict(zip(json_k, json_v))).encode()
                    send_data = base64.b64encode(decoded_data)
                    send_data = b"START" + send_data + b"STOP"
                    s.sendall(send_data)

                    list_send_pkts.remove(pkt)
    except Exception as e:
        print("sock_SEND failed. ", e)
        traceback.print_exc()
        print("Restoring MTU...")
        command = ["ifconfig", use_interface, "mtu", mtu_current]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        print("MTU restored.")
        print("Stopping monitor mode...")
        command = ["airmon-ng", "stop", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        pg.communicate()
        print("Stopped monitor mode.")
        input("Press enter to close this window")
        exit(1)


list_send_pkts = []
frequencies = {
    "2412": "1",
    "2417": "2",
    "2422": "3",
    "2427": "4",
    "2432": "5",
    "2437": "6",
    "2442": "7",
    "2447": "8",
    "2452": "9",
    "2457": "10",
    "2462": "11",
    "2467": "12",
    "2472": "13",
    "2484": "14"
}
try:
    command = ["iw", "list"]
    pg = subprocess.Popen(command, stdout=subprocess.PIPE)
    (list_out, err) = pg.communicate()

    if "Wiphy" in list_out.decode():
        interfaces = []
        for line in list_out.decode().split("\n"):
            if "Wiphy" in line:
                interfaces.append(line.split(" ")[1])

        for interface in interfaces:
            command = ["iw", interface, "info"]
            pg = subprocess.Popen(command, stdout=subprocess.PIPE)
            (info_interface, err) = pg.communicate()

            if "* monitor" in info_interface.decode():
                print(interface + ": Monitor mode supported.")
            else:
                print(interface + ": Monitor mode not supported.")
                interfaces.remove(interface)

        command = ["airmon-ng"]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (airmon_out, err) = pg.communicate()
        airmon_dev = []
        if len(interfaces) > 1:
            print("Which device do you want to use?")
            choose = 1
            for interface in interfaces:
                for line in airmon_out.decode().split("\n"):
                    if interface in line:
                        print("[" + str(choose) + "] - " + line)
                        airmon_dev.append(line.split()[1])
                        break
                choose += 1
            choose_interface = int(input("Choose a number (e.g: 1): ")) - 1
            use_interface = airmon_dev[choose_interface]
        else:
            for interface in interfaces:
                for line in airmon_out.decode().split("\n"):
                    if interface in line:
                        airmon_dev.append(line.split()[1])
                        break
            use_interface = airmon_dev[0]

        print("Starting interface...")
        command = ["airmon-ng", "start", use_interface]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (start_out, err) = pg.communicate()
        print(start_out.decode())
        print("Interface should be in monitor mode now.")
        use_interface += "mon"

        mtu_value = "1800"
        print("Getting current MTU...")
        command = ["ifconfig"]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_out, err) = pg.communicate()
        mtu_current = ""
        for line in mtu_out.decode().split("\n"):
            if use_interface in line:
                mtu_current = line.split(" mtu ")[1].rstrip()
        print("Current MTU: " + mtu_current)
        print("Setting MTU to " + mtu_value + "...")
        command = ["ifconfig", use_interface, "mtu", mtu_value]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_set_out, err) = pg.communicate()
        command = ["ifconfig"]
        pg = subprocess.Popen(command, stdout=subprocess.PIPE)
        (mtu_out, err) = pg.communicate()
        print(mtu_out.decode())
        print("MTU should be set now.")

        original_mac = input("Please input the MAC-Address of your Nintendo console (e.g: a4:c0:e1:00:00:00): ")

        host = ""
        while host != "y" and host != "n":
            host = input("Are you the host of the group? [y/n] : ").lower()
        if host == "y":
            host = True
        else:
            host = False

        if host:
            print("Please turn on your Nintendo console and select the local mulitplayer option in your game.")
            input("Press Enter when you are done.")

            print("Scanning the area on every channel for 5 seconds...")
            list_channel = [str(x) for x in range(1, 13)]
            use_channel = ""
            for channel in list_channel:
                command = ["iw", use_interface, "set", "channel", channel]
                pg = subprocess.Popen(command, stdout=subprocess.PIPE)
                (iwchannel_out, err) = pg.communicate()
                print("Scanning channel " + channel + " now...")
                scan_pkts = sniff(iface=use_interface, timeout=5)
                for pkt in scan_pkts:
                    if pkt.haslayer(Dot11FCS):
                        if pkt.haslayer(Dot11EltCountry):
                            if pkt[Dot11].addr2.lower() == original_mac.lower():
                                pkt.show()
                                use_channel = channel
                                break
                if use_channel != "":
                    break
            print("Found channel.")
            print("Using channel " + use_channel + " now.")

            print("Which IP-Adrress do you want to use?")
            command = ["ifconfig"]
            pg = subprocess.Popen(command, stdout=subprocess.PIPE)
            (ifconf_out, err) = pg.communicate()
            choose = 1
            list_inet = []
            for line in ifconf_out.decode().split("\n"):
                if "inet" in line:
                    list_inet.append(line.split()[1])
                    print("[" + str(choose) + "] - " + line.split()[1])
                    choose += 1
            choose_ip = int(input("Choose an IP-Address (e.g: 1): ")) - 1
            addr = (list_inet[choose_ip], 7517)
            print("Starting proxy host...")
            sock = socket.create_server(addr)
            print("Started listening on " + str(addr[0]) + ":" + str(addr[1]))

            # proxy_mac = proxy_mac_in()
            # print("Using MAC-Address " + proxy_mac + " now.")

            print("Launch complete.")
            print("****************")
            print("Share this magic key with your friends:")
            key = get_random_bytes(16)
            magic_key = base64.b64encode(key).decode()
            print(magic_key)
            print("****************")

            conn, addr = sock.accept()
            print("Accepted connection from: " + str(addr))
            print("Starting to send and recieve packets...")
            _thread.start_new_thread(recv, (conn, key))
            _thread.start_new_thread(send, (conn, key))
            sniff(iface=use_interface, store=0, prn=send_pkt)

        else:
            # proxy_mac = proxy_mac_in()
            # print("Using MAC-Address " + proxy_mac + " now.")
            use_channel = ""

            choose_ip = input("Please enter the IP-Address you want to connect to (e.g: 127.0.0.1): ")
            addr = (choose_ip, 7517)

            print("Your friend needs to tell you a magic key in order to connect to the server.")
            magic_key = base64.b64decode(input("Please enter the magic key: "))

            sock = socket.create_connection(addr)
            print("Connected to: " + str(addr))
            print("Starting to send and recieve packets...")
            _thread.start_new_thread(recv, (sock, magic_key))
            _thread.start_new_thread(send, (sock, magic_key))
            sniff(iface=use_interface, store=0, prn=send_pkt)
except KeyboardInterrupt:
    print("Shutting down...")
    try:
        print("Stopping socket...")
        sock.close()
        print("Stopped socket.")
    except Exception:
        print("Socket wasn't defined yet.")
    print("Restoring MTU...")
    command = ["ifconfig", use_interface, "mtu", mtu_current]
    pg = subprocess.Popen(command, stdout=subprocess.PIPE)
    (mtu_set_out, err) = pg.communicate()
    print("MTU restored.")
    print("Stopping monitor mode...")
    command = ["airmon-ng", "stop", use_interface]
    pg = subprocess.Popen(command, stdout=subprocess.PIPE)
    pg.communicate()
    print("Stopped monitor mode.")
    print("Thanks for using my Nintendo proxy!")
    input("Press enter to close this window.")
    exit(0)
except Exception as e:
    print("Main failed. ", e)
    traceback.print_exc()
    print("Restoring MTU...")
    command = ["ifconfig", use_interface, "mtu", mtu_current]
    pg = subprocess.Popen(command, stdout=subprocess.PIPE)
    (mtu_set_out, err) = pg.communicate()
    print("MTU restored.")
    print("Stopping monitor mode...")
    command = ["airmon-ng", "stop", use_interface]
    pg = subprocess.Popen(command, stdout=subprocess.PIPE)
    pg.communicate()
    print("Stopped monitor mode.")
    input("Press enter to close this window")
    exit(1)
