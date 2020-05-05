# Local test proxy for Nintendo local multiplayer (adhoc)

## Content:

  -  <a href="#what">What does it do?</a>
    - <a href="#server">Server Mode</a>
    - <a href="#cleint">Client Mode</a>
  - <a href="#how">How does it work?</a>
  - <a href="#setup">Setup</a>
    - <a href="#requirements">Requirements</a>
      - <a href="#hardware">Hardware and OS Requirements</a>
      - <a href="#linux">Linux packages</a>
      - <a href="#python">Python packages</a>
  - <a href="#local-setup">My own testing setup</a>
  - <a href="#todo">TODO</a>

## What does it do? {#what}

### Server-mode {#server}
The host of the game creates a socketserver with an encryption key and sets the mac of the console.
The script scans for the specific channel that the Nintendo is sending on and configures the wireless device.
The MTU gets raised to 1800 because some Nintendo packets were too big and caused Errno 90.

### Client-mode {#client}
First the client needs to set the mac address of the console, so no other traffic gets redirected.
The client connects to the socket of the host and needs to enter the generated encryption key.
As soon as the connection is established both Server and Client start sniffing and sending packets.
The client will use the channel that the host is using as well.

## How does it do that? {#how}

I am using Python3 Scapy in order to sniff and send packets via the wireless device.

The script uses linux commands like:
  - ifconfig (setting the mtu to 1800)
  - iw (searching for devices with monitor mode)
  - airmon-ng (setting the device to monitor mode)

I know I don't really need to use airmon-ng for that but it is a handy shortcut and I like it.
After we configured the wireless device we can use it to capture packets and send them to the client.
In order to do that I am using sockets and pycryptodome AES_GCM ( + some json and base64) to establish a secure connection between host and client.
I don't want to send all the packets that we are picking up so the script filters everything out that is not from the nintendo mac address.

But as we do that sometimes the compare fails as there is no source address set in some packets and at the moment I log these packets to see if they are related to local multiplayer stuff.
Until now I never saw a Nintendo packet in the log so I am quite sure that this is fine and I can ignore it.

And that's it! (At the moment)

## Setup {#setup}

### Requirements {#requirements}

#### Hardware and OS {#hardware}

  - Wifi adapter with monitor mode
  - Another method (probably lan) in order to connect to host/client
  - Linux (I am sure it works with Debian/Ubuntu as I am using it but other distros should work too)

#### Linux Requirements {#linux}
  
  - net-tools (ifconfig)
  
  > sudo apt install net-tools
  
  - aircrack-ng (airmon-ng)
  
  > sudo apt install aircrack-ng
  
One line:

> sudo apt install net-tools aircrack-ng -y
  
#### Python Requirements {#python}

  - Python 3.8 (because I am using socket.create_server which was added in 3.8)
  - Scapy
    
    > python3.8 -m pip install scapy
    
  - PyCryptoDome
  
    > python3.8 -m pip install pycryptodome

One line:

> python3.8 -m pip install scapy pycryptodome

## My local testing setup: {#local-setup}

  - 1 Ubuntu x64 pc (for development and controlling ssh sessions)
    - connected via LAN
  - 1 Raspberry Pi 4 with an additional wifi-adapter (host, controlled via ssh)
    - uses LAN connection to talk to client and dev
  - 1 Ubuntu x64 Laptop (client, controlled via ssh)
    - uses LAN connection to talk to client and dev
  - 2 Nintendo 3DS (local multiplayer)
    - seperated from each other
    - one is the host and the other is searching for players to join
    - I figured adhoc hasn't changed and Nintendo still uses it so if it works with this setup every Nintendo console should work that supports adhoc mode.

## TODO: {#todo}

- [x] Proxy traffic from host to client console
- [ ] Find out how Nintendo discovers other local multiplayer hosts
- [ ] Find a way to make it happen with this script
- [ ] Make this script more stable (crashes should always set everything to normal state)
- [ ] add command line arguments (testing feels so slow without it)
- [ ] add Windows support (will be hard as there will be a lot of problems with monitor mode)
- [ ] Do you even write AES_GCM and sockets that way??
