# Nifi-Proxy
Attempt to proxy the nifi-traffic to another place but failed | understanding how nifi works

## What is the goal of this project?

I want to understand how Nintendo uses adhoc networks to setup local multiplayer sessions.
In order to challenge my (non-existent) knowledge I want to create a proxy that allows me to play with my friends if they are a room away from me.
This proxy should be able to pick up every Nintendo packet from my console and send it to the other console via LAN and a wifi-adapter.

## What do I know now?

  - The host console creates an adhoc network on a specific channel (often 11 or 6)
  - Broadcast packets contain information about the Nintendo Adhoc Wifi with country JP
  - Beacon frames and data frames are sent all the time while the host is active
  - The client sets the host mac as addr3 (bssid) in order to connect to the adhoc network
  - While in game the host sends everything to broadcast
  - While in game the client sends everything to broadcast with addr3/bssid of the host console
  
## What do I need to figure out?

  - [ ] Are the packets perfectly replicated by the wifi-adapter?
  - [ ] Is the linux kernel messing with my packets?
  - [ ] How does the client discover potential hosts?
  
## Further reading:

If you want to read more about my progress, head over to the test-proxy dir. There will be another Readme.md which contains more information about my current progress.
