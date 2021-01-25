# DHCPEyes :eyes:
**Intercept requests passively of DHCP from own network!**

<img
src="https://raw.githubusercontent.com/vincenzogianfelice/DHCPEyes/master/media/demo.png"
alt="DemoImage"
/>

# Authors
- **Vincenzo Gianfelice**
- **Contact**: _developer.vincenzog@gmail.com_
- **BTC**(donation): *3EwV4zt9r5o4aTHyqjcM6CfqSVirSEmN6y*

# Prerequisites
Require **python2.7** (also **python3.5**)

- scapy >= 2.4.4
- termcolor
- colorama (if you use **windows**)

###### Windows
- First, install [WinPcap](https://www.winpcap.org/install/)
- After installed winpcap, run file exe after [downloaded](https://github.com/vincenzogianfelice/DHCPEyes/releases)
- For searching interfaces on Windows, digit in prompt ```netsh interface show interfaces```, and copy the 4 column (```Nome interfaccia```/```Name interface```)

# Installation
```
pip2 install -r requirements.txt
```

# Usage
```
    ____  __  ____________  ______
   / __ \/ / / / ____/ __ \/ ____/_  _____  _____
  / / / / /_/ / /   / /_/ / __/ / / / / _ \/ ___/
 / /_/ / __  / /___/ ____/ /___/ /_/ /  __(__  )
/_____/_/ /_/\____/_/   /_____/\__, /\___/____/
                              /____/

        * Passive DHCP Listener! (v1.2) *

Usage: ./dhcpeyes.py -i <interface>

     -i        Interface for listening
Optional:
     -o <arg>  File Output Save
     -t <arg>  Options types: DHCPD  (discover)
                              DHCPR  (request)
                              DHCPN  (nak)
                              DHCPI  (inform)
               Default print all options
```

#### Examples
```
./dhcpeyes.py -i wlan0 -t DHCPR              # Intercept only DHCPREQUEST on wlan0
./dhcpeyes.py -t DHCPI -i wlan0 -t DHCPD     # Intercept DHCPINFORM and DHCPDISCOVER
./dhcpeyes.py -i wlan0                       # Intercept all
```

###### Windows
```
./dhcpeyes.py -i "Connessione alla rete locale (LAN)" -t DHCPR  # Using "Connessione alla rete locale (LAN)" provided from output of command netsh
```
