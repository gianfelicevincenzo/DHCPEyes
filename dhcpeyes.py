#!/usr/bin/env python2.7
#  Coded by vincenzogianfelice <developer.vincenzog@gmail.com> with <3
VERSION='v1.0'

import base64
import sys
import time
import os
from termcolor import colored
from scapy.all import Ether,IP,DHCP,sniff

## DHCP Message Type - RFC2132/Page-4 (https://tools.ietf.org/html/rfc2132#page-4) ##
## Per il momento, verranno utilizzati solo DHCPREQUEST e DHCPDISCOVER.
## Presto verra' aggiunta la possibilita' di intercettare il DHCPOFFER
## Stay Tuned! ;)
DHCPDISCOVER=1
DHCPOFFER=2
DHCPREQUEST=3
DHCPDECLINE=4
DHCPACK=5
DHCPNAK=6
DHCPRELEASE=7
DHCPINFORM=8

## DHCPOptions of Scapy
## (https://github.com/secdev/scapy/blob/master/scapy/layers/dhcp.py)
## `at line 112`. Actual version of scapy is 2.4.4.
MESSAGE_DHCP='message-type'
REQUEST_ADDRESS='requested_addr'
ADDRESS_SERVER_DHCP='server_id'
VENDOR='vendor_class_id'
HOSTNAME='hostname'

def logo():
    LOGO='ICAgIF9fX18gIF9fICBfX19fX19fX19fX18gIF9fX19fXyAgICAgICAgICAgICAgIAogICAvIF9fIFwvIC8gLyAvIF9fX18vIF9fIFwvIF9fX18vXyAgX19fX18gIF9fX19fCiAgLyAvIC8gLyAvXy8gLyAvICAgLyAvXy8gLyBfXy8gLyAvIC8gLyBfIFwvIF9fXy8KIC8gL18vIC8gX18gIC8gL19fXy8gX19fXy8gL19fXy8gL18vIC8gIF9fKF9fICApIAovX19fX18vXy8gL18vXF9fX18vXy8gICAvX19fX18vXF9fLCAvXF9fXy9fX19fLyAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC9fX19fLyAgICAgICAgICAgICAK'

    print(base64.b64decode(LOGO).decode('ascii'))
    print('\t* DHCP Passive Listener! ('+VERSION+') *')
    print('')

def help():
    print('Usage: {} -i <interface>'.format(sys.argv[0]))
    print
    print('Optional:')
    print('     -o <arg>  File Output Save')
    print('     -t <arg>  REQUEST types: DHCPR (request),  DHCPD (discover)')

def dhcp_options_search(pkts):
    data=[pkts.getlayer(DHCP).options[0][1]]
    for ex in pkts.getlayer(DHCP).options:
        if REQUEST_ADDRESS in ex:
            data.append((REQUEST_ADDRESS, ex[1]))
        elif ADDRESS_SERVER_DHCP in ex:
            data.append((ADDRESS_SERVER_DHCP, ex[1]))
        elif VENDOR in ex:
            data.append((VENDOR, ex[1]))
        elif HOSTNAME in ex:
            data.append((HOSTNAME, ex[1]))

    return data

def parser_packet(pkts):
    mac_addr=pkts.getlayer(Ether).src
    address='???'
    vendor='???'
    address_server_dhcp='???'
    hostname='???'

    data=dhcp_options_search(pkts)

    type_option=data[0]
    del data[0]

    ## Check in base al valore dell'opzione '-t' e dal tipo di pacchetto
    ## in entrata
    if type_option == DHCPDISCOVER and (type_dhcp == 'DHCPD' or not type_dhcp):
        option_dhcp='DHCPDISCOVER'
    elif type_option == DHCPREQUEST and (type_dhcp == 'DHCPR' or not type_dhcp):
        option_dhcp='DHCPREQUEST'
    else:
        return

    time_capture=time.strftime("%d/%m/%y %H:%M")
    for ex in data:
        if REQUEST_ADDRESS in ex:
            address=ex[1]
        elif ADDRESS_SERVER_DHCP in ex:
            address_server_dhcp=ex[1]
        elif VENDOR in ex:
            vendor=ex[1].decode('utf8')
        elif HOSTNAME in ex:
            hostname=ex[1].decode('utf8')

    if (file_out):
        with open(file_out,'a+') as fd:
            fd.write('{}: {} server_dhcp={} mac={} vendor={} address={} hostname={}'.format(time_capture, option_dhcp, address_server_dhcp, mac_addr, vendor, address, hostname))
            fd.write('\n')

    if (type_option == DHCPDISCOVER):
        output_format='[{}] {} ({} ({})) {}: {}'.format(time_capture,
                                                        option_dhcp,
                                                        mac_addr,
                                                        vendor,
                                                        colored('host', 'yellow', attrs=['bold']),
                                                        hostname)
    elif (type_option == DHCPREQUEST):
        output_format='[{}] {} ({}) CLIENT -> [{} ({})] {}: {} {}: {}'.format(time_capture,
                                                                              option_dhcp,
                                                                              colored(address_server_dhcp, 'blue', attrs=['bold']),
                                                                              mac_addr,
                                                                              vendor,
                                                                              colored('addr', 'yellow', attrs=['bold']),
                                                                              address,
                                                                              colored('host', 'yellow', attrs=['bold']),
                                                                              hostname)

    print(output_format)

if __name__ == '__main__':
    interface=None
    type_dhcp=None
    file_out=None

    logo()

    op=sys.argv[1::2]
    val=sys.argv[2::2]
    if (len(sys.argv) < 2 or len(op) != len(val)):
        help()
        sys.exit(1)

    for o in op:
        index_op=op.index(o)
        if ( o == '-o' ):
            file_out=val[index_op]
        elif ( o == '-t' ):
            type_dhcp=val[index_op]
            if type_dhcp != 'DHCPR' and type_dhcp != 'DHCPD':
                help()
                sys.exit(1)
        elif ( o == '-i'):
            interface=val[index_op]

    ## Check root permissions
    if (os.name != 'win32'):
        if (os.getuid() != 0):
            print('Please run as root')
            sys.exit(1)

    sniff(iface=interface, prn=parser_packet, store=False, filter=('udp port 67 and port 68'))
