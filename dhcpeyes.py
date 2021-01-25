#!/usr/bin/env python2.7
## Coded by vincenzogianfelice <developer.vincenzog@gmail.com> with <3
import base64
import sys
import time
import os
from termcolor import colored
from scapy.all import Ether, DHCP, IP, sniff
if (os.name == 'nt'):
    import colorama
    colorama.init()

# Variabili costanti
VERSION = 'v1.2'

# DHCP Message Type - RFC2132/Page-4 (https://tools.ietf.org/html/rfc2132#page-4) ##
# Per il momento, non verranno utilizzate tutti i "tipi", dato che il client, una volta stabilito il server di destinazione DHCP,
# invia direttamente i pacchetti a quest'ultimo (e non in broadcast), rendendo inefficace l intercettazione
# in modo passivo.
# Presto verra' aggiunta la possibilita' di intercettare le richieste/risposte tra il client/server (MITM)
# Stay Tuned! ;)
DHCPDISCOVER = 1    # Used
DHCPOFFER = 2       # No
DHCPREQUEST = 3     # Used
DHCPDECLINE = 4     # No
DHCPACK = 5         # No
DHCPNAK = 6         # Used
DHCPRELEASE = 7     # No
DHCPINFORM = 8      # Used

# DHCPOptions of Scapy
# (https://github.com/secdev/scapy/blob/master/scapy/layers/dhcp.py)
# `at line 112`. Actual version of scapy is 2.4.4.
MESSAGE_DHCP = 'message-type'
ERROR_MESSAGE = 'error_message'
REQUEST_ADDRESS = 'requested_addr'
ADDRESS_SERVER_DHCP = 'server_id'
VENDOR = 'vendor_class_id'
HOSTNAME = 'hostname'

# Variabili globali per lo script
REQUESTED = list()      # Dispositivi totali connessi alla rete (tramite DHCP)
TOT_DEVICES = list()    # Dispositivi totali catturati

def logo():
    LOGO = 'ICAgIF9fX18gIF9fICBfX19fX19fX19fX18gIF9fX19fXyAgICAgICAgICAgICAgIAogICAvIF9fIFwvIC8gLyAvIF9fX18vIF9fIFwvIF9fX18vXyAgX19fX18gIF9fX19fCiAgLyAvIC8gLyAvXy8gLyAvICAgLyAvXy8gLyBfXy8gLyAvIC8gLyBfIFwvIF9fXy8KIC8gL18vIC8gX18gIC8gL19fXy8gX19fXy8gL19fXy8gL18vIC8gIF9fKF9fICApIAovX19fX18vXy8gL18vXF9fX18vXy8gICAvX19fX18vXF9fLCAvXF9fXy9fX19fLyAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC9fX19fLyAgICAgICAgICAgICAK'

    print(base64.b64decode(LOGO).decode('ascii'))
    print('\t* Passive DHCP Listener! ('+VERSION+') *')
    print('')

def help():
    print('Usage: {} -i <interface>'.format(sys.argv[0]))
    print('')
    print('     -i        Interface for listening')
    print('Optional:')
    print('     -o <arg>  File Output Save')
    print('     -t <arg>  Options types: DHCPD  (discover)')
    print('                              DHCPR  (request)')
    print('                              DHCPN  (nak)')
    print('                              DHCPI  (inform)')
    print('               Default print all options')

    if (os.name == 'nt'):
        print('')
        print('')
        print('(PS). In Windows, digit "netsh interface show interface" for show the names of interfaces')

def dhcp_options_search(pkts):
    data = [pkts.getlayer(DHCP).options[0][1]]
    for ex in pkts.getlayer(DHCP).options:
        if REQUEST_ADDRESS in ex:
            data.append((REQUEST_ADDRESS, ex[1]))
        elif ADDRESS_SERVER_DHCP in ex:
            data.append((ADDRESS_SERVER_DHCP, ex[1]))
        elif VENDOR in ex:
            data.append((VENDOR, ex[1]))
        elif HOSTNAME in ex:
            data.append((HOSTNAME, ex[1]))
        elif ERROR_MESSAGE in ex:
            data.append((ERROR_MESSAGE, ex[1]))
    return data

def parser_packet(pkts):
    if (not pkts):
        return

    mac_addr = pkts.getlayer(Ether).src
    ip_src = pkts.getlayer(IP).src
    ip_dst = pkts.getlayer(IP).dst
    address = '???'
    vendor = '???'
    address_server_dhcp = '???'
    hostname = '???'
    error_msg = '???'

    data = dhcp_options_search(pkts)
    if (not data):
        return

    TOT_DEVICES.append(mac_addr)
    type_option = data[0]

    del data[0]

    time_capture = tuple(time.localtime())
    # Check in base al valore dell'opzione '-t' e/o dal tipo di pacchetto
    # in entrata
    if type_option == DHCPDISCOVER and ('DHCPD' in type_dhcp or not type_dhcp):
        option_dhcp = 'DHCPDISCOVER'
        format_syntax = '[%s] %s (%s (%s)) %s: %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), option_dhcp, mac_addr, vendor, colored(\'host\', \'yellow\', attrs=[\'bold\']), hostname)'
    elif type_option == DHCPREQUEST and ('DHCPR' in type_dhcp or not type_dhcp):
        REQUESTED.append(mac_addr)

        option_dhcp = colored('DHCPREQUEST', 'white', attrs=['bold'])
        format_syntax = '[%s] %s (%s) CLIENT -> [%s (%s)] %s: %s %s: %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), option_dhcp, colored(address_server_dhcp, \'blue\', attrs=[\'bold\']), mac_addr, vendor, colored(\'addr\', \'yellow\', attrs=[\'bold\']), address, colored(\'host\', \'yellow\', attrs=[\'bold\']), hostname)'
    elif type_option == DHCPNAK and ('DHCPN' in type_dhcp or not type_dhcp):
        option_dhcp = 'DHCPNAK'
        format_syntax = '[%s] %s (%s from %s) (%s) via %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), colored(option_dhcp, \'red\', attrs=[\'bold\']), mac_addr, colored(ip_src, \'blue\', attrs=[\'bold\']), error_msg, ip_dst)'
    elif type_option == DHCPINFORM and ('DHCPI' in type_dhcp or not type_dhcp):
        option_dhcp = 'DHCPINFORM'
        format_syntax = '[%s] %s [%s (%s)] %s: %s %s: %s'
        value_syntax = '(time.strftime("%d/%m/%y %H:%M",time_capture), option_dhcp, mac_addr, vendor, colored(\'addr\', \'yellow\', attrs=[\'bold\']), ip_src, colored(\'host\', \'yellow\', attrs=[\'bold\']), hostname)'
    else:
        return

    for ex in data:
        if REQUEST_ADDRESS in ex:
            address = ex[1]
        elif ADDRESS_SERVER_DHCP in ex:
            address_server_dhcp = ex[1]
        elif VENDOR in ex:
            vendor = ex[1].decode('utf8')
        elif HOSTNAME in ex:
            hostname = ex[1].decode('utf8')
        elif ERROR_MESSAGE in ex:
            error_msg = ex[1].decode('utf8')

        if (file_out):
            with open(file_out, 'a+') as fd:
                fd.write('{}: {} server_dhcp={} mac={} vendor={} address={} hostname={} errorr_msg={}'.format(time.strftime("%d-%m-%y-%H-%M", time_capture), option_dhcp, address_server_dhcp, mac_addr, vendor, address, hostname, error_msg))
                fd.write('\n')

    print((format_syntax) % eval(value_syntax))

if __name__ == '__main__':
    interface = None
    type_dhcp = list()
    file_out = None

    logo()

    op = sys.argv[1::2]
    val = sys.argv[2::2]
    if (len(sys.argv) < 2 or len(op) != len(val)):
        help()
        sys.exit(1)

    # Semplice parsing delle opzioni da input
    i = 0
    for o in op:
        if (o == '-o'):
            file_out = val[index_op]
        elif (o == '-t'):
            if val[i] != 'DHCPD' and val[i] != 'DHCPR' and val[i] != 'DHCPN' and val[i] != 'DHCPI':
                help()
                sys.exit(1)

            type_dhcp.append(val[i])
        elif (o == '-i'):
            interface = val[i]
        i += 1

    # Check root permissions
    if (os.name == 'posix'):
        if (os.getuid() != 0):
            print('Please run as root')
            sys.exit(1)

    start = time.time()
    sniff(iface=interface, prn=parser_packet, store=False, filter=('udp port 67 and port 68'))
    end = time.time()-start

    if (end < 60):
        who_time = '{} seconds'.format(int(end))
    elif (end >= 60 and end < 3600):
        who_time = '{} minutes'.format(int(end/60))
    else:
        who_time = '{} hours'.format(int(end/3600))

    print('')
    print('\r[+] {}: {} devices ({} {})'.format(who_time,
                                            len(set(TOT_DEVICES)),
                                            len(set(REQUESTED)),
                                            colored('connected', 'yellow', attrs=['bold'])))
