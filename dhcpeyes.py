#!/usr/bin/env python2.7
import base64
import sys
import time
from termcolor import colored
from scapy.all import *
from os import getuid

LOGO='ICAgIF9fX18gIF9fICBfX19fX19fX19fX18gIF9fX19fXyAgICAgICAgICAgICAgIAogICAvIF9fIFwvIC8gLyAvIF9fX18vIF9fIFwvIF9fX18vXyAgX19fX18gIF9fX19fCiAgLyAvIC8gLyAvXy8gLyAvICAgLyAvXy8gLyBfXy8gLyAvIC8gLyBfIFwvIF9fXy8KIC8gL18vIC8gX18gIC8gL19fXy8gX19fXy8gL19fXy8gL18vIC8gIF9fKF9fICApIAovX19fX18vXy8gL18vXF9fX18vXy8gICAvX19fX18vXF9fLCAvXF9fXy9fX19fLyAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC9fX19fLyAgICAgICAgICAgICAK'

def help():
    print 'Usage: {} -i <interface>'.format(sys.argv[0])
    print ''
    print 'Optional:'
    print '     -o <arg>  File Output Save'
    print '     -t <arg>  REQUEST types: DHCPR (request),  DHCPD (discover)'

def dhcp_discover(pkts):
    data=list()
    for ex in pkts.getlayer(DHCP).options:
        if 'hostname' in ex:
            data.append(('hostname', ex[1]))
        elif 'vendor_class_id' in  ex:
            data.append(('vendor_class_id', ex[1]))

    return data

def dhcp_request(pkts):
    data=list()
    for ex in pkts.getlayer(DHCP).options:
        if 'requested_addr' in ex:
            data.append(('requested_addr', ex[1]))
        elif 'server_id' in ex:
            data.append(('server_id', ex[1]))
        elif 'vendor_class_id' in ex:
            data.append(('vendor_class_id', ex[1]))
        elif 'hostname' in ex:
            data.append(('hostname', ex[1]))

    return data

def show_data(pkts):
    data=list()
    mac=pkts.getlayer(Ether).src
    ip='???'
    vendor_class_id='???'
    ip_server_dhcp='???'
    hostname='???'

    type_request=pkts.getlayer(DHCP).options[0][1]

    ##KEY VALUE FOR PRINT##
    k_addr=colored('addr', 'yellow', attrs=['bold'])
    k_host=colored('host', 'yellow', attrs=['bold'])

    if type_request == 1:
        if (type_dhcp == 'DHCPD' or not type_dhcp):
            data=dhcp_discover(pkts)
    elif type_request == 3:
        if (type_dhcp == 'DHCPR' or not type_dhcp):
            data=dhcp_request(pkts)

    if (data):
        for ex in data:
            if 'requested_addr' in ex:
                ip=ex[1]
            elif 'server_id' in ex:
                ip_server_dhcp=ex[1]
            elif 'vendor_class_id' in ex:
                vendor_class_id=ex[1]
            elif 'hostname' in ex:
                hostname=ex[1]

    if (file_out):
        with open(file_out,'a+') as fd:
            if (type_request==1 and type_dhcp == 'DHCPD' or not type_dhcp):
                t='DISCOVER'
            elif (type_request==3 and type_dhcp == 'DHCPR' or not type_dhcp):
                t='REQUEST'
            else:
                return

            fd.write('{}: {} server_dhcp={} mac={} vendor={} address={} hostname={}'.format(time.strftime("%d-%m-%y-%H-%M"), t, ip_server_dhcp, mac, vendor_class_id, ip, hostname))
            fd.write('\n')

    if (type_request == 1 and (type_dhcp == 'DHCPD' or not type_dhcp)):
        print '[{}] DHCP DISCOVER ({} ({})) {}: {}'.format(time.strftime("%d/%m/%y %H:%M"), mac, vendor_class_id, k_host, hostname)
    elif (type_request == 3 and (type_dhcp == 'DHCPR' or not type_dhcp)):
        print '[{}] DHCP REQUEST ({}) CLIENT -> [{} ({})]: {}: {} {}: {}'.format(time.strftime("%d/%m/%y %H:%M"), colored(ip_server_dhcp,'blue',attrs=['bold']), mac, vendor_class_id, k_addr, ip, k_host, hostname)

if __name__ == '__main__':
    interface=None
    type_dhcp=None
    file_out=None

    print base64.b64decode(LOGO)
    print '\t* DHCP Passive Listener! *'
    print

    
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
    if (getuid() != 0):
        print 'Please run as root'
        sys.exit(1)

    sniff(iface=interface, prn=show_data,store=False, filter=('udp port 67 and port 68'))
