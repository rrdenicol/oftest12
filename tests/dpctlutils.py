"""
Test cases for testing actions taken on packets

See basic.py for other info.

It is recommended that these definitions be kept in their own
namespace as different groups of tests will likely define 
similar identifiers.

  The function test_set_init is called with a complete configuration
dictionary prior to the invocation of any tests from this file.

  The switch is actively attempting to contact the controller at the address
indicated oin oft_config

"""



import logging


import oftest.cstruct as ofp
import oftest.message as message
import oftest.action as action
import oftest.parse as parse
import oftest.instruction as instruction
import basic
#import pktact
#import oftest.controller as controller

import testutils

#Import scappy packet generator
try:
    import scapy.all as scapy
except:
    try:
        import scapy as scapy
    except:
        sys.exit("Need to install scapy for packet parsing")


import os.path
import subprocess

#@var port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
pa_port_map = None
#@var pa_logger Local logger object
pa_logger = None
#@var pa_config Local copy of global configuration data
pa_config = None

# For test priority
#@var test_prio Set test priority for local tests
test_prio = {}

# Cache supported features to avoid transaction overhead
cached_supported_actions = None

TEST_VID_DEFAULT = 2

def test_set_init(config):
    """
    Set up function for IPv6 packet handling test classes

    @param config The configuration dictionary; see oft
    """

    global pa_port_map
    global pa_logger
    global pa_config

    pa_logger = logging.getLogger("ipv6")
    pa_logger.info("Initializing test set")
    pa_port_map = config["port_map"]
    pa_config = config

# chesteve: IPv6 packet gen
def simple_ipv6_packet(pktlen=1000, 
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='fe80::2420:52ff:fe8f:5189',
                      ip_dst='fe80::2420:52ff:fe8f:5190',
                      ip_tos=0,
                      tcp_sport=0,
                      tcp_dport=0, 
                      EH = False, 
                      EHpkt = scapy.IPv6ExtHdrDestOpt()
                      ):

    """
    Return a simple dataplane IPv6 packet 

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IPv6 source
    @param ip_dst IPv6 destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port

    Generates a simple TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """
    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = scapy.Ether(dst=dl_dst, src=dl_src)/ \
            scapy.Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            scapy.IP(src=ip_src, dst=ip_dst, tos=ip_tos)

    else:
        pkt = scapy.Ether(dst=dl_dst, src=dl_src)/ \
            scapy.IPv6(src=ip_src, dst=ip_dst)

    # Add IPv6 Extension Headers 
    if EH:
        pkt = pkt / EHpkt

    if (tcp_sport >0 and tcp_dport >0):
        pkt = pkt / scapy.TCP(sport=tcp_sport, dport=tcp_dport)

    pktlen = len(pkt) # why??
    pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def oxm_send_flow_mod_add(flow_match,flow_acts,logger):
    """
    Send a flow mod with the oxm operation mode
    """

    of_dir = os.path.normpath("../../of11softswitchv6")
    ofd = os.path.normpath(of_dir + "/udatapath/ofdatapath")
    dpctl = os.path.normpath(of_dir + "/utilities/dpctl")
    dpctl_switch = "unix:/tmp/ofd"

    flow_cmd1 = "flow-mod"
    flow_cmd2 = "cmd=add,table=0,idle=100"

    pcall = [dpctl, dpctl_switch, flow_cmd1, flow_cmd2, flow_match,  flow_acts]
    #print pcall
    rv = subprocess.call(pcall)

    return rv

def oxm_delete_all_flows():
    of_dir = os.path.normpath("../../of11softswitchv6")
    ofd = os.path.normpath(of_dir + "/udatapath/ofdatapath")
    dpctl = os.path.normpath(of_dir + "/utilities/dpctl")
    dpctl_switch = "unix:/tmp/ofd"

    flow_cmd1 = "flow-mod"
    flow_cmd4 = "cmd=del,table=0"
    pcall = [dpctl, dpctl_switch, flow_cmd1, flow_cmd4]
    rv = subprocess.call(pcall) 

    return rv

def request_flow_stats():

    of_dir = os.path.normpath("../../of11softswitchv6")
    ofd = os.path.normpath(of_dir + "/udatapath/ofdatapath")
    dpctl = os.path.normpath(of_dir + "/utilities/dpctl")
    dpctl_switch = "unix:/tmp/ofd"

    pa_logger.debug("Request stats-flow")  
    pcall = [dpctl, dpctl_switch, "stats-flow"]  #  
    #subprocess.call(pcall)

if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test-spec=ipv6"
