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
import dpctlutils as dpctl

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

def test_set_init(config):
    """
    Set up function for dpctl based test classes using OXM format

    @param config The configuration dictionary; see oft
    """

    global pa_port_map
    global pa_logger
    global pa_config

    pa_logger = logging.getLogger("dpctltests")
    pa_logger.info("Initializing test set")
    pa_port_map = config["port_map"]
    pa_config = config


TEST_VID_DEFAULT = 2
# TESTS
class MatchIPv4Simple(basic.SimpleDataPlane):
    """
    Just send a packet IPv4 / TCP thru the switch
    """
    def runTest(self):
        
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[3]
        
        # Remove all entries Add entry match all
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")

        # Add entry match all
        flow_match = "dl_type=0x0800,nw_src=192.168.0.1"
        flow_acts = "apply:output=" + str(egr_port)
        rc = dpctl.oxm_send_flow_mod_add(flow_match,flow_acts,pa_logger)
        self.assertEqual(rc, 0, "Failed to add flow entry")

        #Send packet
        pkt = testutils.simple_tcp_packet()
        pa_logger.info("Sending IPv4 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))
        
        #Receive packet
        exp_pkt = testutils.simple_tcp_packet()
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #See flow match
        dpctl.request_flow_stats()
        
        #Remove flows
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")


#
class MatchIPv4SetField(basic.SimpleDataPlane):
    """
    Set the tp_src field of a IPv4 / TCP packet  
    """
    def runTest(self):
        
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[3]
        
        # Remove all entries Add entry match all
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")

        # Add entry match all
        flow_match = "dl_type=0x0800,nw_src=192.168.0.1"
        flow_acts = "apply:set_field=tp_src=12,output=" + str(egr_port)
        rc = dpctl.oxm_send_flow_mod_add(flow_match,flow_acts,pa_logger)
        self.assertEqual(rc, 0, "Failed to add flow entry")

        #Send packet
        pkt = testutils.simple_tcp_packet()
        pa_logger.info("Sending IPv4 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))
        
        #Receive packet
        exp_pkt = testutils.simple_tcp_packet(tcp_sport=12)
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #See flow match
        dpctl.request_flow_stats()
        
        #Remove flows
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")


class MatchIPv6Simple(basic.SimpleDataPlane):
    """
    Just send a packet IPv6 to match a simple entry on the matching table
    """
    def runTest(self):
        
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[3]
        
        # Remove all entries Add entry match all
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")

        # Add entry match 
        flow_match = "dl_type=0x86DD,nw_src_ipv6=fe80::2420:52ff:fe8f:5189"
        flow_acts = "apply:output=" + str(egr_port)
        rc = dpctl.oxm_send_flow_mod_add(flow_match,flow_acts,pa_logger)
        self.assertEqual(rc, 0, "Failed to add flow entry")

        #Send packet
        pkt = dpctl.simple_ipv6_packet(EH = True)
        pa_logger.info("Sending IPv6 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))
        
        #Receive packet
        exp_pkt = dpctl.simple_ipv6_packet(EH = True)
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #See flow match
        dpctl.request_flow_stats()
        
        #Remove flows
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")


class InPortMatch(basic.SimpleDataPlane):
    """
    Just match an IPv4 packet thru the switch
    """
    def runTest(self):

        # Config
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[1]
        
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")

        flow_match = "in_port=" + str(ing_port)
        flow_acts = "apply:output=" + str(egr_port)
        rc = dpctl.oxm_send_flow_mod_add(flow_match,flow_acts,pa_logger)
        self.assertEqual(rc, 0, "Failed to add flow entry")
        
        pkt = testutils.simple_tcp_packet()
        
        pa_logger.info("Sending IPv4 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))

        pkt = testutils.simple_tcp_packet()
        pa_logger.info("Sending IPv4 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))
        
        exp_pkt = testutils.simple_tcp_packet()
        
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #See flow match
        dpctl.request_flow_stats()
        
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")


class SanityCheck(basic.SimpleDataPlane):
    """
    Check if a flow mod with non-consistent fields is installed or not
    """
    def runTest(self):

        # Config
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[3]
        
        # Remove flows
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")

        # Add entry with invalid arguments (wrong dl_type for a IPv4 packet)
        flow_match = "dl_type=0x7000,nw_src=192.168.0.1"
        flow_acts = "apply:output=" + str(egr_port)
        rc = dpctl.oxm_send_flow_mod_add(flow_match,flow_acts,pa_logger)
        self.assertEqual(rc, 0, "Failed to add flow entry")
       
	
        #Send IPv4 packet 

        pkt = testutils.simple_tcp_packet()

        pa_logger.info("Sending IPv4 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))

        pkt = testutils.simple_tcp_packet()
        pa_logger.info("Sending IPv4 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))
        
        #Should not receive packet
        exp_pkt = testutils.simple_tcp_packet()
	testutils.receive_pkt_check(self.dataplane, exp_pkt, [], of_ports, self,
                              pa_logger)

        #See flow match
        dpctl.request_flow_stats()

        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")


class MatchTCPSrc(basic.SimpleDataPlane):

    def runTest(self):
        	# Config
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port =   of_ports[3]
        
        # Remove flows
        rc = dpctl.oxm_delete_all_flows()
        self.assertEqual(rc, 0, "Failed to delete all flows")

        # Add entry match all 
        flow_match = "in_port=1,tp_src=80"
        flow_acts = "apply:output=" + str(egr_port)

        rc = dpctl.oxm_send_flow_mod_add(flow_match,flow_acts,pa_logger)
        self.assertEqual(rc, 0, "Failed to add flow entry")

        #Send packet
        pkt = dpctl.simple_ipv6_packet(tcp_sport=80, tcp_dport=8080) 

        print "Sending IPv6 packet to " + str(ing_port)
        pa_logger.info("Sending IPv6 packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        
        self.dataplane.send(ing_port, str(pkt))

        #Receive packet
        exp_pkt = dpctl.simple_ipv6_packet(tcp_sport=80, tcp_dport=8080) 

        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #See flow match
        dpctl.request_flow_stats()
        
        #Remove flows
        rc = dpctl.oxm_delete_all_flows()        
        self.assertEqual(rc, 0, "Failed to delete all flows")


class PacketOnlyIPv6HBHandDO(basic.DataPlaneOnly):
    """
    Just send an IPv6 packet with HBHandDO EHs thru the switch
    """
    def runTest(self):
        
        pkt = dpctl.simple_ipv6_packet(EH = True,  EHpkt = scapy.IPv6ExtHdrHopByHop()/scapy.IPv6ExtHdrDestOpt()) 
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        pa_logger.info("Sending IPv6 packet with HBHandDO EHs to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))
        
#        exp_pkt = dpctl.simple_ipv6_packet(EH = True,  EHpkt = scapy.IPv6ExtHdrHopByHop()/scapy.IPv6ExtHdrDestOpt())
        
#        testutils.receive_pkt_verify(self, ing_port, exp_pkt)


if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test-spec=dpctltests"

