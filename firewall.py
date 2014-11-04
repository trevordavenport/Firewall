#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import struct
import socket

class Firewall:
    """
    Firewall class.
    Extend this to implement some firewall functionality.
    Don't change the name or anything -- the eecore component
    expects it to be firewall.Firewall.
    """
    def __init__(self, config, timer, iface_int, iface_ext):
    """
    Constructor
    """
    self.timer = timer
    self.iface_int = iface_int
    self.iface_ext = iface_ext
	self.udp_rules = []
	self.tcp_rules = []
	self.icmp_rules = []
	self.dns_rules = []

	all_rules = open(config['rule'], 'r')
	rules = all_rules.read().strip().split('\n')

	#Parse through rules
	i = 0
	while i < len(rules):
	    #Example: ['pass', 'tcp', 'any', 'any']
	    rule = rules[i].split()
	    if len(rule) > 0:
	        verdict = rule[0].lower()
	        if verdict == 'drop' or verdict == 'pass':
		    	protocol = rule[1].lower()
		    if protocol == 'tcp':
		        self.tcp_rules.append(rule)
		    elif protocol == 'icmp':
		        self.icmp_rules.append(rule)
		    elif protocol == 'udp':
				self.udp_rules.append(rule)
		    if protocol == 'udp' or protocol == 'dns':
		        self.dns_rules.append(rule)
	    i += 1
        all_rules.close()

    #Send packet	    
    def send_pkt(self, pkt, pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)

    #Selects how to handle packet
    def handle_packet(self, pkt_dir, pkt):
        pkt_header_size = ord(pkt[0]) & 0b00001111
        pkt_size = ord(pkt[2]) + ord(pkt[3])
		protocol = ord(pkt[9])
		if pkt_header_size >= 5 and pkt_size == len(pkt):	
	    	#TCP
	    	if protocol == 6:
	        	tcp_start = (ord(pkt[0]) & 0b00001111) * 4
				offset = ord(pkt[tcp_start+12]) >> 4
			if offset >= 5:
	    	    self.get_valid_rule(pkt, pkt_dir)
	    	#UDP, DNS, ICMP
            elif protocol == 17 or protocol == 1:
				self.get_valid_rule(pkt, pkt_dir)
	    else:
	        self.send_pkt(pkt, pkt_dir)
    
    #Chooses a Valid Rule 
    def get_valid_rule(self, pkt, pkt_dir):
        protocol = ord(pkt[9])
		valid_rule = []
        start = (ord(pkt[0]) & 0b00001111) * 4
		dst_port = struct.unpack('!H', pkt[start+2:start+4])[0]

		if protocol == 6:
	    	for rule in self.tcp_rules:
				if self.check_ip(pkt, pkt_dir, rule) and self.check_port(pkt, pkt_dir, rule):
		    		valid_rule = rule

        elif protocol == 17 and dst_port == 53 and pkt_dir == PKT_DIR_OUTGOING:
	    	for rule in self.dns_rules:
				if self.handle_dns(pkt, pkt_dir, rule):
		    		valid_rule = rule
        elif protocol == 17:
	    	for rule in self.udp_rules:
				if self.check_ip(pkt, pkt_dir, rule) and self.check_port(pkt, pkt_dir, rule):
		    		valid_rule = rule
	
        elif protocol == 1:
	    	start = (ord(pkt[0]) & 0b00001111) * 4
	    	itype = ord(pkt[start])
	    	for rule in self.icmp_rules:
				isValid = rule[3].lower() == 'any' or int(rule[3]) == itype
				if self.check_ip(pkt, pkt_dir, rule) and isValid:
		    		valid_rule = rule
        
		if valid_rule == [] or valid_rule[0].lower() == 'pass':
	    	self.send_pkt(pkt, pkt_dir)

    #Handle DNS Packets
    def handle_dns(self, pkt, pkt_dir, rule):
		rule_url = rule[2].split('.')
		start = (ord(pkt[0]) & 0b00001111) * 4
		dns_start = start + 8
		qd_count = struct.unpack('!H', pkt[dns_start+4:dns_start+6])[0]
		qname_start = dns_start + 12
		i = qname_start
		name = ''
		#Parse Through Headers
		while pkt[i] != '\x00':
	    	j = i + 1
	    	while j <= ord(pkt[i]) + i:
				name = name + pkt[j]
				j += 1
	    		i = j 
	    		if pkt[i] != '\x00':
	        name = name + '.'
		name = name.split('.')
	
		#Checks to Determine Validity of DNS Packets
		valid_name = False
		if(name == rule_url):
		    valid_name = True
		if(len(name) == 3):
			if(rule_url[0] == '*' and len(rule_url) != 1):
			    if(len(rule_url) == 3 and rule_url[1:] == name[1:]):
					valid_name = True
		if(len(name) == 2):
			if(rule_url[0] == '*' and len(rule_url) != 1):
			    if((len(rule_url) == 2 or len(rule_url) == 3) and rule_url[1:] == name[1:]):
					valid_name = True
		if(rule_url[0] == '*' and len(rule_url) == 1):
			valid_name = True
		if valid_name and qd_count == 1:
		    return True
		return False   
    
    #Check Ext IP Addr Field of Current Rule
    def check_ip(self, pkt, pkt_dir, rule):
		addr = self.get_ip(pkt, pkt_dir)
		if rule[2].lower() == 'any':
            return True
		elif len(rule[2]) == 2:
	    	ccode = rule[2]
	    	return self.compare_addrs(ccode, addr)
		elif rule[2] == addr:
	    	return True
		elif '/' in rule[2]:
	    	ip = rule[2].split('/')
        	ip_prefix = struct.unpack('!L', socket.inet_aton(ip[0]))[0]
	    	addr = struct.unpack('!L', socket.inet_aton(addr))[0]
	    	addr = addr >> int(ip[1])
        	ip_prefix = ip_prefix >> int(ip[1])
	    	return ip_prefix == addr
    	return False

    #Check Ext Port Field of Current Rules
    def check_port(self, pkt, pkt_dir, rule):
		port = self.get_port(pkt, pkt_dir)
        if rule[3].lower() == 'any':
	    	return True
		elif int(rule[3]) == port:
	    	return True
		elif port >= int(rule[3].split('-')[0]) and port <= int(rule[3].split('-')[1]):
	    	return True
		return False
    
    #Returns external port number
    def get_port(self, pkt, pkt_dir):
		start = (ord(pkt[0]) & 0b00001111) * 4
        src_port = struct.unpack('!H', pkt[start:start+2])[0]
		dst_port = struct.unpack('!H', pkt[start+2:start+4])[0]
		if pkt_dir == PKT_DIR_INCOMING:
	    	return src_port
		elif pkt_dir == PKT_DIR_OUTGOING:
	    	return dst_port

    #returns external IP address
    def get_ip(self, pkt, pkt_dir):
        src_addr = socket.inet_ntoa(pkt[12:16])
		dst_addr = socket.inet_ntoa(pkt[16:20])
		if pkt_dir == PKT_DIR_INCOMING:
	    	return src_addr.strip()
		elif pkt_dir == PKT_DIR_OUTGOING:
	    	return dst_addr.strip()

    #Compare Ext IP address with geoIP DB
    #Uses Binary Search to Parse Through DB
    def compare_addrs(self, ccode, addr):
		#Example: ['1.1.1.1', '1.2.3.4', 'AU']
		#BEGIN -- Binary Search
		geo = open('geoipdb.txt', 'r')
		geo_IP = geo.read().strip().split('\n')
		ccode = ccode.lower()
		low = 0
		high = len(geo_IP) - 1
		if addr == '' or len(geo_IP) == 0:
	    	return True
		while (low <= high):
	    	mid = (high + low) // 2
	    	if(geo_IP[mid].split()[0] < addr):
	       		low = mid + 1
			if ccode == geo_IP[mid].split()[2].lower() and (addr >= geo_IP[mid].split()[0] and addr <= geo_IP[mid].split()[1]):
		    	return True
	    	elif(geo_IP[mid].split()[0] > addr):
				high = mid
			if ccode == geo_IP[mid].split()[2].lower() and (addr >= geo_IP[mid].split()[0] and addr <= geo_IP[mid].split()[1]):
		    	return True
	    	elif(geo_IP[mid].split()[0] == addr and ccode == geo_IP[mid].split()[2].lower()):
				return True
		geo.close()
		return False

    #for proj 3b
    def handle_timer(self):
        pass
    



			