import re
import sys
import pprint
import ipaddress
import argparse

def debug(string, level=1):
	if level > 1:
		pprint.pprint(string, sys.stderr, width=70)

# Replace "host" with IP 255.255.255.255
def host2num(where):
	global srcip, srcmask, dstip, dstmask
	if "src" in where:
		if "host" in arr[9]:
			arr[9] = arr[10]
			arr[10] = "255.255.255.255"
	if "dst" in where:
		if "host" in arr[7]:
			arr[7] = arr[8]
			arr[8] = "255.255.255.255"


# Place the service in arr[11] in the form of tcp:1234, udp:12345=3456, or *
# If --range: replace neq, gt, lt with ranges
# Return True if "neq", False in all other cases
def prepsvc():
	global service, neq_range
	#debug("prepsvc -- Before prepsvc", 3)
	#debug(arr, 3)
	if service:
		debug("prepsvc -- Already processed. Skipping", 3)
		return
	#print(arr); print("test")
	if len(arr) - 1 >= 12: serv2num(12)
	if "icmp" in arr[6] and (len(arr) - 1 >= 11): arr.insert(11, "eq")
	if len(arr) - 1 >= 12: serv2num(12)
	if len(arr) - 1 >= 13: serv2num(13)
	if "ip" in arr[6]:
		arr.insert(11, "*")
	elif len(arr) < 12:
		arr.insert(11, arr[6])
	elif "range" in arr[11]:
		arr[11] = arr[6] + ':' + arr[12] + '-' + arr[13]
	elif "neq" in arr[11]:
		#if args.range:
		# the first range goes into arr[11]
		arr[11] = arr[6] + ':1-' + str(int(arr[12]) - 1)
		service = arr[11]
		# the second range is returned
		neq_range = arr[6] + ':' + str(int(arr[12]) + 1) + '-65535'
			#return
		#else:
		#	arr[11] = arr[6] + '!' + arr[12]
	elif "eq" in arr[11]:
		arr[11] = arr[6] + ':' + arr[12]
	elif "gt" in arr[11]:
		#if args.range:
		arr[11] = arr[6] + ':' + arr[12] + '-65535'
		#else:
		#	arr[11] = arr[6] + '>' + arr[12]
	elif "lt" in arr[11]:
		#if args.range:
		arr[11] = arr[6] + ':1-' + arr[12]
		# else:
		# 	arr[11] = arr[6] + '>' + arr[12]
	else:
		arr.insert(11, arr[6])
		
	#service = arr[11]
	#debug("prepsvc -- After prepsvc", 3)
	#debug(arr, 3)
	#debug(neq_range, 3)


# Replace service name with port number
# f is the position in arr
def serv2num(f):
	debug(arr, 1)
	if re.match(r'\d+', arr[f]):
		debug("serv2num -- Service %s is a number" % str(arr[f]), 1)
		return  # if number nothing to do
	if arr[f] in s2n:
		debug("serv2num -- Replacing %s with %s" % (arr[f], s2n[arr[f]]), 1)
		arr[f] = s2n[arr[f]]
	
	else:
		#debug(line, 0)
		debug(arr, 0)
		debug("serv2num -- %s is not a known service" % str(arr[f]), 0)
		sys.exit(1)


# Function to parse ACL configuration and extract ACL rules
def parse_acl_config(config):
    global arr
    acl_rules = []
    strTemp = ""
    # regex = r'access-list\s+(\S+)\s+(\S+)\s+(\d+)\s+(extended|standard)\s+(permit|deny)\s+(\S+)\s+(\S+)\s+(.*)'
    regex = r'access-list.*'
    lines = re.findall(regex, config, re.MULTILINE)
    #print("config:")
    #print(config)
    #print(lines)
    for line in lines:

        #if args.verbose: counter += 1
        arr = []
        service = ''
        neq_range = ''
        #debug(line, 3)
        # Remove leftovers
        if "remark" in line or "object-group" in line or " object " in line or not ("extended" in line ): continue
        #print(line)
        line = re.sub(r'\s+', ' ', line)  # replace all multiple tabs and.or spaces with a single space
        line = re.sub(r'\(hitcnt.*$|\s+log\s+.*$|\s+log$', '', line)  # remove hit counters and logging statements
        line = line.replace(r'<--- More --->', '')
        line = line.strip()
        #print(line)
        # Replace any with 0/0
        line = re.sub(r'\bany\b|\bany4\b', '0.0.0.0 0.0.0.0', line)
        #debug(line, 2)
        arr = line.split()
        #print(arr)
        # We are not interested in permit lines, if --deny is set
        # if args.deny and not "deny" in arr[5]: continue
        
        # # We are not interested in deny lines, if --permit is set
        # if args.permit and "deny" in arr[5]: continue
        
        # # Explicitly add 'deny' at the end of the policy line
        # if not args.permit and not args.deny and "deny" in arr[5]:
        # 	action = 'deny'
        # else:
        # 	action = ''
        
        # if args.both and args.noany and "0.0.0.0 0.0.0.0" in line: continue
        
        # Source ports are not supported yet
        if "range" in arr[9]: 
            strTemp = arr[10]
            del arr[9:12]
            if len(arr) == 11:
	            arr.insert(11, "srcport:" + strTemp)		    
        if "eq" in arr[9] or "lt" in arr[9] or "gt" in arr[9] or "neq" in arr[9]:
            strTemp = arr[10]
            del arr[9:11]
            if len(arr) == 11:
	            arr.insert(11, "srcport:" + strTemp)
        if "host" in line:
            host2num("src")
            host2num("dst")
        
        # if "0.0.0.0/0" in args.addr and not args.any and not args.noany:
        # 	srcip = arr[7]
        # 	srcmask = arr[8]
        # 	dstip = arr[9]
        # 	dstmask = arr[10]
        # 	print_acl()
        # else:
        # 	for searchip in ips:
        # 		debug("Searching for %s" % str(searchip), 2)
        # 		if args.src:
        # 			if issrc(searchip): print_acl()
        # 		elif args.dst:
        # 			if isdst(searchip): print_acl()
        # 		elif args.both:
        # 			if issrc(searchip) or isdst(searchip): print_acl()
        #print(arr)
        prepsvc()

        acl_rules.append(arr)
        #print(arr)
        #print("============")
        #del arr[:]

 
    
        # acl_name = match[0]
        # acl_type = match[1]
        # action = match[2]
        # protocol = match[3]
        # source = match[4]
        # destination = match[5]
        # acl_rules.append((acl_name, acl_type, action, protocol, source, destination))
    return acl_rules

# Function to analyze ACL rules
# def analyze_acl_rules(acl_rules):
#     for rule in acl_rules:
#         acl_name, acl_type, action, protocol, source, destination = rule
#         # Perform analysis and checks on the ACL rules
#         # Example: Check for specific source/destination addresses, protocol usage, or any other custom requirements



# Analyze ACL rules
#analyze_acl_rules(acl_rules)

if __name__ == "__main__":
    arr = []
    service = ''
    neq_range = ''
    order = 0
    s2n = {'domain': '53', 'sunrpc': '111', 'citrix-ica': '1494', 'telnet': '23', 'tftp': '69', 'syslog': '514',
           'rtsp': '554', 'secureid-udp': '5510', 'gopher': '70', 'h323': '1720', 'echo': '7', 'netbios-ssn': '139',
           'snmptrap': '162', 'rpc': '111', 'radius': '1645', 'pcanywhere-data': '5631', 'nameserver': '42',
           'rsh': '514', 'sqlnet': '1521', 'uucp': '540', 'ftp': '21', 'sip': '5060', 'whois': '43', 'smtp': '25',
           'ctiqbe': '2748', 'hostname': '101', 'snmp': '161', 'mobile-ip': '434', 'daytime': '13', 'ldaps': '636',
           'isakmp': '500', 'netbios-dgm': '138', 'finger': '79', 'https': '443', 'ldap': '389', 'kshell': '544',
           'irc': '194', 'nntp': '119', 'biff': '512', 'http': '80', 'cifs': '3020', 'exec': '512', 'pptp': '1723',
           'ntp': '123', 'aol': '5190', 'talk': '517', 'pcanywhere-status': '5632', 'pop3': '110', 'pop2': '109',
           'ftp-data': '20', 'lotusnotes': '1352', 'rip': '520', 'xdmcp': '177', 'pim-auto-rp': '496', 'login': '513',
           'dnsix': '195', 'ident': '113', 'netbios-ns': '137', 'kerberos': '750', 'tacacs': '49', 'who': '513',
           'cmd': '514', 'bootps': '67', 'bgp': '179', 'nfs': '2049', 'klogin': '543', 'chargen': '19', 'www': '80',
           'time': '37', 'discard': '13', 'imap4': '143', 'lpd': '515', 'bootpc': '68', 'radius-acct': '1646',
           'ssh': '22', 'redirect': '5', 'information-reply': '16', 'alternate-address': '6', 'mask-reply': '18',
           'timestamp-request': '13', 'router-solicitation': '10', 'mobile-redirect': '32', 'parameter-problem': '12',
           'echo': '8', 'timestamp-reply': '14', 'conversion-error': '31', 'information-request': '15',
          'unreachable': '3', 'echo-reply': '0', 'source-quench': '4', 'mask-request': '17', 'time-exceeded': '11',
           'router-advertisement': '9'}
    # Read ASA ACL configuration from file

    parser = argparse.ArgumentParser()
    parser.add_argument
    parser.add_argument('acl', default="-", nargs='?',
					help="Cisco ASA ACL filename or \"-\" to read from the console (default)")
    args = parser.parse_args()
    

    with open(args.acl, 'r') as file:
        asa_config = file.read()

    # Parse ACL configuration and extract ACL rules
    acl_all = parse_acl_config(asa_config)
    #print(acl_all)

    for entry in acl_all:
        order = order + 1
        if order < len(acl_all):
            for entry1 in acl_all[order:]:
                srv_isincluded = False    
                if entry[1] != entry1[1] or entry[6] != entry1[6]: continue
                if len(entry) > 11 and len(entry1) > 11:
                    srcip = ipaddress.ip_network(entry[7] + '/' + entry[8])
                    srcip1 = ipaddress.ip_network(entry1[7] + '/' + entry1[8])
                    #debug(entry, 3); debug(entry1, 3)
                    dstip = ipaddress.ip_network(entry[9] + '/' + entry[10])
                    dstip1 = ipaddress.ip_network(entry1[9] + '/' + entry1[10])
                    if entry[11] == entry1[11] or (entry[11] == "*" and entry1[11] != "*"):
                        if (":" not in entry[11]) and (":" not in entry[11]) and entry[11] != '*':
                            if entry[12] == entry1[12]:
                                srv_isincluded = True
                        else:
                            srv_isincluded = True
                    if "-" in entry[11] and ("-" not in entry1[11]) and entry1[12] >= entry[12] and entry1[12] <= entry[13]:
                        srv_isincluded = True
                    if "-" in entry[11] and "-" in entry1[11] and entry1[12] >= entry[12] and entry1[13] <= entry[13]:
                        srv_isincluded = True
                    if srcip1.subnet_of(srcip) and dstip1.subnet_of(dstip) and srv_isincluded:
                        print("===Possible shadowed rules====")
                        print("Please check if the rule ", entry1, " is shadowed by ", entry )
