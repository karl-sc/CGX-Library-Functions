#### MASTER LIBRARY FUNCTIONS ################################
# USAGE: from cgx_function_library import *                 #
# from cgx_function_library import *                        #
#############################################################



##### EVENTS #####

#/----------------------
#| cgx_event_code_to_description - Gets an alarm_code as STR e.g. 'SITE_CONNECTIVITY_DEGRADED' and returns a STR of the long description for the code. Returns "unknown" on error
CGX_EVENT_CODES = { 
            'DEVICEHW_POWER_LOST' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Power Loss', 'severity': 'major', 'description': 'Power Supply Unit (PSU) on a device is indicating fault. Power to that PSU may be interrupted or the PSU may have failed.'},
            'DEVICEHW_INTERFACE_DOWN' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Interface Down', 'severity': 'major', 'description': 'A configured admin-up interface is either not receiving a signal or has an error that is causing lack of data flow through that interface.'},
            'DEVICEHW_DISKENC_SYSTEM' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Disk Encryption Upgrade failure', 'severity': 'critical', 'description': 'One of the disk partitions failed to convert into an encrypted partition during device upgrade.'},
            'DEVICEHW_DISKUTIL_PARTITIONSPACE' : { 'type': 'alarm', 'category': 'device', 'display_name': 'High Disk Capacity Utilization', 'severity': 'major', 'description': 'Disk Storage Utilization on a device has reached 85% of capacity. Non-critical functions including logging and statistics export might be impacted.'},
            'DEVICEHW_MEMUTIL_SWAPSPACE' : { 'type': 'alarm', 'category': 'device', 'display_name': 'High Memory Utilization', 'severity': 'critical', 'description': 'Memory Utilization on a device has reached maximum capacity forcing using of disk based swap space. Sub-optimal performance might be impacting device functions.'},
            'DEVICESW_DHCPSERVER_ERRORS' : { 'type': 'alarm', 'category': 'device', 'display_name': 'DHCP server failed to start', 'severity': 'critical', 'description': 'DHCP server listening on physical interfaces failed to start due to possible reasons: (a) DHCP server configuration error. (b) Lack of active element interface with static IP configuration. (c) Internal errors on element.'},
            'DEVICESW_DHCPSERVER_RESTART' : { 'type': 'alert', 'category': 'device', 'display_name': 'DHCP server restarted', 'severity': 'minor', 'description': 'DHCP server listening on physical interfaces has restarted and recovered from an error.'},
            'DEVICESW_DHCPRELAY_RESTART' : { 'type': 'alert', 'category': 'device', 'display_name': 'DHCP relay agent restarted', 'severity': 'minor', 'description': 'DHCP relay agent on device has restarted and recovered from an error.'},
            'DEVICESW_DISCONNECTED_FROM_CONTROLLER' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Device disconnected from Controller', 'severity': 'major', 'description': 'Device has remained disconnected from the Controller for a prolonged duration.'},
            'DEVICESW_INITIATED_CONNECTION_ON_EXCLUDED_PATH' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Device Initiated Connection on excluded path', 'severity': 'major', 'description': 'Device Initiated Connection on excluded interface.'},
            'DEVICESW_NTP_NO_SYNC' : { 'type': 'alarm', 'category': 'device', 'display_name': 'NTP synchronization failed', 'severity': 'major', 'description': 'Unable to sync up with all configured NTP servers for more than 24 hours.'},
            'DEVICESW_GENERAL_PROCESSRESTART' : { 'type': 'alert', 'category': 'device', 'display_name': 'Process Restart', 'severity': 'minor', 'description': 'A software process on the device has restarted either due to an error or as a self-recovery method. Process restart as a self-recovery does not impact long-term functions on the device but can cause short term sub-optimal functions and errors.'},
            'DEVICESW_GENERAL_PROCESSSTOP' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Process Stopped', 'severity': 'major', 'description': 'A software process on the device has stopped due to an error and inability to recover with a self-restart. Functionality is likely impacted.'},
            'DEVICESW_MONITOR_DISABLED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'System Monitoring Disabled', 'severity': 'major', 'description': 'A software process that monitors the health of device and its Hardware/Software components has been disabled. Though not currently impacting, operation of the device and the software on the device while this fault exists will impact recovery and handling of other Hardware/Software faults that need recovery action.'},
            'DEVICESW_SNMP_AGENT_FAILED_TO_START' : { 'type': 'alarm', 'category': 'device', 'display_name': 'SNMP Agent Failed to Start', 'severity': 'major', 'description': 'SNMP agent failed to start due to these possible reasons: (a) Invalid configuration, or (b) Decryption failure.'},
            'DEVICESW_SNMP_AGENT_RESTART' : { 'type': 'alert', 'category': 'device', 'display_name': 'SNMP agent restarted', 'severity': 'minor', 'description': 'SNMP agent on device has restarted and recovered from an error.'},
            'DEVICESW_SYSTEM_BOOT' : { 'type': 'alert', 'category': 'device', 'display_name': 'Device Reboot', 'severity': 'critical', 'description': 'Device rebooted either due to recovery on a fault condition or as part of normal operational procedures including user initiated reboots and software upgrades. Reboots due to fault conditions can cause sub-optimal or significantly reduced functionality on the device.'},
            'DEVICEIF_ADDRESS_DUPLICATE' : { 'type': 'alert', 'category': 'device', 'display_name': 'Duplicate IP Address', 'severity': 'major', 'description': 'Another device in the local network is using an IP address assigned to this device.'},
            'DEVICEHW_INTERFACE_ERRORS' : { 'type': 'alert', 'category': 'device', 'display_name': 'High rate of errors on the interface', 'severity': 'major', 'description': 'Number of transmission and/or reception errors seen on an interface over the last one hour period has exceeded the threshold (0.5% of received or transmitted packet counts in the same one hour period).'},
            'DEVICEHW_INTERFACE_HALFDUPLEX' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Interface running in half-duplex mode', 'severity': 'major', 'description': 'A interface has negotiated half duplex, although it is allowed to run in full duplex, which is preferred.'},
            'FLAP_RATE_EXCEEDED' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Flap Rate Exceeded', 'severity': 'major', 'description': 'An alarm has repeatedly raised and cleared triggering a flapping condition per the event policy rule.'},
            'NETWORK_ANYNETLINK_DEGRADED' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Secure Fabric Link Degraded', 'displayCode': 'NETWORK_SECUREFABRICLINK_DEGRADED', 'severity': 'minor', 'description': 'Secure Fabric Link is degraded with atleast 1 VPNlink UP from the active spoke and 1 or more VPNlinks DOWN from the active spoke.'},
            'NETWORK_ANYNETLINK_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Secure Fabric Link Down', 'displayCode': 'NETWORK_SECUREFABRICLINK_DOWN', 'severity': 'major', 'description': 'Secure Fabric Link is down with all VPNLinks DOWN from the active spoke.'},
            'NETWORK_DIRECTPRIVATE_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Private Wan Reachability Down', 'severity': 'major', 'description': 'For remote office (branch) sites, all data center sites with ion 7000x deployed have been declared unreachable on Private WAN. If there are no alternate paths in the application policy, the fault is traffic impacting and should be attended to immediately.'},
            'NETWORK_DIRECTINTERNET_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Direct Internet Reachability Down', 'severity': 'major', 'description': 'For remote office (branch) sites, reachability on an Internet circuit has been declared to be down. If there are no alternate paths in the application policy, the fault is traffic impacting and should be attended to immediately.'},
            'NETWORK_PRIVATEWAN_UNREACHABLE' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Private Wan Unreachable', 'severity': 'major', 'description': 'For data center sites, one or more remote offices have been declared unreachable over Private WAN based on routing updates received from the network. If this fault occurred due to WAN edge peering failure PEERING_EDGE_DOWN fault(s) will also be raised.'},
            'NETWORK_PRIVATEWAN_DEGRADED' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Private Wan Degraded', 'severity': 'major', 'description': 'For data center sites, a subset of IP prefixes from one or more remote sites have been determined to be unreachable over Private WAN based on routing updates received from the network.'},
            'OPERATOR_SIGNUP_TOKEN_DISABLED' : { 'type': 'alert', 'category': 'aaa', 'display_name': 'User Signup Disabled', 'severity': 'minor', 'description': 'A new user that was issued a signup token to self-complete the signup steps failed that process multiple times by using wrong combination of the signup token and unique ID supplied by his/her administrator. The same fault can happen if an existing user forgot his/her password, was required to finish the password reset steps but failed that process multiple times.'},
            'PEERING_EDGE_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'WAN Edge Peer Down', 'severity': 'critical', 'description': 'Routing peer session with a configured WAN edge device is down. If alternate paths are available traffic is not affected; else the fault is critical.'},
            'PEERING_CORE_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Core Peer Down', 'severity': 'critical', 'description': 'Routing peer session with a configured Core device is down. If alternate paths are available traffic is not affected; else the fault is critical.'},
            'PEERING_BGP_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'BGP Peer Down', 'severity': 'critical', 'description': 'Routing peer session is down. If alternate paths are available traffic is not affected; else the fault is critical.'},
            'APPLICATION_CUSTOM_RULE_CONFLICT' : { 'type': 'alarm', 'category': 'application', 'display_name': 'Application Custom Rule Conflict', 'severity': 'minor', 'description': 'An application rule conflict has been detected.'},
            'APPLICATION_PROBE_DISABLED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Application Probe Disabled', 'severity': 'major', 'description': 'Application probes are disabled either due to incomplete configuration or invalid state. Element will no longer issue application probe to detect application reachability unless the issue is resolved. Consequently, if application probes are disabled then application will no longer switch to alternative paths in case it fails on its current path.'},
            'SITE_CIRCUIT_ABSENT_FOR_POLICY' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Site missing circuit(s) for policy', 'severity': 'major', 'description': 'Site is missing all circuit definitions specified in the Policy Set assigned to the site. Applications at the site will be affected since there are no circuits to forward the traffic.'},
            'SITE_NETWORK_SERVICE_ABSENT_FOR_POLICY' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Policy DC Group Missing Service Endpoint', 'severity': 'major', 'description': 'One or more DC groups used in the policy has not been assigned a valid service endpoint for the domain bound to the identified site.'},
            'DEVICESW_IMAGE_UNSUPPORTED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Unsupported Software Image', 'severity': 'critical', 'description': 'Device\'s software image is not recognized by the Controller. The software version may not be allowed in the network or may no longer exist.'},
            'DEVICESW_FPS_LIMIT_EXCEEDED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'System Rate Limit Exceeded', 'severity': 'major', 'description': 'A consistently high flow rate above system limits has been detected.'},
            'DEVICESW_CONCURRENT_FLOWLIMIT_EXCEEDED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'System Tracking Limit Exceeded', 'severity': 'critical', 'description': 'An abnormal and significantly high sessions/flow trackers have been detected.'},
            'DEVICESW_LICENSE_VERIFICATION_FAILED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Virtual ION license verification failed', 'severity': 'major', 'description': 'The License is no longer valid. The maximum ION deployment limit reached.'},
            'DEVICESW_TOKEN_VERIFICATION_FAILED' : { 'type': 'alert', 'category': 'device', 'display_name': 'Virtual ION token validation failed', 'severity': 'critical', 'description': 'The token is no longer valid. It\'s either utilized, expired or revoked.'},
            'DEVICESW_CRITICAL_PROCESSSTOP' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Critical Process Stopped', 'severity': 'critical', 'description': 'A critical software process on the device has stopped due to an error and inability to recover with a self-restart. Data forwarding functionality is likely impacted.'},
            'DEVICESW_CRITICAL_PROCESSRESTART' : { 'type': 'alert', 'category': 'device', 'display_name': 'Critical Process Restart', 'severity': 'critical', 'description': 'A critical software process on the device has restarted either due to an error or as a self-recovery method. Process restart as a self-recovery does not impact long-term functions on the device but can cause short term sub-optimal data plane functions and errors.'},
            'DEVICESW_CONNTRACK_FLOWLIMIT_EXCEEDED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Conntrack table flow count exceeded threshold.', 'severity': 'critical', 'description': 'Number of flows in the connection tracking table used for features such as NAT and device management policy has exceeded 90% threshold.'},
            'NETWORK_POLICY_RULE_CONFLICT' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Network policy rule conflict', 'severity': 'minor', 'description': 'Two or more policy rules in a network policy set conflict, potentially resulting in incorrect policy being applied to some flows.'},
            'NETWORK_POLICY_RULE_DROPPED' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Network policy rule dropped', 'severity': 'major', 'description': 'Network policy configuration contains rules with too many permutations such that the required resources exceed the operational limits. Some rules have been dropped from the policy so as to not exceed the limit and therefore the desired policy actions may not be performed in some cases.'},
            'NAT_POLICY_STATIC_NATPOOL_OVERRUN' : { 'type': 'alarm', 'category': 'device', 'severity': 'minor', 'display_name': 'Static NAT pool range is overrun by selector prefix', 'description': 'Configured Nat pool range cannot map 1:1 with matching traffic selector prefix.'},
            'PRIORITY_POLICY_RULE_CONFLICT' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Priority policy rule conflict', 'severity': 'minor', 'description': 'Two or more policy rules in a priority policy set conflict, potentially resulting in incorrect policy being applied to some flows.'},
            'PRIORITY_POLICY_RULE_DROPPED' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Priority policy rule dropped', 'severity': 'major', 'description': 'Priority policy configuration contains rules with too many permutations such that the required resources exceed the operational limits. Some rules have been dropped from the policy so as to not exceed the limit and therefore the desired policy actions may not be performed in some cases.'},
            'NAT_POLICY_LEGACY_ALG_CONFIG_OVERRIDE' : { 'type': 'alert', 'category': 'policy', 'display_name': 'NAT policy ALG action overridden by legacy configuration', 'severity': 'major', 'description': 'ALG action configured in the NAT policy has been overridden by legacy configuration present on the device.'},
            'SECURITY_POLICY_RULE_INCOMPLETE' : { 'type': 'alarm', 'category': 'policy', 'display_name': 'Security rule configuration incomplete', 'severity': 'critical', 'description': 'The security policy rule configuration is incomplete. In this case the security policy rule is skipped.'},
            'SITE_CONNECTIVITY_DOWN' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Site Connectivity down', 'severity': 'critical', 'description': 'All site WAN connectivity is down.'},
            'SITE_CONNECTIVITY_DEGRADED' : { 'type': 'alarm', 'category': 'network', 'display_name': 'Site Connectivity degraded', 'severity': 'major', 'description': 'Multiple issues are present impacting site WAN connectivity.'},
            'SPOKEHA_STATE_UPDATE' : { 'type': 'alert', 'category': 'spokeha', 'display_name': 'Device state in the spoke cluster changed', 'severity': 'major', 'description': 'Device changed its state from active to backup or backup to active. If the device changed its state to backup, and there is no other device eligible to become active, then network connectivity at the site will be affected.'},
            'SPOKEHA_MULTIPLE_ACTIVE_DEVICES' : { 'type': 'alarm', 'category': 'spokeha', 'display_name': 'Split Brain', 'severity': 'critical', 'description': 'A critical alarm will be raised on the spoke HA cluster resource by the controller when both elements declare themselves to be "active" (split brain).'},
            'SPOKEHA_CLUSTER_DEGRADED' : { 'type': 'alarm', 'category': 'spokeha', 'display_name': 'Cluster Degraded', 'severity': 'major', 'description': 'One of the element in the SpokeCluster has effective priority 0.'},
            'SPOKEHA_CLUSTER_DOWN' : { 'type': 'alarm', 'category': 'spokeha', 'display_name': 'Cluster Down', 'severity': 'critical', 'description': 'All elements in the SpokeCluster have effective priority 0.'},
            'CLAIMCERT_AUTO_RENEWAL_DISABLED' : { 'type': 'alert', 'category': 'device', 'display_name': 'Auto Renewal of Claim Certificate is Disabled', 'severity': 'major', 'description': 'The claim certificate shall expire in a short period of time. This may happen when either previous attempts to renew the certificate have failed or the certificate expiry has been set to a short timeframe.'},
            'CLAIMCERT_EXPIRY_WARNING' : { 'type': 'alert', 'category': 'device', 'display_name': 'Claim Certificate Expiration Date Approaching', 'severity': 'major', 'description': 'The claim certificate shall expire in a short period of time. This may happen when either previous attempts to renew the certificate have failed or the certificate expiry has been set to a short timeframe.'},
            'CLAIMCERT_RENEWAL_RETRY_LIMIT_EXCEEDED' : { 'type': 'alarm', 'category': 'device', 'display_name': 'Claim Certificate Renewal Attempts Exceeded', 'severity': 'critical', 'description': 'There were errors observed during the process of Claim Certificate renewal. Repeated attempts to renew the Claim Certificate exceeded three consecutive retries. Auto renewal is therefore disabled and a renewal must be triggered from the Controller. However, this event indicates a problem that is external to the process and it must be attended to immediately.'},
            'CLAIMCERT_RENEWAL_FAILED' : { 'type': 'alert', 'category': 'device', 'display_name': 'Renewal of Claim Certificate Failed', 'severity': 'major', 'description': 'The process of renewing the Claim Certificate encountered problems. These may be related to external events such as failures reported by CA or incorrect/invalid certificate being issued. Other reasons can be internal failures such as problems arising from generating a CSR request or receiving CSR details from controller.'},
            'CLAIMCERT_RENEWALS_TOO_FREQUENT' : { 'type': 'alert', 'category': 'device', 'display_name': 'Claim Certificate Renewed Too Frequently', 'severity': 'major', 'description': 'A condition is reached where a renewed Claim Certificate is determined to fall within a renewal window and subsequent renewals are attempted once again. This condition may occur when the Certificate issued by the CA has a shorter expiry time than the renewal window configured on the Controller.'},
            'DEVICESW_IPFIX_COLLECTORS_DOWN' : { 'type': 'alarm', 'category': 'device', 'display_name': 'IPFIX collectors are down', 'severity': 'major', 'description': 'The software process responsible to export IPFIX records has observed that there are no active connections to the IPFIX collectors. The process will continue to monitor the connection status and resume exporting of the IPFIX records once the connections are re-established.'},
            'DEVICEHW_ION9000X722FW_OUTOFDATE' : { 'type': 'alarm', 'category': 'device', 'display_name': 'ION 9000 Ports 9-12 Firmware Update Required', 'severity': 'major', 'description': 'A very important firmware update is required for stable operation of ports 9 through 12 on this device.'}
            }
def cgx_event_code_to_description(alarm_code):
    global CGX_EVENT_CODES
    try:
        return CGX_EVENT_CODES[alarm_code]['description']
    except:
        return "Unknown" ### event code not found
#\----------------------

#/----------------------
#| cgx_get_last_alarms - Gets last Alarms with or without filters. By default, pulls the last 100 active alarms. Set resolved to True to include resolved to view the past 24 hours of alarms.
def cgx_get_last_alarms(sdk, count=100, acknowledged=False, resolved=False, hours_interval=24, suppressed=False):
    true = True
    false = False
    acknowledged = True if str(acknowledged).lower() == "true" else False
    suppressed = True if str(suppressed).lower() == "true" else False
    resolved = True if str(resolved).lower() == "true" else False 
    event_request_query = {"limit":{"count":count,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"severity":[],"priority":[],"acknowledged":acknowledged,"suppressed":false,"query":{"site":[],"category":[],"code":[],"correlation_id":[],"type":["alarm"]}}
    if resolved: ## to view resolved, you must indicate a start time and end time.
        (start_time, end_time) = cgx_generate_timestamps(hours_interval=hours_interval)
        event_request_query = {"limit":{"count":count,"sort_on":"time","sort_order":"descending"},"view":{"summary":false},"end_time":end_time,"start_time":start_time,"severity":[],"priority":[],"query":{"site":[],"category":[],"code":[],"correlation_id":[],"type":["alarm"]}}
    try:
        result = sdk.post.events_query(event_request_query)
        return result.cgx_content.get("items", None)
    except:
        return None
#\----------------------

##### SITES #####

#/----------------------
#| cgx_site_name_to_id - Attempts to find the best matching site id given a site name. Case is insensitive.
#|                       Optionally include a minimum assurance to guarantee a level of match. 80 is pretty close ('Neywork' will match 'New York'), 
#|                       90 is incredibly close (Newyork = New York), and 100 is exact (New York = New York). 
def cgx_site_name_to_id(sdk, search_site,minimum_assurance=0):
    from fuzzywuzzy import fuzz
    search_ratio = 0
    site_dict = {}
    resp = sdk.get.sites()
    if resp.cgx_status:
        site_list = resp.cgx_content.get("items", None)    #site_list contains an list of all returned sites
        for site in site_list:                            #Loop through each site in the site_list
            check_ratio = fuzz.ratio(search_site.lower(),site['name'].lower())
            if (check_ratio > search_ratio and check_ratio >= minimum_assurance): ###Find the "best" matching site name with the minimum assurance (90 is really close)
                search_ratio = check_ratio
                site_dict = site
    else:
        print("ERROR: API Call failure when enumerating SITES in tenant! Exiting!")
    try:
        return site_dict['id']
    except:
        return None
#\----------------------

#/----------------------
#| cgx_site_id_to_name - Attempts to find the site name given a site id
def cgx_site_id_to_name(sdk, search_id):
    resp = sdk.get.sites(site_id=search_id)
    if resp.cgx_status:
        return resp.cgx_content['name']
    else:
        print("ERROR: API Call failure when enumerating SITE ID in tenant! Exiting!")
        return None
#\----------------------


#/----------------------
#| cgx_site_name_to_object - Attempts to find the best matching site dict object given a site name
def cgx_site_name_to_dict(sdk, search_site):
    from fuzzywuzzy import fuzz
    search_ratio = 0
    site_dict = {}
    resp = sdk.get.sites()
    if resp.cgx_status:
        site_list = resp.cgx_content.get("items", None)    #site_list contains an list of all returned sites
        for site in site_list:                            #Loop through each site in the site_list
            check_ratio = fuzz.ratio(search_site.lower(),site['name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                site_dict = site
    else:
        print("ERROR: API Call failure when enumerating SITES in tenant! Exiting!")
    try:
        return site_dict
    except:
        return None
#\----------------------

#/----------------------
#| cgx_destroy_all_sites - Attempts to iterate through all sites and 
def cgx_destroy_all_sites(sdk, unclaim_device=True):
    from cloudgenix_config import do
    from cloudgenix_config import pull
    result = sdk.get.sites().cgx_content.get("items")
    site_list = []
    for i in result:
        site_list.append(i['id'])
    for site_id in site_list:
        try:
            elements_list = cgx_get_elements_in_site(sdk, site_id) 
            result = pull.pull_config_sites(site_id, None, return_result=True, passed_sdk=sdk) # Pull the site config before destroying
            do.do_site(result, destroy=True, passed_sdk=sdk, ) # Destroy the site using the previously pulled config
            if unclaim_device:
                for element in elements_list:
                    cgx_unclaim_element(sdk,element) ## Unclaim each ION at the site
        except:
            print("Problem with destroying site",site_id)
#\----------------------

#/----------------------
#| cgx_destroy_site - Attempts to destroy a specific site by ID by destroying the site
def cgx_destroy_site(sdk, site_id):
    from cloudgenix_config import do
    from cloudgenix_config import pull
    try:
        result = pull.pull_config_sites(site_id, None, return_result=True, passed_sdk=sdk) # Pull the site config before destroying
        do.do_site(result, destroy=True, passed_sdk=sdk, ) # Destroy the site using the previously pulled config
    except:
        print("Problem with destroying site",site_id)
#\----------------------


##### ELEMENTS #####

#/----------------------
#| cgx_get_element_ids_in_site - returns a list of element ID's bound to that site
def cgx_get_element_ids_in_site(sdk, site_id):
    response = []
    elements_list = sdk.get.elements().cgx_content.get("items")
    for element in elements_list:
        if element['site_id'] == site_id:
            response.append(element['id'])
    return response
#\----------------------

#/----------------------
#| cgx_get_element_dict_in_site - returns a list of element DICT's bound to that site
def cgx_get_element_dict_in_site(sdk, site_id):
    response = None
    elements_list = sdk.get.elements().cgx_content.get("items")
    for element in elements_list:
        if element['site_id'] == site_id:
            if response == None:
                response = []
            response.append(element)
    return response
#\----------------------

#/----------------------
#| cgx_element_name_to_id - Attempts to find the best matching element id given an element name
def cgx_element_name_to_id(sdk, search_ion):
    from fuzzywuzzy import fuzz
    search_ratio = 0
    element_dict = {}
    resp = sdk.get.elements()
    if resp.cgx_status:
        element_list = resp.cgx_content.get("items", None)    #element_list contains an list of all returned elements
        for element in element_list:                            #Loop through each site in the element_list
            check_ratio = fuzz.ratio(search_ion.lower(),element['name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                element_dict = element
    else:
        print("ERROR: API Call failure when enumerating SITES in tenant! Exiting!")
    try:
        return element_dict['id']
    except:
        return None
#\----------------------

#/----------------------
#| cgx_element_name_to_dict - Attempts to find the best matching element id given an element name
def cgx_element_name_to_dict(sdk, search_ion):
    from fuzzywuzzy import fuzz
    search_ratio = 0
    element_dict = {}
    resp = sdk.get.elements()
    if resp.cgx_status:
        element_list = resp.cgx_content.get("items", None)    #element_list contains an list of all returned elements
        for element in element_list:                            #Loop through each site in the element_list
            check_ratio = fuzz.ratio(search_ion.lower(),element['name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                element_dict = element
    else:
        print("ERROR: API Call failure when enumerating SITES in tenant! Exiting!")
    try:
        return element_dict
    except:
        return None
#\----------------------

#/----------------------
#| cgx_unclaim_element - unclaims a claimed element by id
def cgx_unclaim_element(sdk, element_id):
    declaim_post = {"action":"declaim","parameters":None}
    sdk.post.operations_e(element_id, declaim_post)
#\----------------------




##### APP ID #####

#/----------------------
#| cgx_app_id_to_name_cached - Caching function which takes in an APP_ID and returns the NAME
app_id_name_cache = {}
app_def_cache = None
def cgx_app_id_to_name_cached(sdk, search_app_id):
    global app_id_name_cache, app_def_cache
    search_app_id = str(search_app_id).strip().lower()
    if search_app_id in app_id_name_cache.keys():
        return app_id_name_cache[search_app_id]['display_name']
    if not app_def_cache:
        app_def_cache = sdk.get.appdefs().cgx_content.get("items",None)
    for app in app_def_cache:
        if search_app_id == app['id']: 
            app_id_name_cache[search_app_id] = app
            return app['display_name']
    app_id_name_cache[search_app_id] = None
    return None
#\----------------------

#/----------------------
#| cgx_app_id_to_name - Non-caching function which takes in an APP_ID and returns the NAME
def cgx_app_id_to_dict(sdk, search_app_id):
    try:
        result = sdk.get.appdefs(appdef_id=str(search_app_id)).cgx_content
        return result['display_name']
    except:
        return "Unknown"
#\----------------------

#/----------------------
#| cgx_app_id_to_name_cached - Caching function which takes in an APP Name and returns the ID
app_id_name_cache = {}
app_def_cache = None
def cgx_app_name_to_id_cached(sdk, search_app_name):
    global app_id_name_cache, app_def_cache
    from fuzzywuzzy import fuzz
    search_ratio = 0
    app_dict = {}
    try:
        if not app_def_cache:
            app_def_cache = sdk.get.appdefs().cgx_content.get("items",None)
        for app in app_def_cache:
            check_ratio = fuzz.ratio(search_app_name.lower(),app['display_name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                app_dict = app
        return app_dict['id']
    except:
        return "N/A"
#\----------------------

#/----------------------
#| cgx_app_id_to_dict_cached - Caching function which takes in an APP Name and returns the app dict
app_id_name_cache = {}
app_def_cache = None
def cgx_app_id_to_dict_cached(sdk, search_app_name):
    global app_id_name_cache, app_def_cache
    from fuzzywuzzy import fuzz
    search_ratio = 0
    app_dict = {}
    try:
        if not app_def_cache:
            app_def_cache = sdk.get.appdefs().cgx_content.get("items",None)
        for app in app_def_cache:
            check_ratio = fuzz.ratio(search_app_name.lower(),app['display_name'].lower())
            if (check_ratio > search_ratio ): ###Find the "best" matching site name
                search_ratio = check_ratio
                app_dict = app
        return app_dict
    except:
        return "unknown"
#\----------------------


##### ANALYTICS #####

#/----------------------
#| cgx_get_last_flows - Gets last flows based on a Site_ID, start time, end time, and optional list of app-id's to filter by
def cgx_get_last_flows(sdk, site_id, start_time, end_time, filter_list_of_apps=[]):
    true = True
    false = False
    (start_time, end_time) = cgx_generate_timestamps(hours_interval=1)
    flow_request_query = {"start_time":start_time,"end_time":end_time,"filter":{"app":filter_list_of_apps,"site":[site_id]},"debug_level":"all"}
    try:
        result = sdk.post.flows_monitor(flow_request_query)
        if result.cgx_status:
            return result.cgx_content.get("flows").get("items")
        else:
            print("Error getting flows")
            return result
    except:
        return None
#\----------------------

#/----------------------
#| cgx_get_bw_consumption - Gets bandwidth consumption average for a give time period. If no site_id is given, Aggregate BW consumption for the tenant is provided.
def cgx_get_bw_consumption(sdk, start_time, end_time, site_id=None, average=True, percentile=90):
    true = True
    false = False
    post_request = {"start_time":start_time, "end_time":end_time, "interval":"5min","metrics":[{"name":"BandwidthUsage","statistics":["average"],"unit":"Mbps"}],"view":{},"filter":{"site":[]}}
    if site_id: post_request['filter']['site'].append(str(site_id))
    result = sdk.post.monitor_metrics(post_request)
    metrics = result.cgx_content
    series = metrics.get("metrics",[{}])[0].get("series",[])[0]
    if average == True:
        return(cgx_average_series(series))
    else:
        return(cgx_percentile_series(series, percentile=percentile))
#\----------------------


##### Topology #####

#/----------------------
#| cgx_mesh_two_sites - Takes two sites and forms VPN tunnels between the two across all capable WAN connections
def cgx_mesh_two_sites(sdk, site1_id, site2_id ):
    site1_wans = sdk.get.waninterfaces(site1_id).cgx_content.get("items", None)
    site2_wans = sdk.get.waninterfaces(site2_id).cgx_content.get("items", None)
    for left_wan in site1_wans:
        for right_wan in site2_wans:
            if left_wan['type'] == right_wan['type']: ##WANS must be of same type. I.E. PrivateWAN must connect to Private WAN's
                cgx_add_anynet_link(sdk, site1_id, left_wan['id'], site2_id, right_wan['id'])
#\----------------------
       
#/----------------------
#| cgx_add_anynet_link - Adds a VPN tunnel between two sites on a specific WAN circuit  
def cgx_add_anynet_link(sdk, site1, wan1, site2, wan2 ):
    ### This function adds a SecureFabric/Anynet link between two sites
    post_data = {'name': None, 'description': None, 'tags': None, 
                        'ep1_site_id': str(site1), 
                            'ep1_wan_if_id': str(wan1), 
                        'ep2_site_id': str(site2), 
                            'ep2_wan_if_id': wan2, 
                    'admin_up': True, 'forced': True, 'type': None}
    result = sdk.post.tenant_anynetlinks(post_data)
    if result.cgx_status == False:
        print("FAILURE:",result.cgx_errors)
    else:
        print("SUCCESS",site1,result.cgx_status)
#\----------------------


##### MISC #####

#/----------------------
#| cgx_generate_timestamps - Generates CGX start and end Timestamps used in events, alarms, reporting for specified interval in hours (default 1 hour). The time may be offset backwards (I.E Set offset to 8 to get a start/end time 8 hours ago)
def cgx_generate_timestamps(hours_interval=1, offset_hours=0):
    from datetime import timedelta
    from datetime import datetime
    now = (datetime.utcnow() - timedelta(hours=(offset_hours)))
    end_time = now.isoformat()
    start_time = (now - timedelta(hours=(hours_interval))).isoformat() 
    return (str(start_time)+"Z", str(end_time)+"Z") ## return (start_time, end_time) I.E. call with "(start_time, end_time) = cgx_generate_timestamps(hours_interval=8) for the last 8 hours"
#\----------------------

#/----------------------
#| cgx_generate_timestamps_days - Generates CGX start and end Timestamps used in events, alarms, reporting for specified interval in days (default 1 day or 24 hours)
def cgx_generate_timestamps_days(days_interval=1, offset_days=0):
    from datetime import timedelta
    from datetime import datetime
    now = (datetime.utcnow() - timedelta(days=(offset_days)))
    end_time = now.isoformat()
    start_time = (now - timedelta(days=(days_interval))).isoformat() 
    return (str(start_time)+"Z", str(end_time)+"Z") ## return (start_time, end_time) I.E. call with "(start_time, end_time) = cgx_generate_timestamps(days_interval=1) for the last 24 hours"
#\----------------------

#/----------------------
#| cgx_mililseconds_to_timestamp - Takes a millisecond value and converts it to a datetime stamp. Friendly_Output makes it nicer when printing output
def cgx_millseconds_to_timestamp(epoc_milliseconds, friendly_output=False):
    from datetime import datetime
    try:
        dt_object = datetime.fromtimestamp(int(epoc_milliseconds)/1000) #divide by 1000 to convert to epoch
        if friendly_output: return str(dt_object.isoformat()).split(".")[0]
        return(str(dt_object.isoformat())+"Z")
    except:
        print("Error converting time",epoc_milliseconds)
        return(epoc_milliseconds)
#\----------------------

#/----------------------
#| cgx_convert_protocol_to_name - Translates a protocol number to a friendly name. I.E. Proto 6 would return TCP
def cgx_convert_protocol_to_name(protocol_number):
    value = str(protocol_number).lower().strip()
    protocols_dict = {
        "1"   : "ICMP",
        "2"   : "IGMP",
        "6"   : "TCP",
        "4"   : "IPv4 Encap",
        "17"  : "UDP",
        "41"  : "IPv6",
        "47"  : "GRE",
        "51"  : "AH",
        "115" : "L2TP",
        "136" : "UDP-Lite",
        "143" : "Ethernet",
    }
    if value in protocols_dict.keys(): return protocols_dict[value]
    return value
#\----------------------

#/----------------------
#| safe_resolve - SAFELY finds nested keys in a DICT object with error correction in a function.
#                Usage - Instead of doing "street_address = sites['items'][0]['address']['street']"" which could have key errors and break, do this:
#                        street_address = safe_resolve(sites,'items',0,'address','street'). Any key error will be cleanly handled and "None" will be returned on error
def safe_resolve(nested_object, *keys):
   for key in keys:
       try:
           nested_object = nested_object[key]
       except:
           return None
   return nested_object
#\----------------------

#/----------------------
#| safe_sum - SAFELY sums values passed regardless of original type. E.G. safe_sum(1,2,3,"a","b",None,False,True,True) returns 6 ignoring non numerical values
def safe_sum(*values):
    total = 0
    for key in values:
        try:
            if type(key) is not bool:
                total += float(key)
        except:
            total += 0
    try:
        if int(total) == total: 
            return int(total)
        else:
            return total
    except:
        return total
#\----------------------


#/----------------------
#| cgx_average_series - takes a metrics series structure (input['metrics']['series']['data']['datapoints'][**list**]['value']) and averages it to the decimal places (default:2)
#|                  A typical call would look like: 
#|                      metrics = cgx_get_bw_consumption(sdk,start,end) ## Calls sdk.post.monitor_metrics and returns Metrics with Series in them
#|                      for series in metrics.get("metrics",[{}])[0].get("series",[]):
#|                          average = cgx_average_series(series)
def cgx_average_series(metrics_series_structure, decimal_places=2):
    count = 0
    sum = 0
    for datapoints in metrics_series_structure.get("data",[{}])[0].get("datapoints",[{}]):
        if (datapoints.get("value",None) is not None):
            count += 1
            sum += datapoints.get("value",0)
    if count != 0:
        if decimal_places == 0:
            return round((sum/count))
        return round((sum/count),decimal_places)
    return 0
#\----------------------

#/----------------------
#| cgx_percentile_series - takes a metrics series structure (input['metrics']['series']['data']['datapoints'][**list**]['value']) and gets a percentile return
#|                  A typical call would look like: 
#|                      metrics = cgx_get_bw_consumption(sdk,start,end) ## Calls sdk.post.monitor_metrics and returns Metrics with Series in them
#|                      for series in metrics.get("metrics",[{}])[0].get("series",[]):
#|                          average = cgx_average_series(series)
def cgx_percentile_series(metrics_series_structure, decimal_places=2, percentile=90):
    import numpy as np
    sum_array = []
    for datapoints in metrics_series_structure.get("data",[{}])[0].get("datapoints",[{}]):
        if (datapoints.get("value",None) is not None):
            sum_array.append( datapoints.get("value",0) )
    if len(sum_array) > 0:
        a = np.array(sum_array )
        p = np.percentile(a, percentile)
        return p
    return 0
#\----------------------

#/----------------------
#| cgx_sum_series - takes a series structure (input['series']['data']['datapoints'][**list**]['value']) and sums it to the decimal places (default:2)
#|                  A typical call would look like: 
#|                      metrics = cgx_get_bw_consumption(sdk,start,end) ## Calls sdk.post.monitor_metrics and returns Metrics with Series in them
#|                      for series in metrics.get("metrics",[{}])[0].get("series",[]):
#|                          sum = cgx_sum_series(series)
def cgx_sum_series(metrics_series_structure, decimal_places=2):
    count = 0
    sum = 0
    for datapoints in metrics_series_structure.get("data",[{}])[0].get("datapoints",[{}]):
        if (datapoints.get("value",None) is not None):
            count += 1
            sum += datapoints.get("value",0)
    if count != 0:
        if decimal_places == 0:
            return round((sum))
        return round((sum),decimal_places)
    return 0
#\----------------------

#/----------------------
#| validate_2d_array - Validates an array is 2-dimensional for use in CSV Export
def validate_2d_array(test_list):
    import numpy as np
    np_list = np.array(test_list)
    if len(np_list.shape) == 2:
        return True
    return False
#\----------------------


#/----------------------
#| write_2d_list_to_csv - Writes a 2-Dimensional list to a CSV file
def write_2d_list_to_csv(csv_file, list_2d, write_mode="w"):
    import csv
    try:
        file = open(csv_file, write_mode)
        with file:    
            write = csv.writer(file)
            write.writerows(list_2d)
            return True
        return False
    except:
        return False

#\----------------------




#######################################Examples#########################################################################
def print_alarms(sdk,alarms):
    import re
    counter=0
    for alarm in alarms:
        site_name = cgx_site_id_to_name(sdk,alarm['site_id'])
        event_desc = cgx_event_code_to_description(alarm['code'] )
        counter+=1
        #print(counter,site_name,alarm['severity'],,alarm['code'],)
        print("")
        print("Alarm",counter," - Site: ",site_name)
        print("  - Timestamp :",re.sub("\..*Z","",str(alarm['time']))   )
        print("  - Site      :",site_name   )
        print("  - Severity  :",alarm['severity']   )
        print("  - Code      :",alarm['code']   )
        print("  - Code Descr:",event_desc   )


def print_flows(sdk,flows):
    import re
    counter=0
    for flow in flows:
        app_id = cgx_app_id_to_name_cached(sdk,flow['app_id'])
        counter+=1
        direction = "LAN to WAN" if safe_resolve(flow,'lan_to_wan') else "WAN to LAN"
        print("")
        print("Flow",counter," - App: ",app_id, "- Direction:",direction)
        print("  - Flow Start  :",re.sub("\..*Z","",str(cgx_millseconds_to_timestamp(flow['flow_start_time_ms']))   ))
        print("  - Source      :",flow['source_ip'], "(" + str(flow['source_port']) + ")"  )
        print("  - Destination :",flow['destination_ip'], "(" + str(flow['destination_port']) + ")"  )
        print("  - Appliction  :",app_id , "(" + str(flow['app_id']) + ")")
        print("  - Protocol    :",cgx_convert_protocol_to_name(flow['protocol']   ))
        print("  - INIT Success:",flow['init_success']   )
        print("  - TXN Success :",flow['success_transactions']   )
        print("  - TXN Fail    :",flow['incomplete_trans']   )
        print("  - TXN Fail    :",safe_resolve(flow,'incomplete_trans')   )
        print("  - OOO Packets :", " (" + str(safe_resolve(flow,'ooo_pkts_c2s')) + "/" + str(safe_resolve(flow,'ooo_pkts_s2c') ) + ") " )
        print("  - Packet Count:", " (" + str(safe_resolve(flow,'packets_c2s')) + "/" + str(safe_resolve(flow,'packets_s2c') ) + ") " ) 
        print("  - Retrans Pkts:", " (" + str(safe_resolve(flow,'retransmit_pkts_c2s')) + "/" + str(safe_resolve(flow,'retransmit_pkts_s2c') ) + ") " ) 
        print("  - Domain      :",safe_resolve(flow,'unknown_domain') )
        print("  - PathChng rsn:",safe_resolve(flow,'wan_path_change_reason') )



#/----------------------
#| cgx_set_snmpv2_config_by_id - Modifies SNMP Configuration given a site id. Will not add where no config is present
def cgx_set_snmpv2_config_by_id(sdk, site_id=None, community=None, enabled=True):
    if not site_id: return False
    list_of_elements = cgx_get_element_ids_in_site(sdk, site_id)
    if list_of_elements:
        for element_id in list_of_elements:
            snmpagent_config = sdk.get.snmpagents(site_id, element_id).cgx_content
            if len(snmpagent_config['items']) < 1:
                return False ### No results
            snmpagent_id = snmpagent_config['items'][0]['id']
            if enabled:
                if snmpagent_config['items'][0]['v2_config'] is None:
                    snmpagent_config['items'][0]['v2_config'] = {}
                snmpagent_config['items'][0]['v2_config']['enabled'] = enabled
                if community:
                    snmpagent_config['items'][0]['v2_config']['community'] = community
            else:
                snmpagent_config['items'][0]['v2_config'] = None
            snmp_put_result = sdk.put.snmpagents(site_id, element_id, snmpagent_id, snmpagent_config['items'][0])
            return snmp_put_result
    else:
        return False
#\----------------------



def retrieve_edl_to_list(edl_url):
    response = requests.get(edl_url)
    listofdomains= re.sub('\*\.|\/',"",response.text).split()
    return listofdomains

def get_dns_service_profile(sdk, profile_name):
    result = sdk.get.dnsserviceprofiles()
    answer = None
    for dns_profile in result.cgx_content['items']:
        if dns_profile['name'] == profile_name :
            answer = sdk.get.dnsserviceprofiles(dnsserviceprofile_id=dns_profile['id']).cgx_content
            return answer
    return answer

def populate_dns_profile_breakout(dns_profile=None, fqdn_list=None, dns_primary=None, service_role_id=None):
    dns_svr_fwd_config = dns_profile['dns_forward_config']['dns_servers']
    for domain in fqdn_list:
        domain_missing = True
        for dns_fwd_entry in dns_svr_fwd_config:
            if dns_fwd_entry.get("domain_names") != None:
                if dns_fwd_entry["domain_names"][0] == domain:
                    domain_missing = False
        if (domain_missing): 
            dns_profile['dns_forward_config']['dns_servers'].append(
            {
                "ip_prefix": "",
                "domain_names": [domain],
                "dnsserver_ip": dns_primary,
                "dnsserver_port": None,
                "forward_dnsservicerole_id": service_role_id,
                "source_port": None,
                "address_family": "ipv4"
            })
    return dns_profile

def get_dns_servicerole_id(sdk, service_role_name):
    result = sdk.get.dnsserviceroles()
    for serviceroles in result.cgx_content.get('items', None):
        if serviceroles['name'] == service_role_name:
            return serviceroles['id']
    return None
