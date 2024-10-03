import re
import os
import json
import ipaddress
from typing import List, Dict, Set, Tuple
from classes import Analysis, iOSPermission, AlertInLog, ScanType, Result
from util import (
    get_source_and_destination,
    get_arp_destination,
    extract_dns_query_domain,
    broadcast_global,
    get_time,
    extract_mdns_queries,
    apple_ip,
    router_ip,
    local_network_ranges,
    is_app_scanning,
    get_other_local_addresse,
    has_scan_types,
    is_permission_type,
    create_app_id_dict,
    get_all_multicast_addresses,
    get_all_broadcast_addresses,
    get_all_local_addresses,
    remove_background_queries,
    add_results_from_first_run,
    get_scapy_protocol
)
from scapy.all import rdpcap, PacketList, DNS, DNSQR, DHCP, ICMP
from scapy.error import Scapy_Exception
from datetime import datetime


# iOS helper functions to extract the iOS traffic and analyze it
pattern = r"step (\d+)"


def get_ios_app_id(app_path: str) -> str:
    """
    Extracts the iOS app ID from the given app path.

    Args:
        app_path (str): The path of the iOS app.

    Returns:
        str: The iOS app ID.
    """
    return re.split(r"_.*\.ipa", os.path.basename(app_path))[0]


def get_ios_dataset(
    path: str, permission_list: Dict[str, iOSPermission]
) -> Tuple[List[Analysis], List[str]]:
    """
    Retrieves the iOS dataset from the given path.

    Args:
        path (str): The path of the dataset.
        permission_list (Dict[str, iOSPermission]): The dictionary containing iOS permissions.

    Returns:
        Tuple[List[Analysis], List[str]]: A tuple containing the list of analysis results and the list of failed apps.
    """
    result = []
    failed = []
    for app in os.listdir(path):
        app_path = os.path.join(path, app)
        if not os.path.isdir(app_path):
            continue
        if "out" in os.listdir(app_path):
            run_path = os.path.join(app_path, "out")
            pcap = []
            logfile = None
            tcpdump_pcap_1 = ""
            tcpdump_pcap_2 = ""

            for f in os.listdir(run_path):
                if f.startswith("."):
                    continue
                if f.endswith(".pcapng") and not f.startswith(".") and not "_decrypted.pcapng" in f:
                    pcap.append(f)
                elif f.endswith("log.log"):
                    logfile = os.path.join(run_path, f)
                elif f.endswith("_1.pcap"):
                    if os.path.getsize(os.path.join(run_path, f)) > 100:
                        tcpdump_pcap_1 = os.path.join(run_path, f)
                elif f.endswith("_2.pcap"):
                    if os.path.getsize(os.path.join(run_path, f)) > 100:
                        tcpdump_pcap_2 = os.path.join(run_path, f)

            if len(pcap) != 2:
                print(f"{app} does not have two pcap")
                failed.append(app)
                continue
            if logfile is None:
                print(f"{app} does not have log file")
                failed.append(app)
                continue

            with open(logfile, "r") as f:
                if "xcodebuild exited with code '65'" in f.read():
                    print(f"{app} failed xcodebuild exited with code '65'")
                    failed.append(app)
                    continue

            time_0 = get_time(pcap[0])
            time_1 = get_time(pcap[1])

            if time_0 < time_1:
                pcap_1 = pcap[0]
                pcap_2 = pcap[1]
            else:
                pcap_1 = pcap[1]
                pcap_2 = pcap[0]

            pcap_1 = os.path.join(run_path, pcap_1)
            pcap_2 = os.path.join(run_path, pcap_2)

            if "-2023-" in app:
                app = app.split("-2023-")[0]

            permission = permission_list.get(app, iOSPermission())

            if tcpdump_pcap_1 == "" or tcpdump_pcap_2 == "":
                result.append(
                    Analysis(
                        app,
                        pcap_1,
                        pcap_2,
                        tcpdump_pcap_1,
                        tcpdump_pcap_2,
                        iOS_information=permission,
                        log_path=logfile,
                    )
                )
            else:
                result.append(
                    Analysis(
                        app,
                        tcpdump_pcap_1,
                        tcpdump_pcap_2,
                        pcap_1,
                        pcap_2,
                        iOS_information=permission,
                        log_path=logfile,
                    )
                )
        else:
            print(f"{app} out folder missing")
            failed.append(app)

    return result, failed

def parse_iOS_permission_results(path: str) -> Dict[str, iOSPermission]:
    """
    Parses the iOS permission results from the given file path.

    Args:
        path (str): The path of the permission results file.

    Returns:
        Dict[str, iOSPermission]: A dictionary containing the iOS permissions.
    """
    result = {}
    with open(path, "r") as f:
        for line in f:
            json_data = json.loads(line)
            current = iOSPermission()
            current.app_id = get_ios_app_id(json_data["app"])
            description = set()
            bonjour_services = set()
            for k, v in json_data.items():
                if "NSLocalNetworkUsageDescription" in v:
                    description.add(v["NSLocalNetworkUsageDescription"])

                if "NSBonjourServices" in v:
                    bonjour_services.update(v["NSBonjourServices"])
            current.bonjour_services = bonjour_services
            current.description = description
            result[current.app_id] = current
    return result


def analyze_iOS_log_file(path: str) -> AlertInLog:
    """
    Analyzes the iOS log file and determines the alert type.

    Args:
        path (str): The path of the log file.

    Returns:
        AlertInLog: The type of alert in the log file.
    """
    with open(path, "r") as f:
        data = f.read()
        has_accept_interactions = False

        if "local network" not in data.lower():
            return None

        if "exploration for 10 steps" in data.lower():
            has_accept_interactions = True

        # current_line = None
        no_interaction_phase = True
        next_line_alert = False
        for line in data.splitlines():
            line = line.lower()
            if has_accept_interactions:
                if "exploration for 25 steps" in line:
                    return AlertInLog.interaction
                elif "local network" in line.lower():
                    return AlertInLog.no_interaction
            else:
                if "starting exploration step" in line:
                    match = re.search(pattern, line)
                    # Check if a match is found
                    if match:
                        # Extract the step number from the matched group
                        # current_line = int(match.group(1))
                        next_line_alert = True
                        continue
                elif next_line_alert:
                    if "local network" in line:
                        if no_interaction_phase:
                            return AlertInLog.no_interaction

                        else:
                            return AlertInLog.interaction
                    if "found alert" not in line and no_interaction_phase:
                        no_interaction_phase = False

                    next_line_alert = False
    return AlertInLog.error


# What to do for the rerun?
# 1. if multicast it should be in both pcap
# 2. if broadcast it should be in both pcap
# 3. if local it should be in both pcap
# 4. if log file -> we should find scanning in both logs and in the second dump
# _teamviewer._tcp
#0._teamviewer._tcp.local.

def has_bonjour_plist_value(bonjour_services: Set[str], queries: Set[str]) -> bool:
    for bonjour in bonjour_services:
        for query in queries:
            if bonjour in query:
                return True
#        if (
#            bonjour in queries
#            or bonjour + ".local" in queries
#            or bonjour + ".local." in queries
#            or bonjour + "local" in queries
#            or bonjour + "local." in queries
#        ):
 #           return True
    return False





def is_airplay(queries: Set[str]) -> bool:
    for query in queries:
        if (
            "_raop._tcp.local" in query 
            or "_dacp._tcp.local" in query
            or "_airplay._tcp.local" in query
            or query.endswith("._http._tcp.local")
            or query.endswith("._http._tcp.local.")

        ):
            return True
    return False

def is_airprint(queries: Set[str]) -> bool:
    for query in queries:
        if  "_universal._sub._homekit" in query:
            return True
    return False

def is_google_cast(queries: Set[str]) -> bool:
    for query in queries:
        if (
            query.endswith("_googlecast._tcp.local")
            or query.endswith("_googlecast._tcp.local.")
        ):
            return True


def is_other_bonjour(queries: Set[str]) -> bool:
    for query in queries:
        if (
            not query.endswith("_googlecast._tcp.local")
            and not query.endswith("_googlecast._tcp.local.")
            and "_universal._sub._homekit" not in query
            and "_raop._tcp.local" not in query 
            and "_dacp._tcp.local" not in query
            and "_airplay._tcp.local" not in query
            and not  query.endswith("._http._tcp.local")
            and not query.endswith("._http._tcp.local.")
        ):
            return True
    return False

def search_for_scanning_ios(
    pcap: PacketList, my_ip_cidr: str, iOSPermission: iOSPermission
) -> Tuple[bool, bool, bool, bool, Set[str], Set[str]]:
    """
    Searches for scanning activities in the iOS pcap.

    Args:
        pcap (PacketList): The pcap to analyze.
        my_ip_cidr (str): The IP address and CIDR notation of the device.
        iOSPermission (iOSPermission): The iOS permission for Bonjour services.

    Returns:
        Tuple[bool, bool, bool, bool, Set[str], Set[str]]: A tuple containing the scan results.
    """
    arp_store = set()
    multicast_store = set()
    local_net_store = set()
    broadcast = False
    contacted_addresses = set()
    dns_queries = set()
    other_local_addresses: Set[str] = set()
    bonjour_found = set()
    multicast_protocols = set()
    broadcast_protocols = set()
    icmp_router = False
    other_local = False
    icmp_external = False


    my_ip, _, network_length = my_ip_cidr.partition("/")
    ip_network = ipaddress.IPv4Network(my_ip_cidr, strict=False)
    broadcast_ip = ip_network.broadcast_address

    for packet in pcap:
        src, dst = get_source_and_destination(packet)
        if src == my_ip:
            if dst == "224.0.0.251" or dst == "239.255.255.0":
                pass
            else:
                contacted_addresses.add(dst)

        dns_query = extract_dns_query_domain(packet, my_ip)
        if dns_query is not None:
            dns_queries.add(dns_query)
        if src == my_ip and ipaddress.IPv4Address(dst) not in ip_network and ICMP in packet:
            icmp_external = True
            continue


        if src == my_ip and ipaddress.IPv4Address(dst) in ipaddress.IPv4Network(
            "224.0.0.0/4", strict=False
        ):
            # 224.0.0.22 - Router -> 239.255.255.0
            if dst == "224.0.0.251":  # bonjour
                if DNS in packet and DNSQR in packet:
                    query_names = extract_mdns_queries(packet)
                    if has_bonjour_plist_value(
                        iOSPermission.bonjour_services, query_names
                    ):
                        multicast_protocols.add(get_scapy_protocol(packet))

                        contacted_addresses.add(dst)
                        multicast_store.add(dst)
                        continue
                    if len(remove_background_queries(query_names)) > 0:
                        multicast_protocols.add(get_scapy_protocol(packet))
                        contacted_addresses.add(dst)
                        multicast_store.add(dst)
                        for query in remove_background_queries(query_names):
                            bonjour_found.add(query)

                    #    print(remove_background_queries(query_names))
                        #contacted_addresses.add(dst)
                        #multicast_store.add(dst)
                    continue
            elif dst == "239.255.255.0":
                #Bonjour service
                continue           
            else:
                multicast_protocols.add(get_scapy_protocol(packet))
                multicast_store.add(dst)
                continue

        if (
            src == my_ip and (dst == broadcast_global or dst == str(broadcast_ip))
        ):  # or (src == "0.0.0.0" and dst == broadcast_global or src == "0.0.0.0" and dst == broadcast_ip)
            # print(dst)
            # remove 0.0.0.0?
            if DHCP in packet:
                continue
            #print("Found broadcast package")
            broadcast_protocols.add(get_scapy_protocol(packet))

            broadcast = True
            continue

        if src == my_ip and ipaddress.IPv4Address(dst) in ip_network:
            if ipaddress.IPv4Address(dst) == apple_ip:
                continue
            elif ipaddress.IPv4Address(dst) == router_ip and DNSQR in packet:
                continue
            #elif ipaddress.IPv4Address(dst) == router_ip and ICMP  in packet:
            #    if not icmp_external:
            #        icmp_router = True
            #    else:
            #        continue
            elif ipaddress.IPv4Address(dst) == router_ip:
                continue
            elif dst not in ["192.168.2.1", "192.168.2.5", "192.168.2.8", "192.168.2.9", "192.168.2.207", "192.168.2.15", "192.168.2.13", "192.168.2.16", "192.168.2.10", "192.168.2.12", "192.168.2.225", "192.168.2.147", "192.168.2.110", "192.168.2.29", "192.168.2.255", "192.168.2.6"]:
                other_local = True
                
            
            local_net_store.add(dst)
            continue

        if src == my_ip and ipaddress.IPv4Address(dst) not in ip_network:
            # Your code here
            for local_network in local_network_ranges:
                if ipaddress.IPv4Address(dst) in local_network:
                    other_local_addresses.add(dst)
                    break
        arp_packet = get_arp_destination(packet, my_ip)
        if arp_packet:
            if arp_packet in ["192.168.2.1", "192.168.2.5", "192.168.2.8", "192.168.2.9", "192.168.2.207", "192.168.2.15", "192.168.2.13", "192.168.2.16", "192.168.2.10", "192.168.2.12", "192.168.2.225", "192.168.2.147", "192.168.2.110", "192.168.2.29", "192.168.2.6"]:
                continue
            arp_store.add(arp_packet)
            continue

    #if len(arp_store) >= 4:
    #    print(f"ARP-Scan detected: {', '.join(arp_store)}")

    #if len(local_net_store) >= 4:
    #    print(f"Network-Access-Scan detected: {', '.join(local_net_store)}")

    return (
        len(multicast_store) > 0,
        broadcast,
        len(local_net_store) >= 2 or other_local,
        len(arp_store) >= 1,
        contacted_addresses,
        dns_queries,
        len(other_local_addresses) >= 1,
        bonjour_found,
        multicast_protocols,
        broadcast_protocols
    )


def get_ios_result_list(
    pcap: str, my_ip_cidr: str, iOSPermission: iOSPermission
) -> Tuple[List[ScanType], Set[str], Set[str]]:
    """
    Retrieves the iOS result list from the pcap.

    Args:
        pcap (str): The pcap file path.
        my_ip_cidr (str): The IP address and CIDR notation of the device.
        iOSPermission (iOSPermission): The iOS permission for Bonjour services.

    Returns:
        Tuple[List[ScanType], Set[str], Set[str]]: A tuple containing the scan results, contacted addresses, and DNS queries.
    """
    result = []
    try:
        (
            multicast,
            broadcast,
            local,
            arp,
            contacted_addresses,
            dns_queries,
            other_local_addresses,
            bonjour_found,
            multicast_protocols,
            broadcast_protocols
        ) = search_for_scanning_ios(rdpcap(pcap), my_ip_cidr, iOSPermission)
        if multicast:
            result.append(ScanType.multicast)
        if broadcast:
            result.append(ScanType.broadcast)
        if local:
            result.append(ScanType.local)
        if arp:
            result.append(ScanType.arp)
        if other_local_addresses:
            result.append(ScanType.other_local_address)
    except Scapy_Exception:
        print(f"Exception triggered for {pcap}")
    return result, contacted_addresses, dns_queries, bonjour_found, multicast_protocols, broadcast_protocols


def analyze_ios_app(app: Analysis, my_ip_cidr: str) -> Result:
    """
    Analyzes the iOS app.

    Args:
        app (Analysis): The iOS app analysis object.
        my_ip_cidr (str): The IP address and CIDR notation of the device.

    Returns:
        Result: The analysis result.
    """
    no_interaction, contacted_addresses, dns_queries, bonjour_found, multicast_protocols_1, broadcast_protocols_1 = get_ios_result_list(
        app.pcap_1, my_ip_cidr, app.iOS_information
    )
    interaction, contacted_addresses2, dns_queries2, bonjour_found2, multicast_protocols_2, broadcast_protocols_2 = get_ios_result_list(
        app.pcap_2, my_ip_cidr, app.iOS_information
    )

    log_result = analyze_iOS_log_file(app.log_path)
    return Result(
        app.app_id,
        no_interaction,
        interaction,
        permission_data=app.iOS_information,
        log_result=log_result,
        resolved_addresses=dns_queries.union(dns_queries2),
        contacted_ip_addresses=contacted_addresses.union(contacted_addresses2),
        remaining_bonjour=bonjour_found.union(bonjour_found2),
        contacted_addresses_1=contacted_addresses,
        contacted_addresses_2=contacted_addresses2,
        multicast_protocols=multicast_protocols_1.union(multicast_protocols_2),
        broadcast_protocols=broadcast_protocols_1.union(broadcast_protocols_2)
    )


def analyze_ios(dataset: List[Analysis], my_ip_cidr: str) -> List[Result]:
    """
    Analyzes the iOS dataset.

    Args:
        dataset (List[Analysis]): The list of iOS app analysis objects.
        my_ip_cidr (str): The IP address and CIDR notation of the device.

    Returns:
        List[Result]: The list of analysis results.
    """
    result = []
    for app in dataset:
        result.append(analyze_ios_app(app, my_ip_cidr))
    return result


def read_mapping_file(path: str) -> Dict[str, Dict[str, str]]:
    """
    Reads the mapping file.

    Args:
        path (str): The path of the mapping file.

    Returns:
        Dict[str, Dict[str, str]]: The mapping file data.
    """
    result = {}
    with open(path, "r") as f:
        data = json.load(f)

        for app in data:
            result[app["app_id"]] = app

    return result


def find_apps_to_rerun(
    permission: Dict[str, iOSPermission], results: List[Result], frida = False
) -> Set[str]:
    """
    Finds the apps that need to be rerun based on the permissions and results.

    Args:
        permission (Dict[str, iOSPermission]): The dictionary containing iOS permissions.
        results (List[Result]): The list of analysis results.

    Returns:
        Set[str]: The set of app IDs that need to be rerun.
    """
    apps_to_rerun = set()
    # for k, v in permission.items():
    #    apps_to_rerun.add(k)

    for result in results:
        if is_app_scanning(result):
            apps_to_rerun.add(result.app_id)
        elif result.log_result:
            apps_to_rerun.add(result.app_id)
        elif len(get_other_local_addresse(result.contacted_ip_addresses)) > 0:
            apps_to_rerun.add(result.app_id)
        if not frida:
            if result.app_id in permission:
                apps_to_rerun.add(result.app_id)
            elif len((result.remaining_bonjour)) >0:
                apps_to_rerun.add(result.app_id)
            elif len(result.interaction) > 0 or len(result.no_interaction) > 0:
                apps_to_rerun.add(result.app_id)

    return apps_to_rerun


def create_mapping_file_for_rerun(
    permission: Dict[str, iOSPermission],
    appResults: List[Result],
    mapping_file: Dict[str, Dict[str, str]],
    frida = False
) -> List[Dict[str, str]]:
    """
    Creates a mapping file for the apps that need to be rerun.

    Args:
        permission (Dict[str, iOSPermission]): The dictionary containing iOS permissions.
        result (List[Result]): The list of analysis results.
        mapping_file (Dict[str, Dict[str, str]]): The mapping file data.

    Returns:
        List[Dict[str, str]]: The mapping file for the apps that need to be rerun.
    """
    apps = find_apps_to_rerun(permission, appResults, frida= frida)


    return get_mappings_from_app_ids(apps, mapping_file)


def get_mappings_from_app_ids(rerun_app_ids, mapping_file):
    result: List[Dict[str, str]] = []
    for app in rerun_app_ids:
        if app in mapping_file:
            result.append(
                {
                    "app_path": mapping_file[app]["app_path"],
                    "app_id": mapping_file[app]["app_id"],
                }
            )
    return result


def compare_192_168_0_161(result_1: List[Result], result_2: List[Result]):
    both = 0
    only_1 = 0
    result_map = create_app_id_dict(result_2)
    for result in result_1:
        if "192.168.0.161" in result.contacted_ip_addresses:
            matching_result = result_map.get(result.app_id, None)
            if matching_result:
                if "192.168.0.161" in matching_result.contacted_ip_addresses:
                    both += 1
                else:
                    only_1 += 1
    
    return both, only_1, both/(both+only_1), only_1/(both+only_1)


def logs_but_no_traffic(r: Result) -> bool:
    return r.log_result and str(r.log_result) != str(AlertInLog.error) and not has_scan_types(r)



def get_logs_but_no_traffic(results: List[Result]) -> List[Result]:
    """
    Retrieves the logs but no traffic results.

    Args:
        results (List[Result]): The list of analysis results.

    Returns:
        List[Result]: The list of logs but no traffic results.
    """
    result = []
    for r in results:
        if r.log_result and str(r.log_result) != str(AlertInLog.error) and not has_scan_types(r):
            result.append(r)
    return result

    

def get_nologs_but_traffic(results: List[Result]) -> List[Result]:
    """
    Retrieves the logs but no traffic results.

    Args:
        results (List[Result]): The list of analysis results.

    Returns:
        List[Result]: The list of logs but no traffic results.
    """
    result = []
    for r in results:
        if not r.log_result and has_scan_types(r):
            result.append(r)
    return result



def search_for_bonjour(results: List[Result]):
    for result in results:
        if str(ScanType.multicast) not in str(result.no_interaction) and str(ScanType.multicast) not in str(result.interaction): # maybe add log result
            try:
                if len(remove_background_queries(result.remaining_bonjour)) > 0 and get_all_multicast_addresses(result.contacted_ip_addresses):
                    print(f"{result.app_id}")
                    print(remove_background_queries(result.remaining_bonjour))
                    print(f"plist: {result.permission_data.bonjour_services}")
                    print(result.log_result)
                    print(result.no_interaction)
                    print(result.interaction)
                    print("------------------------")
            except AttributeError:
                print(f"error {result.app_id}")
                pass


# Manual analyzed, for some apps there is a race condition, with permission accept...
manual_logs_no_traffic = {
 'at.internorm.smartwindow': ScanType.broadcast,
 'com.EdigreenH.store': ScanType.broadcast,
 'com.FuChuang.GHACDVR': ScanType.local,
 'com.aidewin.zxaction': ScanType.broadcast, 
 'com.audiokitpro.AudioKitSynthOne': ScanType.multicast,
 'com.autonavi.amap': ScanType.local,
 'com.bankdo.bankaccount': ScanType.local,
 'com.broadbandspeedchecker.speedchecker': ScanType.local,
 'com.bym.band.heroband3': ScanType.local, # local outside
 'com.dji.go': ScanType.local,
 'com.dji.golite': ScanType.local,
 'com.ea.ios.apexlegendsmobilefps': ScanType.local, #  icmp 
 'com.espn.ScoreCenter': ScanType.multicast,
 'com.etips.etipsbundle140': ScanType.local,
 'com.high5.davinci.GoldenGoddessCasino': ScanType.broadcast, 
 'com.hubsoft-client-app.jk': ScanType.local,
 'com.onelifechanged.lcmsermons': ScanType.multicast,
 'com.ubisoft.dance.justdance2015companion': ScanType.broadcast,
 'com.zebra.printersetup': ScanType.multicast, 
 'com.wolow': ScanType.local,
 'com.kingwear.KingWear.Noisefit.KingWearSport': ScanType.local,  # looks like library icmp bottles of beer message
 'com.logo.pingdriver': ScanType.local,
 'com.musescore.player': ScanType.local, #local outside

 'com.promeddevs.LedWiFPinStadium': ScanType.local, #scan -Look into traffic
 'com.neotrack.live.ipcamera': ScanType.multicast,
  'net.meisterapps.samsungcm': ScanType.multicast, # and local

 'com.BkavSmartHome.SmartHomeforiPad': ScanType.own_wifi_ip , # example code
 'com.ngame.allstar.eu': ScanType.own_wifi_ip, # discard message
 'com.rootcloud.overseas.sany.india': ScanType.own_wifi_ip,
 'com.axesoft.eucclub': ScanType.own_wifi_ip, # sendPingWithData AMapSimplePing looks like library icmp bottles of beer message https://forums.developer.apple.com/forums/thread/116723
'cn.apppark.takeawayplatformtc': ScanType.own_wifi_ip, # weird mdns packet
 'com.am.magictd': ScanType.own_wifi_ip, #icmp to itself
 'com.linguee.linguee':  ScanType.own_wifi_ip,

 'com.skyjos.fileexplorerfree': ScanType.broadcast,
 'com.remotemouse.remotemouse4free': ScanType.broadcast,
 'com.tplink.Skylight': ScanType.broadcast,
 'de.gvservice.mobilwork': ScanType.broadcast,
 'nl.wienelware.huemusicsyncdiscoparty': ScanType.local,
 'com.hama.smart': ScanType.multicast, # mdns local network alert
 'us.panaramo.cardkeeper': ScanType.multicast, # cardkeeper.local mdns
 'io.dcloud.H560D3E9B': ScanType.multicast, #  chatfiles.local mdns
 'io.moapp.mo': ScanType.multicast, 
 'it.appideas.totaldownloader-free': ScanType.multicast,   #Google cast lib withoutbonjour


# local server?
# TJCacheServer - Tapoy SDK? https://developer.apple.com/forums/thread/675157
 'com.cenfee.candy06.DeerHunter1': ScanType.multicast, # filter ->  Tapoy
 'com.dss.army.commando.battle.game': ScanType.multicast, # filter -> iphone mDNS -> TJCache -> Tapoy
 'com.geargames.pfp': ScanType.multicast,  # filter -> iphone mDNS -> TJCache -> Tapoy
 'com.ivanovichgames.miniDrivers': ScanType.multicast, # again filtered -> Tapoy
 'com.kingstudios.lifeoflion': ScanType.multicast, # again filtered -> Tapoy
 'com.nordcurrent.happychefiphone': ScanType.multicast, #mdns filtered ->  Tapoy
 'com.optimesoftware.Sudoku': ScanType.multicast, #mdns filtered   -> TJCacheProtocol -> Tapoy
 'com.orientedgames.itunes.dinerCity': ScanType.multicast, #mdns filtered -> Tapoy
 'com.playwithgames.CabrioParking': ScanType.multicast, #mdns filtered -> Tapoy

 # 'BSS.TIMBERplusCamera2': None, -> local network connection not permission
 'www.gogolive.com': None, # IMSdk
 'com.tencent.ig': None,
 'pl.extollite.BedrockTogether': None, 
 'com.valemas.ios.valemasgeneric': None, #other local
 'com.yahoo.finance': None, #Spot IM Core
 'com.zoiper.zoiperiphone': None,
 'com.primo.primotalk': None, # not found
 'com.mbmobile': None, # exit after jailbreak detection - empty message
 'com.linerfone.visiofone': None,

 'com.more.dayzsurvival.ios': None,
 'com.microsoft.rdc.ios': None,
 'com.im30.ROE': None,

  'com.REscan360.REscanViewer': None, 
 'com.sena.kenwoodcamera': None, 
  'com.tplink.kasa-ios': None,
  "com.librestream.hyster.yale.group": None

 }


def copy_results(result_1: Result, result_2: Result):
    result_2.contacted_ip_addresses = result_1.contacted_ip_addresses
    result_2.resolved_addresses = result_1.resolved_addresses
    result_2.remaining_bonjour = result_1.remaining_bonjour
    result_2.no_interaction = result_1.no_interaction
    result_2.interaction = result_1.interaction
    result_2.multicast_protocols = result_1.multicast_protocols
    result_2.broadcast_protocols = result_1.broadcast_protocols
    result_2.log_result = result_1.log_result
    result_2.permission_data = result_1.permission_data
    return result_2



def add_scan_type_for_logs(results_1: List[Result], results_2: List[Result]) -> List[Result]:
    updated: List[Result] = []
    results_1_map = create_app_id_dict(results_1)

    for result in results_2:
        result_1 = results_1_map.get(result.app_id, None)
        if not result_1:
            continue

        if len(result.remaining_bonjour) > 0 and len(result_1.remaining_bonjour) > 0:
            for address in remove_background_queries(result.remaining_bonjour):
                if address in remove_background_queries(result_1.remaining_bonjour):
                    to_add = None
                    if is_airplay(result.remaining_bonjour & result_1.remaining_bonjour):
                        to_add = ScanType.airplay
                    else:
                        to_add = ScanType.multicast
                    
                    if str(to_add) not in str(result.no_interaction+result.interaction):
                        if "224.0.0.251" in result.contacted_addresses_1:
                            result.no_interaction.append(to_add)
                            result_1.no_interaction.append(to_add)

                        if "224.0.0.251" in result.contacted_addresses_2:
                            result.interaction.append(to_add)
                            result_1.interaction.append(to_add)



    for result_2 in results_2:

        result_1 = results_1_map.get(result_2.app_id, None)
        if not result_1:
            #print("no result for first")
            #print(result.app_id)
            continue


        if logs_but_no_traffic(result_2) and is_app_scanning(result_1):
            copy_results(result_1, result_2)
            updated.append(result_2)
        elif logs_but_no_traffic(result_1) and is_app_scanning(result_2):
            copy_results(result_2, result_1)

        elif result_2.app_id in manual_logs_no_traffic:
            if str(result_2.log_result) == str(AlertInLog.no_interaction):
                if str(manual_logs_no_traffic[result_2.app_id]) not in str(result_2.no_interaction):
                    result_2.no_interaction.append(manual_logs_no_traffic[result_2.app_id])
            elif str(result_2.log_result) == str(AlertInLog.interaction):
                if str(manual_logs_no_traffic[result_2.app_id]) not in str(result_2.interaction):
                    result_2.interaction.append(manual_logs_no_traffic[result_2.app_id])
        elif logs_but_no_traffic(result_2) or logs_but_no_traffic(result_1):
            if result_2.app_id == "BSS.TIMBERplusCamera2":
                result_2.log_result = None # they don't trigger the permission but instead write that the app should connect to a local network
                continue
            print(f"Analyze manual: {result_2.app_id}")
            

    return updated
        
def bonjour_without_string(results_1: List[Result], results_2: List[Result], output_logs = False) -> (List[str], List[str], List[str], List[str]):
    app_results = []
    airplay = []
    airprint = []
    google_cast = []
    other = []
    results_1_map = create_app_id_dict(results_1)

    for result in results_2:
        if result.app_id not in results_1_map:
            continue
        result_1 = results_1_map[result.app_id]
        if "224.0.0.251" in result.contacted_ip_addresses and "224.0.0.251" in result_1.contacted_ip_addresses:
            try:
                if (result_1.remaining_bonjour and result.remaining_bonjour) and ( not result.permission_data.bonjour_services or len(result.permission_data.bonjour_services) == 0):
                    print_result = False
                    for address in result_1.remaining_bonjour:
                        if address in result.remaining_bonjour:
                            print_result = True
                            break
                    
                    if print_result and output_logs:
                        print(result.app_id)
                        print(f"run2 {result.remaining_bonjour}")
                        print(f"run1 {result_1.remaining_bonjour}")
                        print(f"plist: {result.permission_data.bonjour_services}")
                        print(f"logs: {result.log_result}")
                        print(f"no interaction: {result.no_interaction}")
                        print(f"iteraction: {result.interaction}")
                    if print_result:
                        app_results.append(result.app_id)
                        if is_airplay(result.remaining_bonjour & result_1.remaining_bonjour):
                            airplay.append(result.app_id)
                        if is_airprint(result.remaining_bonjour & result_1.remaining_bonjour):
                            airprint.append(result.app_id)
                        if is_google_cast(result.remaining_bonjour & result_1.remaining_bonjour):
                            google_cast.append(result.app_id)
                        if is_other_bonjour(result.remaining_bonjour & result_1.remaining_bonjour):
                            other.append(result.app_id)

            except AttributeError:
                pass

    return app_results, airplay, airprint, google_cast, other



def get_prompt_stats(dataset: List[Result]) -> Tuple[List[Result], List[Result]]:
    with_permission = []
    without_permission = []
    for result in dataset:
        if not is_app_scanning(result) and not result.log_result:
            continue
        if result.permission_data.description:
            with_permission.append(result)
        else:
            without_permission.append(result)
    return with_permission, without_permission



def get_all_scanning(results: List[Result]) -> List[Result]:
    """
    Retrieves all scanning results.

    Args:
        results (List[Result]): The list of analysis results.

    Returns:
        List[Result]: The list of scanning results.
    """
    result = []
    for r in results:
        if  is_app_scanning(r) or r.log_result:
            result.append(r)
    return result







def get_release_date(app_id, mapping_file, metadata_base_path="//appstore_crawler/ids_us_september/amp"):
    playstore_id = os.path.basename(mapping_file.get(app_id, None).get("app_path","")).split("_")[1] # Decided to use file path as the id's are sometimes none, while the ones in the path not
    if not playstore_id:
        return None
    metadata_path = os.path.join(metadata_base_path, playstore_id+".json")
    if not os.path.exists(metadata_path):
        return None
    with open(metadata_path, "r") as f:
        data = json.load(f)
        return data.get("data", [{}])[0].get("attributes", {}).get("platformAttributes", {}).get("ios", {}).get("versionHistory", [{}])[0].get("releaseDate", None)
    
    return None


def get_apps_released_after_permission(apps :List[str], mapping_file):
    result = []
    permission = datetime.strptime("2020-09-16", "%Y-%m-%d")

    for app in apps:
        if app == "com.eurosport.EurosportNews" or app == "com.iona-energy.ios" or app == "io.pushpay.wchsheralds" or app == "com.echurchapps.rivervalleycc" :
            result.append(app)
            continue
        if app == "com.audiokitpro.AudioKitSynthOne" or app == "fr.ville-roubaix.vivacite":
            #com.audiokitpro.AudioKitSynthOne a bit newer than permission but targeted for  13.2 (permission introduced in 14)
            #fr.ville-roubaix.vivacite older than permission

            continue
        date = get_release_date(app, mapping_file)
        if date is None:
            print(app)
            continue
        date = datetime.strptime(date, "%Y-%m-%d")


        if date > permission :
            result.append(app)
    return result


def only_airplay_or_airprint(result: Result):
    return not has_scan_types(result) and str(ScanType.airplay) in str(result.no_interaction + result.interaction)


def get_number_of_apps_only_airplay_or_airprint(results: List[Result]):
    return len([result for result in results if only_airplay_or_airprint(result)])