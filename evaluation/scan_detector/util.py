from classes import ScanType, Result
from scapy.layers.http import HTTPRequest
from scapy.all import DNSQR, DNS, Packet, rdpcap 
import ipaddress
import os
from datetime import datetime
import json
from typing import List, Dict, Tuple, Any, Optional, Set
import pyshark
import re
from urllib.parse import parse_qs, urlparse

## Global variables

broadcast_global: str = "255.255.255.255"
apple_ip: ipaddress.IPv4Address = ipaddress.IPv4Address("192.168.2.110")
router_ip: ipaddress.IPv4Address = ipaddress.IPv4Address("192.168.2.1")
local_network_ranges: List[ipaddress.IPv4Network] = [ipaddress.IPv4Network("10.0.0.0/8"), ipaddress.IPv4Network("172.16.0.0/12"), ipaddress.IPv4Network("192.168.0.0/16")]

# ----------------------------

# Helper functions
timestamp_format: str = "%Y%m%d_%H%M%S"


def get_time(folder_name: str) -> datetime:
    """
    Get the time from a folder name.

    Args:
        folder_name: The name of the folder.

    Returns:
        The datetime object representing the time.
    """
    time = folder_name.replace("_traffic.pcapng", "")
    return datetime.strptime(time, timestamp_format)


def create_remove_failed_command(base_path: str, failed: List[str]) -> List[str]:
    """
    Create a list of remove commands for failed files.

    Args:
        base_path: The base path of the files.
        failed: A list of failed file names.

    Returns:
        A list of remove commands.
    """
    result = []
    for fail in failed:
        result.append(f"rm -r {os.path.join(base_path, fail)}")

    for f in result:
        print(f)
    return result


# ----------------------------
def get_dataset_ids_from_file(path: str) -> List[str]:
    """
    Retrieves the iOS dataset from the given file path.

    Args:
        path (str): The path of the dataset.

    Returns:
        List[str]: The list of iOS app IDs.
    """
    result = []
    with open(path, "r") as f:
        for line in f:
            result.append(line.strip())
    return result   


def get_matching_results(
    results: List[Result], dataset_ids: List[str]
) -> List[Result]:
    """
    Get the results that match the given dataset IDs.

    Args:
        results: The list of results.
        dataset_ids: The list of dataset IDs.

    Returns:
        The list of results that match the given dataset IDs.
    """
    result = []
    for res in results:
        if res.app_id in dataset_ids:
            result.append(res)
    return result

# Scapy functions
def get_source_and_destination(packet: Packet) -> Tuple[str, str]:
    """
    Get the source and destination IP addresses from a packet.

    Args:
        packet: The packet.

    Returns:
        A tuple containing the source and destination IP addresses.
    """
    src, dst = "", ""
    if packet.haslayer("IP"):
        src = packet["IP"].src
        dst = packet["IP"].dst
    return src, dst


def get_arp_destination(packet: Packet, my_ip: str) -> str:
    """
    Get the destination IP address from an ARP packet.

    Args:
        packet: The ARP packet.
        my_ip: The IP address of the current device.

    Returns:
        The destination IP address.
    """
    if packet.haslayer("ARP"):
        src_ip = packet["ARP"].psrc
        dst_ip = packet["ARP"].pdst
        if src_ip == my_ip:
            return dst_ip
    return ""


def extract_hostname(dhcp_options: List[Tuple[str, Any]]) -> Optional[str]:
    """
    Extract the hostname from DHCP options.

    Args:
        dhcp_options: The DHCP options.

    Returns:
        The hostname if found, None otherwise.
    """
    for option_code, option_value in dhcp_options:
        if option_code == "hostname":
            return option_value.decode("utf-8")

    return None


def extract_dns_query_domain(packet: Packet, my_ip: str) -> Optional[str]:
    """
    Extract the domain name from a DNS query packet.

    Args:
        packet: The DNS query packet.

    Returns:
        The domain name if found, None otherwise.
    """
    src,_ = get_source_and_destination(packet)
    if src == my_ip and DNSQR in packet and packet[DNS].opcode == 0:  # Check if it's a DNS query packet
        domain_name = packet[DNSQR].qname.decode("utf-8")
        return domain_name
    return None


def extract_mdns_queries(packet: Packet) -> Set[str]:
    """
    Extract the mDNS queries from a packet.

    Args:
        packet: The packet.

    Returns:
        A set of mDNS queries.
    """
    result = set()
    if DNSQR in packet:
        for dns_question in packet[DNS].qd.iterpayloads():
            queries = dns_question.qname
            result.add(queries.decode("utf-8"))
    return result


# ----------------------------


def safe_file(path: str, data: Any) -> None:
    """
    Safely write data to a file.

    Args:
        path: The path of the file.
        data: The data to write.
    """
    with open(path, "w") as f:
        json.dump(data, f)


# ----------------------------


# Evaluation


def get_stats(
    results: List[Result],
    add_local_or_arp: bool = False,
    airplay_or_multicast: bool = False
) -> Tuple[
    int,
    int,
    int,
    int,
    int,
    Dict[str, int],
    Dict[str, int],
    Dict[str, int],
    Dict[str, int],
    Dict[str, int],
]:
    """
    Get statistics from the results.

    Args:
        results: The list of results.

    Returns:
        A tuple containing the statistics.
    """
    scanning = 0
    no_interaction = 0
    interaction = 0
    scanning_map = {}
    interaction_map = {}
    no_interaction_map = {}
    only_no_interaction = 0
    only_interaction = 0
    only_no_interaction_map = {}
    only_interaction_map = {}
    for app in results:
        try:
            if str(ScanType.multicast_or_airplay) in str(app.interaction):
                for i in range(0, len(app.interaction)):
                    key = app.interaction[i]
                    if str(key) == str(ScanType.multicast_or_airplay):
                        del app.interaction[i]
                        break

                        
            if str(ScanType.local_or_arp) in str(app.interaction):
                for i in range(0, len(app.interaction)):
                    key = app.interaction[i]
                    if str(key) == str(ScanType.local_or_arp):
                        del app.interaction[i]
                        break
            for key in app.interaction:
                if add_local_or_arp and (str(key) == str(ScanType.arp) or str(key) == str(ScanType.local)) and str(ScanType.local_or_arp) not in str(app.interaction):
                    app.interaction.append(ScanType.local_or_arp)
                if (str(key) == str(ScanType.multicast) or str(key) == str(ScanType.airplay)) and str(ScanType.multicast_or_airplay) not in str(app.interaction) and airplay_or_multicast:
                    app.interaction.append(ScanType.multicast_or_airplay)
                if (str(key) == str(ScanType.multicast)) and not airplay_or_multicast and str(ScanType.multicast_or_airplay) not in str(app.interaction):
                    app.interaction.append(ScanType.multicast_or_airplay)
        except ValueError as e:
            print(e)
            pass
        try:
            if str(ScanType.multicast_or_airplay) in str(app.no_interaction):
                for i in range(0, len(app.no_interaction)):
                    key = app.no_interaction[i]
                    if str(key) == str(ScanType.multicast_or_airplay):
                        del app.no_interaction[i]
                        break
            if str(ScanType.local_or_arp) in str(app.no_interaction):
                for i in range(0, len(app.no_interaction)):
                    key = app.no_interaction[i]
                    if str(key) == str(ScanType.local_or_arp):
                        del app.no_interaction[i]
                        break
            for key in app.no_interaction:
                if add_local_or_arp and (str(key) == str(ScanType.arp) or str(key) == str(ScanType.local)) and str(ScanType.local_or_arp) not in str(app.no_interaction):
                    app.no_interaction.append(ScanType.local_or_arp)
                if (str(key) == str(ScanType.multicast) or str(key) == str(ScanType.airplay)) and str(ScanType.multicast_or_airplay) not in str(app.no_interaction) and airplay_or_multicast:
                    app.no_interaction.append(ScanType.multicast_or_airplay)
                if (str(key) == str(ScanType.multicast)) and str(ScanType.multicast_or_airplay) not in str(app.no_interaction) and not airplay_or_multicast:
                    app.no_interaction.append(ScanType.multicast_or_airplay)

        except ValueError:
            pass

        if is_app_scanning(app):
            scanning = scanning + 1

        if is_phase_scanning(app.no_interaction):
            no_interaction = no_interaction + 1

        if is_phase_scanning(app.interaction):
            interaction = interaction + 1

        if is_phase_scanning(app.no_interaction) and not is_phase_scanning(app.interaction):

            only_no_interaction = only_no_interaction + 1

        if not is_phase_scanning(app.no_interaction)  and is_phase_scanning(app.interaction):

            only_interaction = only_interaction + 1

        # if ScanType.local in set(app.no_interaction + app.interaction) and not ScanType.arp in set(app.no_interaction + app.interaction):
        #    print(app.app_id)
        for scan in set(app.no_interaction + app.interaction):
            if str(scan) == str(ScanType.multicast) or str(scan) == str(ScanType.airplay) or str(scan) == str(ScanType.arp) or str(scan) == str(ScanType.local):
                continue
            # if str("ScanType.multicast") == str(scan):
            #    print(ten_mio[i].app_id)

            scanning_map[str(scan)] = scanning_map.get(str(scan), 0) + 1
            if scan in app.no_interaction:
                no_interaction_map[str(scan)] = no_interaction_map.get(str(scan), 0) + 1
                if scan not in app.interaction:
                    only_no_interaction_map[str(scan)] = (
                        only_no_interaction_map.get(str(scan), 0) + 1
                    )

                    # if str("ScanType.multicast") == str(scan):
                    #    print("only no interaction")
            if scan in app.interaction:
                interaction_map[str(scan)] = interaction_map.get(str(scan), 0) + 1
                if scan not in app.no_interaction:
                    only_interaction_map[str(scan)] = only_interaction_map.get(str(scan), 0) + 1
                    # if str("ScanType.multicast") == str(scan):
                    #    print("only interaction")


    return (
        scanning,
        no_interaction,
        interaction,
        only_no_interaction,
        only_interaction,
        scanning_map,
        no_interaction_map,
        interaction_map,
        only_no_interaction_map,
        only_interaction_map,
    )



def is_permission_type(scan_type):
    permission_access_type = {
    ScanType.multicast,
    ScanType.broadcast,
    ScanType.local,
    ScanType.arp,
    ScanType.local_or_arp,
    ScanType.multicast_or_airplay
    }
    return str(scan_type) in str(permission_access_type)

def has_scan_types(results):
    return any(is_permission_type(scan_type) for scan_type in (results.no_interaction+ results.interaction))


def is_app_scanning(app: Result) -> bool:
    return has_scan_types(app)


def is_phase_scanning(result_phase) -> bool:
    return any(is_permission_type(scan_type) for scan_type in result_phase)

def get_scanning_results(dataset: List[Result]) -> List[Result]:
    result = []
    for app in dataset:
        if is_app_scanning(app):
            result.append(app)
    
    return result

def get_apps_for_rerun(dataset: List[Result]) -> List[Result]:
    result = []
    for app in dataset:
        if is_app_scanning(app) or len(get_other_local_addresse(app.contacted_ip_addresses)) > 0:
            result.append(app)
    
    return result

def write_app_ids_to_file(results: List[Result], file_path: str) -> None:
    with open(file_path, 'w') as file:
        for result in results:
            file.write(result.app_id + '\n')



def get_only_matching_results(android_dataset: List[Result], ios_dataset: List[Result], mapping_ios_to_android: {str, str}) -> Dict[Result, Result]:
    matching_results = {}
    for app in ios_dataset:
        if app.app_id in mapping_ios_to_android:
            for android_app in android_dataset:
                if android_app.app_id == mapping_ios_to_android[app.app_id]:
                    matching_results[app] = android_app
                    break

    return matching_results

def get_result_map(results: List[Result]) -> Dict[str, Result]:
    result = {}
    for res in results:
        result[res.app_id] = res
    return result


def get_other_local_addresse(contacted_addresses: List[str], my_ip_cidr: str = "192.168.2.1/24") -> List[str]:
    result = set()
    for local_network in local_network_ranges:
        for ip in contacted_addresses:
            if ip == "192.168.0.161":
                #artifact from test (jailbreak?)
                continue
            if ipaddress.IPv4Address(ip) not in ipaddress.IPv4Network(my_ip_cidr, strict=False) and ipaddress.IPv4Address(ip) in local_network:
                result.add(ip)
    return list(result)
# ----------------------------


def read_all_matches(path: str):
    result = []
    for f in os.listdir(path):
        if "matches_" in f:
            with open(f"{path}/{f}", "r") as jf:
                result.append(json.load(jf))
    return result

def get_only_matches(matches: List):
    result = []
    for m in matches:
        result.extend(m.get("translation", []))
    
    return result

def get_ios_to_android(matches: List[Dict]) -> Dict[str, str]:
    result = {}
    for m in matches:
        if "packageName" in m:
            android = m["packageName"]
            if m["bundleId"] in result and android != result[m['bundleId']]:
                print(f"{m['bundleId']}   -   {android} already a match was found: {result[m['bundleId']]}")
            result[m["bundleId"]] = android
    return result



def add_cpp_matches(path: str, matches: Dict[str, str]) -> Dict[str, str]:
    with open(path, "r") as f:
        data = json.load(f)
        for item in data:
            bundleId = item["_id"]
            package_name = item["best_match"]["android_id"]
            if bundleId not in matches:
                matches[bundleId] = package_name
    return matches



# ------------Search for URI and Payloads----------------

def http2_json_packets(p):
    if p.headers_method == 'POST':
        return p.headers_scheme + '://' + p.headers_authority + p.headers_path, p.json_member_with_value
    elif p.headers_method == 'GET':
        return p.headers_scheme + '://' + p.headers_authority + p.headers_path, None



def extract_packet(packet):
    uri_and_payload = {}
    if 'HTTP' in packet:
        if hasattr(packet.http, 'request_full_uri'):
            url_path = packet.http.request_full_uri
            uri_and_payload['uri'] = url_path
        elif hasattr(packet.http, 'response_for_uri'):
            url_path = packet.http.response_for_uri
            uri_and_payload['uri'] = url_path
        else:
            return uri_and_payload
    

        if hasattr(packet.http, 'file_data'):
            # Access the payload of the HTTP packet
            payload = packet.http.file_data
            uri_and_payload['payload'] = payload
        
    if 'HTTP2' in packet:
        try: 
            if packet.layers[-1].layer_name == 'http2':
                url_path, payload = http2_json_packets(packet.layers[-1])
            else:
                url_path, payload = http2_json_packets(packet.http2)
            
            uri_and_payload['uri'] = url_path

            if payload != None:
                uri_and_payload['payload'] = payload
            

        except:
            pass
    return uri_and_payload


def extract_url_paths(packets) -> Tuple[List[dict], List[dict]] :
    uris_and_payloads = []
    local_communication = []
    for packet in packets:
        uri_and_payload = extract_packet(packet)
        if "/status" in uri_and_payload.get('uri', '') or "/session" in uri_and_payload.get("uri", ''):
            continue
        uris_and_payloads.append(uri_and_payload)
    return (uris_and_payloads, local_communication)



# Source: https://blog.netwrix.com/2018/05/29/regular-expressions-for-beginners-how-to-get-started-discovering-sensitive-data/
patterns = {
    'ipv4': r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'ipv6': r'^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,6}:)|((:[0-9a-fA-F]{1,4}){1,7})$', # chatgpt
    'mac': r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b',  # Source: https://stackoverflow.com/questions/4260467/what-is-a-regular-expression-for-a-mac-address
}
compiled_patterns = {key: re.compile(pattern, re.IGNORECASE) for key, pattern in patterns.items()}

sensitive_keywords = ['wifi', 'ssid', 'mac', "192.168.2."]



def check_against_regex(string, uri): # -> findings (where, type, what)
    result = set()

    for key, pattern in compiled_patterns.items():
        matches = pattern.findall(string)
        if matches:
            #for match in matches:
            result.add((uri, key, "regex"))

    return result

def check_against_keywords(string, uri, device_keywords: Set[str]):
    results = set()
    found_keywords = set()

    lower_string = string.lower()
    for word in sensitive_keywords + device_keywords:
        if word.lower() in lower_string:
            found_keywords.add(word)

    if found_keywords:
        for word in found_keywords:
            results.add((uri, "keyword", word))
    return results

def get_domain_from_uri(uri):
    parsed_url = urlparse(uri)
    return parsed_url.netloc

def parse_uri_parameters_to_json(uri):
    parsed_uri = urlparse(uri)
    query_params = parse_qs(parsed_uri.query)
    param_dict = {}
    for param, values in query_params.items():
        param_dict[param] = values[0]

    return json.dumps(param_dict)


def get_payload_from_encoded_string(payload):
    query_params = parse_qs(payload)

    for param_name, param_values in query_params.items():
        for i, param_value in enumerate(param_values):
            try:
                param_dict = json.loads(param_value)
                query_params[param_name][i] = param_dict
            except json.JSONDecodeError:
                pass

    return json.dumps(query_params)


def extract_pii_from_json(json_string, uri, device_keywords):

    extracted_from_regex = check_against_regex(json_string, uri)
    extracted_from_keywords = check_against_keywords(json_string, uri, device_keywords)

    return extracted_from_regex.union(extracted_from_keywords)


def search_for_local_leaks(path: str, local_information_path: str = "./local_information.json"):
    # 1. We want to analyze traffic send to local addresses
    # 2. We want to search for data leaks
    result = []
    device_keywords = read_device_file(path=local_information_path)
    if not os.path.exists(path):
        print(f"{path} does not exist")
        return
    with  pyshark.FileCapture(path, display_filter='http or http2') as packets:
        r, l = extract_url_paths(packets)
        for info in r: 
            uri = info.get('uri', 'no_uri')  # Get the URI from the entry
            domain = get_domain_from_uri(uri)
            if "192.168.2." in domain: #local endpoint skip for now
                continue
            payload = info.get('payload', '')  # Get the payload from the entry

            uri_json = parse_uri_parameters_to_json(uri)
            uri_result = extract_pii_from_json(uri_json, domain, device_keywords)
            result.extend(uri_result)
            if payload:
                extracted = extract_pii_from_json(payload, domain, device_keywords)
                if len(extracted) ==0 :
                    payload_json = get_payload_from_encoded_string(payload)
                    extracted = extract_pii_from_json(payload_json, domain, device_keywords)
                
                result.extend(extracted)


    return result

def extract_all_values(data):
    result = set()
    for k,v in data.items():
        if isinstance(v, dict):
            result.update(extract_all_values(v))
        else:
            result.add(v.lower())
            if ":" in v:
                result.add(v.replace(":", "").lower())

    return list(result)

def read_device_file(path: str = "./local_information.json"):
    with open(path, "r") as f:
        return extract_all_values(json.load(f))



def create_app_id_dict(results: List[Result]) -> Dict[str, Result]:
    """
    Creates a dictionary of app IDs and results.

    Args:
        results (List[Result]): The list of analysis results.

    Returns:
        Dict[str, Result]: The dictionary of app IDs and results.
    """
    result = {}
    for r in results:
        result[r.app_id] = r
    return result


def get_all_multicast_addresses(contacted_addresses: Set[str]) -> Set[str]:
    """
    Retrieves all multicast addresses from the contacted addresses and DNS queries.

    Args:
        contacted_addresses (Set[str]): The set of contacted addresses.
        dns_queries (Set[str]): The set of DNS queries.

    Returns:
        Set[str]: The set of all multicast addresses.
    """
    result = set()
    for address in contacted_addresses:
        if ipaddress.IPv4Address(address) in ipaddress.IPv4Network("224.0.0.0/4"):
            result.add(address)
    return result

def get_all_broadcast_addresses(contacted_addresses: Set[str], network_broadcast: str= "192.168.2.255") -> Set[str]:
    """
    Retrieves all multicast addresses from the contacted addresses and DNS queries.

    Args:
        contacted_addresses (Set[str]): The set of contacted addresses.
        dns_queries (Set[str]): The set of DNS queries.

    Returns:
        Set[str]: The set of all multicast addresses.
    """
    result = set()
    for address in contacted_addresses:
        if address == "255.255.255.255" or address == network_broadcast:
            result.add(address)
    return result


def get_all_local_addresses(contacted_addresses: Set[str], ip_cidr: str = "192.168.2.1/24") -> Set[str]:
    """
    Retrieves all local addresses from the contacted addresses and DNS queries.

    Args:
        contacted_addresses (Set[str]): The set of contacted addresses.
        dns_queries (Set[str]): The set of DNS queries.

    Returns:
        Set[str]: The set of all local addresses.
    """
    result = set()
    ip_network = ipaddress.IPv4Network(ip_cidr, strict=False)
    router = ip_cidr.split("/")[0]
    for address in contacted_addresses:
        if ipaddress.IPv4Address(address) in ip_network and not ipaddress.IPv4Address(address) == apple_ip and not address == str(ip_network.broadcast_address) and not address == router:
            result.add(address)
    return result


def get_scanning_or_airplay(results: List[Result]) -> List[Result]:
    """
    Retrieves all scanning results.

    Args:
        results (List[Result]): The list of analysis results.

    Returns:
        List[Result]: The list of scanning results.
    """
    result = []
    for r in results:
        if  is_app_scanning(r) or r.log_result or str(ScanType.airplay) in str(r.no_interaction + r.interaction):
            result.append(r)
    return result




def remove_scan_type(run: List[ScanType], scan_type: ScanType):
    """
    Removes the given scan type from the results.

    Args:
        results (List[Result]): The list of results.
        scan_type (ScanType): The scan type to remove.

    Returns:
        List[Result]: The list of results without the given scan type.
    """
    for r in run:
        if str(scan_type) == str(r):
            run.remove(r)
            return

    
def remove_wrong_addresses(results_1: List[Result], results_2: List[Result]):
    results_1_map = create_app_id_dict(results_1)


    for result in results_2:
        matching_result = results_1_map.get(result.app_id, None)
        if not matching_result:
            continue
        other_2 = get_other_local_addresse(result.contacted_ip_addresses) + list(get_all_multicast_addresses(result.contacted_ip_addresses)) + list(get_all_broadcast_addresses(result.contacted_ip_addresses))
        other_1 = get_other_local_addresse(matching_result.contacted_ip_addresses) + list(get_all_multicast_addresses(matching_result.contacted_ip_addresses)) + list(get_all_broadcast_addresses(matching_result.contacted_ip_addresses))
        for address in set(other_2 + other_1):
            if address in result.contacted_ip_addresses and address in matching_result.contacted_ip_addresses:
                continue
            elif address in result.contacted_ip_addresses:
                result.contacted_ip_addresses.remove(address)
            elif address in matching_result.contacted_ip_addresses:
                matching_result.contacted_ip_addresses.remove(address)
        if len(get_other_local_addresse(result.contacted_ip_addresses)) == 0:
            if str(ScanType.other_local_address) in str(result.interaction):
                remove_scan_type(result.interaction, ScanType.other_local_address)
            if str(ScanType.other_local_address)    in str(result.no_interaction):
                remove_scan_type(result.no_interaction, ScanType.other_local_address)

        if len(get_all_multicast_addresses(result.contacted_ip_addresses)) == 0:
            if str(ScanType.multicast) in str(result.interaction):
                remove_scan_type(result.interaction, ScanType.multicast)
            if str(ScanType.multicast) in str(result.no_interaction):
                remove_scan_type(result.no_interaction, ScanType.multicast)

        if len(get_all_broadcast_addresses(result.contacted_ip_addresses)) == 0:
            if str(ScanType.broadcast) in str(result.interaction):
                remove_scan_type(result.interaction, ScanType.broadcast)
            if str(ScanType.broadcast) in str(result.no_interaction):
                remove_scan_type(result.no_interaction, ScanType.broadcast)


def only_googlecast_mdns(contacted_mdns):
    only_googlecast = True
    for query in contacted_mdns:
        if "_googlecast." not in query and "google_background" not in query:
            only_googlecast = False
            break
    return only_googlecast


def match_google_cast_queries(contacted_mdns_1, contacted_mdns_2):
    for query in contacted_mdns_2:
        if "google_background" in query:
            continue
        if query not in contacted_mdns_1:
            return False
    
    return True

def get_googlecast_queries(contacted_mdns):
    cast = []
    for query in contacted_mdns:
        if "_googlecast." in query or "google_background" in query:
            cast.append(query)
    
    return cast

def get_airplay_queries(contacted_mdns):
    airplay = []
    for query in contacted_mdns:
        if (
            "_raop._tcp.local" in query 
            or "_dacp._tcp.local" in query
            or "_airplay._tcp.local" in query
            or query.endswith("._http._tcp.local")
            or query.endswith("._http._tcp.local.")

        ):
            airplay.append(query)

    return airplay
    

    

def remove_false_positive(results_1: List[Result], results_2: List[Result]) -> List[Result]:
    results_1_map = create_app_id_dict(results_1)
    all_scanning = []

    remove_wrong_addresses(results_1, results_2)

    for result_2 in get_scanning_or_airplay(results_2):
        matching_result = results_1_map.get(result_2.app_id, None)
        if matching_result:
            if result_2.log_result and matching_result.log_result:
                all_scanning.append(result_2)
                continue
         

            #compare broadcast addresses
            if str(ScanType.multicast) in str(result_2.no_interaction + result_2.interaction):

                if str(ScanType.multicast) not in str(matching_result.no_interaction + matching_result.interaction) and str(ScanType.multicast) in str(result_2.no_interaction + result_2.interaction):
                    if str(ScanType.multicast) in str(result_2.no_interaction):
                        remove_scan_type(result_2.no_interaction, ScanType.multicast)
                    if str(ScanType.multicast) in str(result_2.interaction):
                        remove_scan_type(result_2.interaction, ScanType.multicast)
                            

                if len(get_all_multicast_addresses(result_2.contacted_ip_addresses)) == 1 and "224.0.0.251" in result_2.contacted_ip_addresses and len(remove_background_queries(result_2.remaining_bonjour)) == 0:
                    if str(ScanType.multicast) in str(result_2.no_interaction):
                        remove_scan_type(result_2.no_interaction, ScanType.multicast)
                    if str(ScanType.multicast) in str(result_2.interaction):
                        remove_scan_type(result_2.interaction, ScanType.multicast)

                if len(get_all_multicast_addresses(result_2.contacted_ip_addresses)) == 1 and "224.0.0.251" in result_2.contacted_ip_addresses and len(get_airplay_queries(result_2.remaining_bonjour))  == len(result_2.remaining_bonjour):
                    if str(ScanType.multicast) in str(result_2.no_interaction):
                        remove_scan_type(result_2.no_interaction, ScanType.multicast)
                        if str(ScanType.airplay) not in str(result_2.no_interaction):
                            result_2.no_interaction.append(ScanType.airplay)
                    if str(ScanType.multicast) in str(result_2.interaction):
                        remove_scan_type(result_2.interaction, ScanType.multicast)
                        if str(ScanType.airplay) not in str(result_2.interaction):
                            result_2.interaction.append(ScanType.airplay)


            if str(ScanType.broadcast) in str(result_2.no_interaction + result_2.interaction):
                if str(ScanType.broadcast) not in str(matching_result.no_interaction + matching_result.interaction) and str(ScanType.broadcast) in str(result_2.no_interaction + result_2.interaction) :
                    if str(ScanType.broadcast) in str(result_2.no_interaction):
                        remove_scan_type(result_2.no_interaction, ScanType.broadcast)
                    if str(ScanType.broadcast) in str(result_2.interaction):
                        remove_scan_type(result_2.interaction, ScanType.broadcast)
                        


            if str(ScanType.local) in str(result_2.no_interaction + result_2.interaction) or str(ScanType.arp) in str(result_2.no_interaction + result_2.interaction):
                if (str(ScanType.local) not in str(matching_result.no_interaction + matching_result.interaction) and str(ScanType.arp) not in str(matching_result.no_interaction + matching_result.interaction)) and (str(ScanType.local) in str(result_2.no_interaction + result_2.interaction) or str(ScanType.arp) in str(result_2.no_interaction + result_2.interaction) ):
                    if str(ScanType.local) in str(result_2.no_interaction):
                        remove_scan_type(result_2.no_interaction, ScanType.local)
                    if str(ScanType.arp) in str(result_2.no_interaction):
                        remove_scan_type(result_2.no_interaction, ScanType.arp)
                    if str(ScanType.local) in str(result_2.interaction):
                        remove_scan_type(result_2.interaction, ScanType.local)
                    if str(ScanType.arp) in str(result_2.interaction):
                        remove_scan_type(result_2.interaction, ScanType.arp)


            if str(ScanType.airplay) in str(result_2.no_interaction + result_2.interaction):
                    if str(ScanType.airplay) in str(matching_result.no_interaction + matching_result.interaction) and str(ScanType.airplay) in str(result_2.no_interaction + result_2.interaction) :
                        if str(ScanType.airplay) in str(result_2.no_interaction):
                            remove_scan_type(result_2.no_interaction, ScanType.airplay)
                        if str(ScanType.airplay) in str(result_2.interaction):
                            remove_scan_type(result_2.interaction, ScanType.airplay)


            if is_app_scanning(result_2):
                all_scanning.append(result_2)
                    
    return all_scanning



def remove_background_queries(queries: Set[str]) -> Set[str]:
    result = set()
    for query in queries:
        if (
            query != "_companion-link._tcp.local."
            and query != "_companion-link._tcp.local"
            and not query.endswith("_rdlink._tcp.local.")
            and query != "_sleep-proxy._udp.local."
            and query != "lb._dns-sd._udp.local"
            and query != "lb._dns-sd._udp.local."
            and not query.endswith("_rdlink._tcp.local")
            and query != "_sleep-proxy._udp.local"
            and query != "_meshcop._udp.local."
            and not query.endswith("_gamecenter._tcp.local.")
            and query != "_homekit._tcp.local."
            and query != "_homekit._tcp.local"
            and "_apple-midi._udp.local" not in query
            and  not query.endswith("._http._tcp.local.")
            and not query.endswith("._http._tcp.local")
            and not query.endswith("_http._tcp.local")
            and not query.endswith("_http._tcp.local.")
            and  "Android" not in query
            and "homekit." not in query



        ):
            result.add(query)
    return result


def add_results_from_first_run(run_v1: List[Result], run_v2: List[Result]) -> List[Result]:
    all_ids = set()
    result = []
    for r in run_v2:
        all_ids.add(r.app_id)
        result.append(r)
    for r in run_v1:
        if r.app_id not in all_ids:
            result.append(r)
            all_ids.add(r.app_id)

    return result





# Manual  categorization of apps
categories = {
    "IoT": ["com.libratone", "com.epson.epsonsmart", "com.anio.watch","com.xforce.v5.zxaction","com.imactivate.bins", "de.obdapp.android.release", "com.crrepa.band.hero", "com.parrot.freeflight6", "com.philips.ph.homecare", "com.skyjos.apps.fileexplorerfree", "com.airbeamtv.samsung", "com.philips.lighting.hue2", "com.kraftwerk9.sonyfy", "com.amazon.storm.lightning.client.aosp", "com.sonos.acr", "com.eco.global.app", "com.tinac.ssremotec", "de.rademacher", "de.avm.android.smarthome", "com.mcu.reolink", "com.tuya.smart", "ucm.mobile", "com.belkin.wemoandroid", "com.tao.wiz", "com.sandisk.connect", "com.bose.soundtouch", "jp.co.canon.bsd.ad.pixmaprint", "com.nanjoran.ilightshow", "com.bosch.sh.ui.android", "de.avm.android.fritzapp", "com.kairos.duet", "com.sonos.acr2", "com.osram.lightify", "de.twokit.video.tv.cast.browser.samsung", "com.google.android.apps.chromecast.app", "de.telekom.smarthomeb2c", "com.e2esoft.ivcam", "com.anydesk.anydeskandroid", "com.cisco.connect.cloud", "de.twokit.screen.mirroring.app", "com.panasonic.avc.cng.imageapp", "com.brother.mfc.mobileconnect", "com.yamaha.av.musiccastcontroller", "com.raumfeld.android.controller", "com.tuya.smartlife", "com.tpvision.philipstvapp2", "com.microsoft.rdc.android", "com.frontier_silicon.fsirc.dok2", "de.twokit.screen.mirroring.app.firetv", "tv.remote.universal.control", "com.teufel.SmartAudio", "com.dnm.heos.phone", "com.samsung.roomspeaker3", "co.abetterhome.lighter", "com.dmholdings.DenonAVRRemote", "com.instantbits.cast.webvideo", "com.wdc.wd2go", "com.ubnt.unifi.protect", "jp.co.canon.ic.cameraconnect", "com.doorbird.doorbird", "com.airbeamtv.lg", "com.abus.app2camplus.gcm", "com.getonswitch.onswitch", "com.meross.meross", "de.twokit.screen.mirroring.app.chromecast", "com.universal.remote.multi", "com.logitech.harmonyhub", "com.tplink.skylight", "com.aesoftware.tubio", "air.net.mediayou.AirMusicControlApp", "smartvest.abus.com.smartvest", "com.playstation.mobile2ndscreen", "com.iona_energy.android", "de.avm.android.fritzapptv", "com.legrandgroup.c300x", "com.wolow", "de.buschjaeger.welcome_ispf", "com.nedis.smartlife", "ca.bejbej.voicerecordpro", "filmapp.apps.videobuster.de", "pl.extollite.bedrocktogetherapp", "com.theta360", "com.dmholdings.denonremoteapp", "de.twokit.video.tv.cast.browser.firetv", "com.asus.aihome", "com.vocolinc.linkwise", "com.kraftwerk9.remotie", "com.kraftwerk9.smartify", "com.kraftwerk9.firetv", "com.loxone.kerberos", "de.avm.android.myfritz2", "com.senecaflyer.xpremotepanel", "com.promeddevs.wifipro", "com.floramobileapps.RokuTVFree", "com.generalcomp.revo", "com.wifiaudio.Soundavo", "push.lite.avtech.com", "com.szneo.OLYMPIA", "com.aeg.myaeg", "com.ligo.apingdriver", "ru.mysmartflat.sapfir", "com.fujitsu.pfu.ScanSnapConnectApplication", "com.evracing.IoTmEtter", "com.REscan360.REscanViewer", "com.mm.android.direct.AmcrestViewPro", "com.mediola.smartwindow", "com.near.aec", "com.ThermoFloor.Heatit", "com.jcast.client", "com.kyocera.externalpanel", "com.u.guardianfullhd", "com.entrya.facilanext", "com.zebra.printersetup", "com.radioenge.radioengeconfig", "com.edimax.eirbox", "com.METechs.SWCtrl", "nl.wienelware.huemusicsyncdiscoparty", "com.wifiaudio.Elipson", "com.globalpro.mobile.phone", "com.phorus.headfi", "com.hdfury.Diva", "mymcl1.p2pwificam.client", "com.cei.basetech.homecontrol"],
    "Videos": ["com.iqiyi.i18n", "com.eurosport", "com.pl.cwc_2015", "wakanimapp.wakanimapp", "pl.cyfrowypolsat.cpgo", "com.rituals.app.prod", "com.vimeo.android.videoapp", "com.disney.disneyplus", "com.justwatch.justwatch","de.ard.audiothek", "tv.pluto.android", "com.espn.score_center", "com.airbeamtv.panasonic", "com.gotv.nflgamecenter.us.lite", "de.wdr.einslive", "com.neulion.smartphone.ufc.android", "com.nfl.fantasy.core.android", "com.nhl.gc1112.free", "com.formulaone.production", "com.aljazeera.mobile", "tv.chaupal.android", "com.zinio.zinio", "be.vootvplus.app", "tv.uscreen.qplay"],
    "Events": ["io.pushpay.scottdawson", "io.pushpay.nvkgmfredericksburg", "com.subsplashconsulting.s_43B6QJ", "io.pushpay.destinycommunitychurch", "io.echurch.victoryfamily", "com.quanticapps.athan", "io.pushpay.bjcopp", "com.echurchapps.churchotlg", "io.pushpay.chesterchristianchurch", "io.pushpay.ccea", "com.echurchapps.refugestevenswi", "com.echurchapps.outreachamerica", "com.subsplash.thechurchapp.summitcrossing", "io.pushpay.thecompasschurchindiana", "io.pushpay.firstbaptistbartlesville", "com.subsplashconsulting.s_VFTSKK", "net.sermon.sn222429"],
    "Audios": ["com.bbc.sounds", "com.subsplashconsulting.s_FPFNPV","com.mobily.rananapp", "com.streema.simpleradio", "com.idagio.app", "com.mixvibes.remixlive", "de.deutschlandfunk.dlfaudiothek", "com.qobuz.music", "com.amp.android", "com.aspiro.tidal", "com.anghami", "com.yle.webtv", "com.appmind.radios.es", "com.radioparadiso.android", "com.rhapsody.alditalk", "com.zumba.zinplay", "com.bowerswilkins.splice", "com.subsplash.thechurchapp.horizontequeretaro","com.subsplashconsulting.s_S5T3NF"],
    "Games": ["com.netease.eve.en", "com.panteon.slingplane", "com.computerlunch.evolution","com.netease.g78na.gb", "com.alpha.mpsen.android", "com.gtarcade.ioe.global","com.nagastudio.giant.monster.run","com.dopuz.klotski.riddle","com.playstation.kipdecades", "com.geargames.pfp", "com.innersloth.spacemafia", "com.optimesoftware.tictactoe.free", "com.ubisoft.dance.justdance2015companion", "com.sandboxol.blockymods", "com.westbund.heros.en", "air.com.moviestarplanet.roboblastplanet", "com.ubisoft.dance.JustDance", "com.high5.davinci.GoldenGoddessCasino"],
    "Network-related": ["com.overlook.android.fing", "com.ubnt.easyunifi", "uk.co.broadbandspeedchecker", "com.ubnt.usurvey"],
    "Fitness": ["com.independence284.pvb88cwnuapp", "com.trainerroad.android.production", "com.veryfit2hr.second"],
    "Shopping": ["com.boozt", "com.lazada.android", "com.alibaba.aliexpresshd", "de.zalando.mobile", "com.lightinthebox.android", "com.houzz.app"],
    "Car": ["net.easyconn.motofun.wws", "de.mwwebwork.benzinpreisblitz", "com.mapfactor.navigator"],
    "Art": ["com.google.android.apps.cultural", "com.cateater.stopmotionstudio"],
    "Call": ["com.estos.apps.android.procallmobileng", "com.primo.primotalk"],
    "Finance": ["com.izettle.android", "com.erply.pointofsale.pos2020", "com.accessbank.nextgen", "com.seekingalpha.webwrapper"],
    "News/reading": ["nl.nos.app", "eu.belsat", "com.cfc.iv3jv", "at.apa.pdfwlclient.vrm_zentralhessen", "at.apa.pdfwlclient.vrm_darmstaedterecho", "com.tencent.weread"],
    "Betting": ["com.espn.fantasy.lm.football", "com.kamagames.roulettist"],
    "Babyphone_phone2phone": ["cz.masterapp.annie3"],
    "Organization": ["com.evernote", "com.intelligentchange.fiveminutejournal", "com.bpmobile.iscanner.free"],
    "Dating": ["com.p1.mobile.putong"],
    "Plants": [ "com.stromming.planta"],
    "Dictionary": ["com.linguee.linguee"],
    "ID": ["com.governikus.ausweisapp2"],
    "Logistic": ["com.nagelgroup.app"],
    "Medical": ["com.clickmedro"],
    "Photo_stuff": ["com.labs.merlinbirdid.app", "com.ai.face.play", "com.mt.mtxx.mtxx"],
    "Browser": ["com.microsoft.bing"],
    "Weather": ["amuseworks.thermometer"],
    "Informatin": ["de.gelbeseiten.android"],
    "Other": ["com.massager.japan"]
}


def categorice_apps(matching: Dict[Result, Result]):
    ios_apps = {}
    android_apps = {}
    both = {}
    total = 0
    for k,v in matching.items():
        for category, apps in categories.items():
            if v.app_id in apps:
                if is_app_scanning(k) and is_app_scanning(v):
                    both[category] = both.get(category, 0) + 1
                    total = total + 1
                elif is_app_scanning(k):
                    ios_apps[category] = ios_apps.get(category, 0) + 1
                    total = total + 1
                elif is_app_scanning(v):
                    android_apps[category] = android_apps.get(category, 0) + 1
                    total  = total + 1
                
    
    return (ios_apps, android_apps, both, total)


def to_classify(matching: Dict[Result, Result]):
    all_classified = set()
    for category, apps in categories.items():
        all_classified.update(apps)
    
    for k,v in matching.items():
        if (is_app_scanning(k) or is_app_scanning(v)) and v.app_id not in all_classified:
            print(v.app_id)



def get_scapy_protocol(packet):
    protocols = packet.payload.payload_guess
    return protocols[0][1].__name__ if len(protocols) > 0 and len(protocols[0]) > 1  else None
