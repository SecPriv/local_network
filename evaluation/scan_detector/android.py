import os
import ipaddress
from classes import Analysis, Result, ScanType
from scapy.error import Scapy_Exception
from util import (
    get_source_and_destination,
    get_arp_destination,
    extract_dns_query_domain,
    broadcast_global,
    local_network_ranges,
    extract_mdns_queries,
    remove_background_queries,
    get_all_multicast_addresses,
    apple_ip,
    router_ip,
    get_scapy_protocol
)
from scapy.all import rdpcap, DNS, DNSQR, DHCP, ICMP
from typing import List, Set, Tuple


# Android helper functions - extract traffic dumps and analyze them

def get_android_dataset(path: str) -> Tuple[List[Analysis], List[str]]:
    """
    Get the Android dataset from the specified path.

    Args:
        path (str): The path to the Android dataset.

    Returns:
        tuple: A tuple containing the list of Analysis objects and the list of failed apps.
    """
    result: List[Analysis] = []
    failed: List[str] = []

    for app in os.listdir(path):
        app_path = os.path.join(path, app)
        if not os.path.isdir(app_path):
            continue
        if "run-0000" in os.listdir(app_path):
            run_path = os.path.join(app_path, "run-0000")
            folder = ""
            for f in os.listdir(run_path):
                dir_path = os.path.join(run_path, f)
                if os.path.isdir(dir_path) and f != "downloads":
                    folder = dir_path

            if folder == "":
                print(f"{app} result folder missing")
                failed.append(app)
                continue
            
            pcap_1 = os.path.join(folder, f"tcpdump_{app}_1.pcap")
            pcap_2 = os.path.join(folder, f"tcpdump_{app}_2.pcap")
            pcap_app_1 = os.path.join(folder, f"{app}_1.pcap")
            pcap_app_2 = os.path.join(folder, f"{app}_2.pcap")

            if not os.path.exists(pcap_1):
                print(f"{pcap_1} does not exist")
                failed.append(app)
                continue
            if not os.path.exists(pcap_2):
                print(f"{pcap_2} does not exist")
                failed.append(app)
                continue
            if not os.path.exists(pcap_app_1):
                print(f"{pcap_app_1} does not exist")
                failed.append(app)
                continue
            if not os.path.exists(pcap_app_2):
                print(f"{pcap_app_2} does not exist")
                failed.append(app)
                continue

            result.append(Analysis(app, pcap_1, pcap_2, pcap_app_1, pcap_app_2))
        else:
            print(f"{app} run folder missing")
            failed.append(app)

    return result, failed


def has_query(query: str, queries: Set[str]) -> bool:
    """
    Check if a query is present in the set of queries.

    Args:
        query (str): The query to check.
        queries (Set[str]): The set of queries.

    Returns:
        bool: True if the query is present in the set of queries, False otherwise.
    """
    for q in queries:
        if query in q:
            return True
    return False

def search_for_scanning(
    pcap: List, my_ip_cidr: str
) -> Tuple[bool, bool, bool, bool, Set[str], Set[str]]:
    """
    Search for scanning activity in the given pcap file.

    Args:
        pcap (List): The list of packets in the pcap file.
        my_ip_cidr (str): The IP address and CIDR notation of the local network.

    Returns:
        tuple: A tuple containing the scan types detected, the addresses involved in the scan, and DNS queries made during the scan.
    """
    arp_store: Set[str] = set()
    multicast_store: Set[str] = set()
    local_net_store: Set[str] = set()
    broadcast = False
    contacted_addresses: Set[str] = set()
    dns_queries: Set[str] = set()
    other_local_addresses: Set[str] = set()
    bonjour_found = set()
    multicast_protocols = set()
    broadcast_protocols = set()

    my_ip, _, network_length = my_ip_cidr.partition("/")
    ip_network = ipaddress.IPv4Network(my_ip_cidr, strict=False)
    broadcast_ip = ip_network.broadcast_address

    icmp_external = False
    icmp_router = False
    other_local = False
    for packet in pcap:
        src, dst = get_source_and_destination(packet)
        if src == my_ip:
            if dst == "224.0.0.251" or dst == "239.255.255.0" or dst == "224.0.0.22":
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
            if dst == "224.0.0.251":  # bonjour
                if DNS in packet and DNSQR in packet:
                    query_names = extract_mdns_queries(packet)
                    #_%9E5E7C8F47989526C9BCD95D24084F6F0B27C5ED._sub -> https://blog.optman.net/annoying-google-cast-mdns-request/
                    if len(remove_background_queries(query_names)) == 0:
                        continue
                    else:
                        multicast_store.add(dst)
                        contacted_addresses.add(dst)
                        for query in remove_background_queries(query_names):
                            bonjour_found.add(query)
                        multicast_protocols.add(get_scapy_protocol(packet))

                    continue
            elif dst == "239.255.255.0" or dst == "224.0.0.22":
                #Bonjour service
                continue           
            else:
                multicast_store.add(dst)
                multicast_protocols.add(get_scapy_protocol(packet))
                continue
        if (src == my_ip and (dst == broadcast_global or dst == str(broadcast_ip))) :
            broadcast = True
            broadcast_protocols.add(get_scapy_protocol(packet))
            continue

        if (
            src == my_ip
            and ipaddress.IPv4Address(dst) in ip_network ):
            if ipaddress.IPv4Address(dst) == apple_ip:
                continue
            elif ipaddress.IPv4Address(dst) == router_ip and DNSQR in packet:
                continue
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
            if arp_packet in ["192.168.2.1", "192.168.2.5", "192.168.2.8", "192.168.2.9", "192.168.2.207", "192.168.2.15", "192.168.2.13", "192.168.2.16", "192.168.2.10", "192.168.2.12", "192.168.2.225", "192.168.2.147", "192.168.2.110", "192.168.2.29", "192.168.2.255", "192.168.2.6"]:
                continue
            arp_store.add(arp_packet)
            continue

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


def compare_dumps(
    app_id: str, tcp_dump: str, app_dump: str, my_ip_cidr: str
) -> Tuple[List[ScanType], Set[str], Set[str]]:
    """
    Compare two network dumps of pcapdroid and tcpdump to detect scanning activity.

    Args:
        app_id (str): The ID of the application.
        tcp_dump (str): Path to the TCP dump file.
        app_dump (str): Path to the application dump file.
        my_ip_cidr (str): The IP address and CIDR notation of the local network.

    Returns:
        tuple: A tuple containing the scan types detected, the addresses involved in the scan, and DNS queries made during the scan.
    """
    result: List[ScanType] = []
    multicast_app = False
    arp_app = False
    local_app = False
    broadcast_app = False
    multicast = False
    broadcast = False
    local = False
    arp = False
    dns_queries_app: Set[str] = set()
    addresses_app: Set[str] = set()
    other_local_addresses_app = False
    other_local_addresses = False
    addresses: Set[str] = set()
    dns_queries: Set[str] = set()
    bonjour_found = set()
    bonjour_found_app = set()
    multicast_protocols_app = set()
    broadcast_protocols = set()

    try:
        (
            multicast_app,
            broadcast_app,
            local_app,
            arp_app,
            addresses_app,
            dns_queries_app,
            other_local_addresses_app,
            bonjour_found_app,
            multicast_protocols_app,
            _
        ) = search_for_scanning(rdpcap(app_dump), my_ip_cidr)
    except Scapy_Exception as e:
        #print(f"Exception triggered for {app_dump}")
        print(e)

    try:
        (
            multicast,
            broadcast,
            local,
            arp,
            addresses,
            dns_queries,
            other_local_addresses,
            bonjour_found,
            _,
            broadcast_protocols
        ) = search_for_scanning(rdpcap(tcp_dump), my_ip_cidr)
    except Scapy_Exception as e:
        #print(f"Exception triggered for {tcp_dump}")
        print(e)

    if multicast_app:
        result.append(ScanType.multicast)
    if len(bonjour_found) > 0 :
        has_cast = False
        has_background_number = False
        for bonjour in bonjour_found:
            if "_googlecast" in bonjour :
                has_cast = True
            if "9E5E7C8F47989526C9BCD95D24084F6F0B27C5ED" in bonjour:
                has_background_number = True
        
        if has_cast and not has_background_number:
            bonjour_found_app.add("google_background")
        
    
    if broadcast:
        result.append(ScanType.broadcast)
    
    if local:
        result.append(ScanType.local)
    

    if arp:
        result.append(ScanType.arp)

    if other_local_addresses: # other_local_addresses_app and
        result.append(ScanType.other_local_address)

    return result, addresses, dns_queries, bonjour_found_app, multicast_protocols_app, broadcast_protocols




        

def analyze_android_app(app: Analysis, my_ip_cidr: str) -> Result:
    """
    Analyze an Android app for scanning activity.

    Args:
        app (Analysis): The Analysis object representing the app.
        my_ip_cidr (str): The IP address and CIDR notation of the local network.

    Returns:
        Result: The result of the analysis.
    """
    no_interaction, addresses, dns_queries, bonjour_found, multicast_1, broadcast_1 = compare_dumps(
        app.app_id, app.pcap_1, app.pcap_app_1, my_ip_cidr
    )
    interaction, addresses2, dns_queries2, bonjour_found2, multicast_2, broadcast_2 = compare_dumps(
        app.app_id, app.pcap_2, app.pcap_app_2, my_ip_cidr
    )
    return Result(
        app.app_id,
        no_interaction,
        interaction,
        resolved_addresses=dns_queries.union(dns_queries2),
        contacted_ip_addresses=addresses.union(addresses2),
        remaining_bonjour=bonjour_found.union(bonjour_found2),
        contacted_addresses_1=addresses,
        contacted_addresses_2=addresses2,
        multicast_protocols = multicast_1.union(multicast_2),
        broadcast_protocols = broadcast_1.union(broadcast_2),
    )


def analyze_android(dataset: List[Analysis], my_ip_cidr: str) -> List[Result]:
    """
    Analyze the Android dataset for scanning activity.

    Args:
        dataset (List[Analysis]): The list of Analysis objects representing the dataset.
        my_ip_cidr (str): The IP address and CIDR notation of the local network.

    Returns:
        List[Result]: The list of results for each app in the dataset.
    """
    result: List[Result] = []
    for app in dataset:
        result.append(analyze_android_app(app, my_ip_cidr))
    return result



# ----------------------------
