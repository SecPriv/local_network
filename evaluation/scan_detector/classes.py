from enum import Enum
from typing import List, Set


# Classes for better organization of data

class iOSPermission:
    """
    Represents iOS app permissions.
    """

    app_id: str
    bonjour_services: Set[str]
    description: Set[str]

    def __str__(self):
        return f"iOSPermission(app_id={self.app_id}, bonjour_services={self.bonjour_services}, description={self.description})"

    def __init__(self, app_id: str = "", bonjour_services: Set[str] = set(), description: Set[str] = set()) -> None:
        self.app_id = app_id
        self.bonjour_services = bonjour_services
        self.description = description



class Analysis:
    """
    Represents an analysis of network scans.
    """

    def __init__(
        self,
        app_id: str,
        pcap_1: str,
        pcap_2: str,
        pcap_app_1: str,
        pcap_app_2: str,
        iOS_information: iOSPermission = None,
        log_path: str = None,
    ):
        """
        Initializes an Analysis object.

        Args:
            app_id (str): The ID of the app being analyzed.
            pcap_1 (str): Path to the first pcap file.
            pcap_2 (str): Path to the second pcap file.
            pcap_app_1 (str): Path to the first app pcap file.
            pcap_app_2 (str): Path to the second app pcap file.
            iOS_information (iOSPermission, optional): iOS app permissions. Defaults to None.
            log_path (str, optional): Path to the log file. Defaults to None.
        """
        self.app_id = app_id
        self.pcap_1 = pcap_1
        self.pcap_2 = pcap_2
        self.pcap_app_1 = pcap_app_1
        self.pcap_app_2 = pcap_app_2
        self.iOS_information = iOS_information
        self.log_path = log_path

    def __str__(self):
        return f"Analysis(app_id={self.app_id}, pcap_1={self.pcap_1}, pcap_2={self.pcap_2}, pcap_app_1={self.pcap_app_1}, pcap_app_2={self.pcap_app_2}, iOS_information={self.iOS_information}, log_path={self.log_path})"


class AlertInLog(Enum):
    """
    Represents different types of alerts in log.
    """

    interaction = 1
    no_interaction = 2
    error = 3

    def __str__(self):
        return self.name


class ScanType(Enum):
    """
    Represents different types of network scans.
    """

    multicast = 1
    broadcast = 2
    local = 3
    arp = 4
    other_local_address = 5
    local_or_arp = 6
    airplay = 7
    multicast_or_airplay = 8
    own_wifi_ip = 9
    def __str__(self):
        return f"{self.name}-{str(self.value)}"
    
    
    def __repr__(self):
        return f"{self.name}-{str(self.value)}"



class Result:
    """
    Represents the result of a network scan.
    """

    def __init__(
        self,
        app_id: str,
        no_interaction: List[ScanType],
        interaction: List[ScanType],
        permission_data: iOSPermission = None,
        log_result: AlertInLog = None,
        resolved_addresses: Set[str] = set(),
        contacted_ip_addresses: Set[str] = set(),
        remaining_bonjour =set(),
        contacted_addresses_1 = set(),
        contacted_addresses_2 = set(),
        multicast_protocols = set(),
        broadcast_protocols = set()
    ):
        """
        Initializes a Result object.

        Args:
            app_id (str): The ID of the app.
            no_interaction (List[ScanType]): List of scan types with no interaction.
            interaction (List[ScanType]): List of scan types with interaction.
            permission_data (iOSPermission, optional): iOS app permissions. Defaults to None.
            log_result (AlertInLog, optional): Alert in log. Defaults to None.
            resolved_addresses (Set[str], optional): Set of resolved IP addresses. Defaults to set().
            contacted_ip_addresses (Set[str], optional): Set of contacted IP addresses. Defaults to set().
        """
        self.app_id = app_id
        self.no_interaction = no_interaction
        self.interaction = interaction
        self.permission_data = permission_data
        self.log_result = log_result
        self.resolved_addresses = resolved_addresses
        self.contacted_ip_addresses = contacted_ip_addresses
        self.remaining_bonjour = remaining_bonjour
        self.contacted_addresses_1 = contacted_addresses_1
        self.contacted_addresses_2 = contacted_addresses_2
        self.multicast_protocols = multicast_protocols
        self.broadcast_protocols = broadcast_protocols

    def __str__(self):
        return f"Result(app_id={self.app_id}, no_interaction={self.no_interaction}, interaction={self.interaction}, permission_data={self.permission_data}, log_result={self.log_result}, resolved_addresses={self.resolved_addresses}, contacted_ip_addresses={self.contacted_ip_addresses})"


class MitmResult:
    def __init__(self, appid, run1, run2) -> None:
        self.appid = appid
        self.run1 = run1
        self.run2 = run2

# ----------------------------




