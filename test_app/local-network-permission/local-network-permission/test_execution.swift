//
//  test_execution.swift
//  local-network-permission
//
//  Created by  on 05.01.24.
//

import Foundation



func run_parallel() {
   // DispatchQueue.global(qos: .default).async {
    print(getAllIPAddresses())
        let _: () = triggerLocalNetworkPrivacyAlert()
    
        sleep(5)
        let _: () =  run_tests()
        print("execute browser")
        let browser = ServiceBrowser()
        startNetServiceBrowser()
        let bonjour2 = BonjourServiceDiscovery()
        print("end browser")

    //}
}


struct TestAddress {
    var address: String
    var name: String
}

func create_test_addresses() -> [TestAddress] {
    var ipv_6 = false
    var test_addresses: [TestAddress] = []
    if !ipv_6 {
        //adapt depending on the network
        test_addresses.append(TestAddress(address: "192.168.2.1", name: "local_ipv4_valid_address"))
        test_addresses.append(TestAddress(address: "192.168.2.123", name: "local_ipv4"))
        test_addresses.append(TestAddress(address: "192.168.0.1", name: "local_ipv4_outside"))
        test_addresses.append(TestAddress(address: "10.1.0.1", name: "local_ipv4_vpn"))
        test_addresses.append(TestAddress(address: "10.20.20.20", name: "local_ipv4_outside_10"))

        test_addresses.append(TestAddress(address: "224.0.0.251", name: "multicast_224"))
        //test_addresses.append(TestAddress(address: "225.0.0.0", name: "multicast_225"))
        //test_addresses.append(TestAddress(address: "226.0.0.0", name: "multicast_226"))
        //test_addresses.append(TestAddress(address: "227.0.0.0", name: "multicast_227"))
        //test_addresses.append(TestAddress(address: "228.0.0.0", name: "multicast_228"))
        test_addresses.append(TestAddress(address: "229.255.255.250", name: "multicast_229"))
        test_addresses.append(TestAddress(address: "224.0.0.69", name: "multicast_unassigned"))
        //test_addresses.append(TestAddress(address: "231.0.0.0", name: "multicast_231"))
        //test_addresses.append(TestAddress(address: "232.0.0.0", name: "multicast_232"))
        //test_addresses.append(TestAddress(address: "233.0.0.0", name: "multicast_233"))
        //test_addresses.append(TestAddress(address: "234.0.0.0", name: "multicast_234"))
        //test_addresses.append(TestAddress(address: "235.0.0.0", name: "multicast_235"))
        //test_addresses.append(TestAddress(address: "236.0.0.0", name: "multicast_236"))
        //test_addresses.append(TestAddress(address: "237.0.0.0", name: "multicast_237"))
        //test_addresses.append(TestAddress(address: "238.0.0.0", name: "multicast_238"))
        test_addresses.append(TestAddress(address: "239.255.255.250", name: "multicast_239"))
        
        test_addresses.append(TestAddress(address: "255.255.255.255", name: "broadcast_255_255_255_255"))
        test_addresses.append(TestAddress(address: "192.168.2.255", name: "broadcast_192-validate"))
    } else {
        test_addresses.append(TestAddress(address: "FD00::1fa2", name: "local_valid"))
        test_addresses.append(TestAddress(address: "FD00::fa", name: "local_invalid"))
        test_addresses.append(TestAddress(address: "FD01::1", name: "local_outside"))

        test_addresses.append(TestAddress(address: "FF02::2", name: "multicast_FF02::1"))
        
        test_addresses.append(TestAddress(address: "FF02::FB", name: "multicast_FF02::FB"))
        test_addresses.append(TestAddress(address: "FF02::2", name: "multicast_FF02::2"))
        //test_addresses.append(TestAddress(address: "FF02::5", name: "multicast_FF02::5"))
        test_addresses.append(TestAddress(address: "FF05::C", name: "multicast_FF05::c"))
        test_addresses.append(TestAddress(address: "FF02::9", name: "multicast_FF02::9"))
        test_addresses.append(TestAddress(address: "FF02::18D", name: "multicast_FF02::18D"))
    }
    
    
    return test_addresses
}

func create_component_list() -> [TestRequest] {
    var test_components: [TestRequest] = []
    test_components.append(SimplePingTest())
    
    test_components.append(NWConnectionQUIC())

    test_components.append(TestURLSession())
    test_components.append(TestNSURLConnection())
    test_components.append(NWConnectionTCP())
    test_components.append(SendToTCP())

    test_components.append(SendToUDP())
    test_components.append(NWConnectionUDP())

    //moved to own test apps
    //test_components.append(webViewObject!) //WKWebViewTest()
    //test_components.append(UIWebViewTest())
    //test_components.append(SFSafariViewControllerTest())
    
    
    return test_components
}


func run_tests() {
    let test_components: [TestRequest] = create_component_list()
    let test_addresses: [TestAddress] = create_test_addresses()
    let url_request: TestURLSession = TestURLSession()
    
    // List of components -> Method to execute and description + protocol
    for component in test_components {
        for address in test_addresses {
            if (( address.name.contains("multicast") || address.name.contains("broadcast") )  && (component.get_type() != "udp" && component.get_type() != "quic" )) {
                continue
            }
            //Request - to find test case
            let base_path = component.get_name() + "/" + component.get_type()  + "/" + address.name
            print(base_path)

            let begin: String = remote_endpoint + "/begin/" + base_path
            let end: String = remote_endpoint + "/end/" + base_path
            print(begin)
            url_request.make_request(url_string: begin)
            _ =  sleep(3)
            component.make_request(url_string: address.address)
            _ =  sleep(5)

            url_request.make_request(url_string: end)
            print(end)
            _ =  sleep(3)

            //Request - to end test case
        }
    }
}



import Network

func getAllIPAddresses() -> [(interfaceName: String, ipAddress: String)] {
    var interfaceIPPairs = [(interfaceName: String, ipAddress: String)]()
    
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0 else { return interfaceIPPairs }
    defer { freeifaddrs(ifaddr) }
    
    var ptr = ifaddr
    while ptr != nil {
        guard let interface = ptr?.pointee else { break }
        let family = interface.ifa_addr.pointee.sa_family
        if family == UInt8(AF_INET) || family == UInt8(AF_INET6) {
            var addr = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if (getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len), &addr, socklen_t(addr.count), nil, 0, NI_NUMERICHOST) == 0) {
                if let address = String(cString: addr) as String?,
                   let interfaceName = String(validatingUTF8: interface.ifa_name) as String? {
                    interfaceIPPairs.append((interfaceName: interfaceName, ipAddress: address))
                }
            }
        }
        ptr = interface.ifa_next
    }
    
    return interfaceIPPairs
}




