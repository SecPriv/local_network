import Foundation
import Network

//        let serviceBrowser = ServiceBrowser()
class ServiceBrowser {
    private var browser: NWBrowser?

    init() {
        print("Service Browser init")
        let url_request: TestURLSession = TestURLSession()
        var begin: String = remote_endpoint + "/begin/nwbrowser"
        url_request.make_request(url_string: begin)
        sleep(2)
        print("start browsing")
        startBrowsing(type: "_test._tcp.")
        sleep(5)
        var end: String = remote_endpoint + "/end/nwbrowser"
        url_request.make_request(url_string: end)
        print("Service Browser end")
    }

    private func startBrowsing(type: String) {
        let parameters = NWParameters()
        parameters.includePeerToPeer = true

        browser = NWBrowser(for: .bonjour(type: type, domain: nil), using: parameters)
        
        browser?.stateUpdateHandler = { newState in
            switch newState {
            case .setup:
                print("Browser setup")
            case .ready:
                print("Browser ready")
            case .failed(let error):
                print("Browser failed with error: \(error)")
            case .cancelled:
                print("Browser cancelled")
            default:
                break
            }
        }

        browser?.browseResultsChangedHandler = { results, changes in
            for change in changes {
                switch change {
                case .added(let endpoint):
                    print("Service found: \(endpoint)")
                    // Handle the discovered service
                case .removed(let endpoint):
                    print("Service removed: \(endpoint)")
                    // Handle the removed service
                default:
                    break
                }
            }
        }

        browser?.start(queue: DispatchQueue.global(qos: .default))
    }

    deinit {
        browser?.cancel()
    }
}



class ServiceAgent: NSObject, NetServiceDelegate {
    func netServiceDidResolveAddress(_ sender: NetService) {
        if let data = sender.txtRecordData() {
            let dict = NetService.dictionary(fromTXTRecord: data)
            print("Resolved: \(dict)")
            print(dict.mapValues { String(data: $0, encoding: .utf8) })
        }
    }
}

class BrowserAgent: NSObject, NetServiceBrowserDelegate {
    var currentService: NetService?
    let serviceAgent = ServiceAgent()


    func netServiceBrowser(_ browser: NetServiceBrowser, didFindDomain domainString: String, moreComing: Bool) {
        print("Domain found: \(domainString)")
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        print("Service found: \(service.name)")
        self.currentService = service
        service.delegate = self.serviceAgent
        service.resolve(withTimeout: 5)
    }
}

func startNetServiceBrowser(){
    let url_request: TestURLSession = TestURLSession()
    var begin: String = remote_endpoint + "/begin/NetServiceBrowser"
    url_request.make_request(url_string: begin)
    sleep(2)
    let agent = BrowserAgent()
    let browser = NetServiceBrowser()
    browser.delegate = agent
    browser.searchForServices(ofType: "_test._tcp.", inDomain: "local.")
    //browser.searchForServices(ofType: "_hue._tcp", inDomain: "local")
    browser.schedule(in: RunLoop.main, forMode: .common)
    sleep(5)
    var end: String = remote_endpoint + "/end/NetServiceBrowser"
    url_request.make_request(url_string: end)


}



class BonjourServiceDiscovery: NSObject, NetServiceDelegate, NetServiceBrowserDelegate {
    var serviceBrowser: NetServiceBrowser!
    var discoveredServices: [NetService] = []

    override init() {
        super.init()
        let url_request: TestURLSession = TestURLSession()
        var begin: String = remote_endpoint + "/begin/nwbrowser"
        url_request.make_request(url_string: begin)
        sleep(2)

        // Initialize the service browser
        serviceBrowser = NetServiceBrowser()
        serviceBrowser.delegate = self

        // Start browsing for services
        serviceBrowser.searchForServices(ofType: "_test._tcp.", inDomain: "local.")
        sleep(5)

        var end: String = remote_endpoint + "/end/nwbrowser"
        url_request.make_request(url_string: end)

    }

    // MARK: - NetServiceBrowserDelegate

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        // A service was found
        print("Found service: \(service)")

        // Store the discovered service
        discoveredServices.append(service)

        // If more services are coming, you might want to wait until all services are found before processing them
        if !moreComing {
            // Process the discovered services
            processDiscoveredServices()
        }
    }

    func netServiceBrowserDidStopSearch(_ browser: NetServiceBrowser) {
        print("Service browser stopped searching")
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        print("Failed to search for services with error: \(errorDict)")
    }

    // MARK: - Service Processing

    func processDiscoveredServices() {
        // Implement any logic to handle the discovered services
        for service in discoveredServices {
            // Resolve each service to get more details (e.g., host, port)
            service.delegate = self
            service.resolve(withTimeout: 5.0)
        }
    }

    // MARK: - NetServiceDelegate

    func netServiceDidResolveAddress(_ sender: NetService) {
        print("Resolved service: \(sender)")
        print("Host: \(sender.hostName ?? "Unknown Host")")
        print("Port: \(sender.port)")

        // You can now establish a connection to the service using the resolved information
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
        print("Failed to resolve service with error: \(errorDict)")
    }
}


