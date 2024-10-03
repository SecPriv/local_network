//
//  tcp_requests.swift
//  local-network-permission
//
//  Created by  on 15.12.23.
//
import Foundation
import UIKit
import WebKit
import SafariServices
import Network
import SwiftUI

protocol TestRequest {
    func make_request(url_string: String);
    
    func get_name() -> String ;
    
    func get_type() -> String;
}

protocol TestViewController: TestRequest, UIViewController  {
    
}

class TestURLSession: TestRequest {
    func make_request(url_string: String) {
        var url_string_var = url_string
        if url_string.hasPrefix("F") {
            url_string_var = "[" + url_string + "]"
        }
        let url = URL(string: "http://" + url_string_var)!
        print(get_name())
        print(url_string)
        let task = URLSession.shared.dataTask(with: url) {(data, response, error) in
            guard let data = data else { return }
            print(String(data: data, encoding: .utf8)!)
        }
        
        task.resume()
        
    }
    
    func get_name() -> String {
        return "URLSession"
    }
    
    func get_type() -> String {
        return "tcp";

    }
    
}





class TestNSURLConnection: TestRequest {
    func make_request(url_string: String) {
        print(get_name())
        print(url_string)
        var url_string_var = url_string
        if url_string.hasPrefix("F") {
            url_string_var = "[" + url_string + "]"
        }
        let url = URL(string: "http://" + url_string_var)!
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        NSURLConnection.sendAsynchronousRequest(request, queue: OperationQueue.main) {(response, data, error) in
            guard let data = data else { return }
            print(String(data: data, encoding: .utf8)!)
        }
        
    }
    
    func get_name() -> String {
        return "NSURLConnection"
    }
    
    func get_type() -> String {
        return "tcp";

    }
    
}



class SendToUDP: TestRequest {
    func make_request(url_string: String) {
        var serverAddr = sockaddr_storage()
        var socketFileDescriptor: Int32
        
        if url_string.contains("F") { // Check if it's an IPv6 address
            var addr6 = sockaddr_in6()
            addr6.sin6_len = __uint8_t(MemoryLayout<sockaddr_in6>.size)
            addr6.sin6_family = sa_family_t(AF_INET6)
            addr6.sin6_port = 1900 // Replace with your port
            
            // Convert the IPv6 address from string to network format
            inet_pton(AF_INET6, url_string, &addr6.sin6_addr)
            
            // Copy sockaddr_in6 to sockaddr_storage
            memcpy(&serverAddr, &addr6, MemoryLayout<sockaddr_in6>.size)
            
            socketFileDescriptor = socket(AF_INET6, SOCK_DGRAM, 0)
        } else {
            var addr4 = sockaddr_in()
            addr4.sin_len = __uint8_t(MemoryLayout<sockaddr_in>.size)
            addr4.sin_family = sa_family_t(AF_INET)
            addr4.sin_port = 1900 // Replace with your port
            
            // Convert the IPv4 address from string to network format
            inet_pton(AF_INET, url_string, &addr4.sin_addr)
            
            // Copy sockaddr_in to sockaddr_storage
            memcpy(&serverAddr, &addr4, MemoryLayout<sockaddr_in>.size)
            
            socketFileDescriptor = socket(AF_INET, SOCK_DGRAM, 0)
        }
        
        guard socketFileDescriptor != -1 else {
            print("Error creating socket")
            return
        }
        
        let message = "test"
        var serverAddrCopy = serverAddr
        // Send the UDP packet
        let sent = withUnsafeBytes(of: &serverAddrCopy) { address in
            sendto(socketFileDescriptor, message, message.utf8.count, 0, address.bindMemory(to: sockaddr.self).baseAddress, socklen_t(serverAddr.ss_len))
        }
        
        if sent == -1 {
            print("Error sending UDP packet")
        }
        
        close(socketFileDescriptor)
    }


    func get_name() -> String {
        return "sendToUdp"
    }

    func get_type() -> String {
        return "udp";

    }
    
}


class NWConnectionUDP: TestRequest {
    func make_request(url_string: String) {
        let myHost: NWEndpoint.Host = NWEndpoint.Host(url_string)
        let connection = NWConnection(host: myHost, port: 9093, using: .udp)
        connection.start(queue: .global())
        connection.send(content: "Test message".data(using: String.Encoding.utf8), completion: NWConnection.SendCompletion.contentProcessed(({ (NWError) in
            print(NWError ?? "Error")
            })))

    }

    func get_name() -> String {
        return "NWConnectionUdp"
    }

    func get_type() -> String {
        return "udp";

    }
    
}


class NWConnectionQUIC: TestRequest {
    func make_request(url_string: String) {
        let myHost: NWEndpoint.Host = NWEndpoint.Host(url_string)
        let connection = NWConnection(host: myHost, port: 9093, using: .quic(alpn: ["h3", "h2", "h1", "h3-29"]))
        connection.start(queue: .global())
        connection.send(content: "Test message".data(using: String.Encoding.utf8), completion: NWConnection.SendCompletion.contentProcessed(({ (NWError) in
            print(NWError ?? "Error")
            })))

    }

    func get_name() -> String {
        return "NWConnectionQuic"
    }

    func get_type() -> String {
        return "quic";

    }
    
}




class NWConnectionTCP: TestRequest {
    func make_request(url_string: String) {
        let myHost: NWEndpoint.Host = NWEndpoint.Host(url_string)
        let myPort: NWEndpoint.Port = NWEndpoint.Port(integerLiteral: 9093)

        let connection = NWConnection(host: myHost, port: myPort, using: .tcp)
        
        connection.stateUpdateHandler = { newState in
            switch newState {
            case .ready:
                print("Connection ready")
                // Start sending data after the connection is ready
                self.sendData(using: connection)
                
            case .failed(let error):
                print("Connection failed: \(error)")
                
            default:
                break
            }
        }
        
        connection.start(queue: .global())
    }
    func sendData(using connection: NWConnection) {
        let message = "Test message"
        let data = message.data(using: .utf8)
        
        connection.send(content: data, completion: .contentProcessed({ (error) in
            if let sendError = error {
                print("Send error: \(sendError)")
            } else {
                print("Data sent successfully")
            }
            
            // Close the connection after sending data
            connection.cancel()
        }))
    }

    func get_name() -> String {
        return "NWConnectionTCP"
    }

    func get_type() -> String {
        return "tcp";

    }
    
}




class SendToTCP: TestRequest {
    
    func sockaddr_cast(_ ptr: UnsafePointer<sockaddr_in>) -> UnsafePointer<sockaddr> {
        return UnsafeRawPointer(ptr).assumingMemoryBound(to: sockaddr.self)
    }
    func sockaddr_cast(_ ptr: UnsafePointer<sockaddr_in6>) -> UnsafePointer<sockaddr> {
        return UnsafeRawPointer(ptr).assumingMemoryBound(to: sockaddr.self)
    }

    // Helper function to convert UInt16 to network byte order
    func htons(_ value: UInt16) -> UInt16 {
        return (value << 8) + (value >> 8)
    }
    
    func make_request(url_string: String) {
        var socketFileDescriptor = Int32(AF_INET) // Default to AF_INET (IPv4)
        var connectResult: Int32
        
        if url_string.contains("F") { // Check if it's an IPv6 address
            socketFileDescriptor = socket(AF_INET6, SOCK_STREAM, 0)
            var serverAddress_in6 = sockaddr_in6()
            serverAddress_in6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            serverAddress_in6.sin6_family = sa_family_t(AF_INET6)
            serverAddress_in6.sin6_port = htons(80)
            let url_str = "[" + url_string + "]"
            inet_pton(AF_INET6, url_str, &serverAddress_in6.sin6_addr)

            connectResult = connect(socketFileDescriptor, sockaddr_cast(&serverAddress_in6), socklen_t(MemoryLayout<sockaddr_in6>.size))
        } else { // IPv4 address
            socketFileDescriptor = socket(AF_INET, SOCK_STREAM, 0)
            var addr = in_addr()
            var serverAddress_in = sockaddr_in(sin_len: __uint8_t(MemoryLayout<sockaddr_in>.stride), sin_family: sa_family_t(AF_INET), sin_port: 80, sin_addr: addr, sin_zero: (0, 0, 0, 0, 0, 0, 0, 0))
            inet_pton(AF_INET, url_string, &serverAddress_in.sin_addr)
            connectResult = connect(socketFileDescriptor, sockaddr_cast(&serverAddress_in), socklen_t(MemoryLayout<sockaddr_in>.size))
        }
        
        guard connectResult != -1 else {
            perror("Error connecting to the server")
            close(socketFileDescriptor)
            return
        }
        
        // Send data
        let dataToSend = "Hello, Server!".data(using: .utf8)!
        let sentBytes = send(socketFileDescriptor, (dataToSend as NSData).bytes, dataToSend.count, 0)
        
        guard sentBytes != -1 else {
            perror("Error sending data")
            close(socketFileDescriptor)
            return
        }
        
        print("Data sent successfully")
        
        // Close the socket when done
        close(socketFileDescriptor)
    }

    func get_name() -> String {
        return "sendToTcp"
    }

    func get_type() -> String {
        return "tcp"
    }
}




class SimplePingTest: NSObject, TestRequest, SimplePingDelegate {
    
    func make_request(url_string: String) {
        if url_string.hasPrefix("F") {
            start(url_string: url_string, forceIPv4: false, forceIPv6: true)
        } else {
            start(url_string: url_string, forceIPv4: true, forceIPv6: false)
        }
    }
    
    func get_name() -> String {
        return "SimpleICMPPing"
    }
    
    func get_type() -> String {
        return "icmp";
    }
    
    var pinger: SimplePing?
    var sendTimer: Timer?

    /// Called by the table view selection delegate callback to start the ping.
    
    func start(url_string: String, forceIPv4: Bool, forceIPv6: Bool) {
        print(url_string)
        let pinger = SimplePing(hostName: url_string)
        self.pinger = pinger

        // By default we use the first IP address we get back from host resolution (.Any)
        // but these flags let the user override that.
            
        if (forceIPv4 && !forceIPv6) {
            pinger.addressStyle = .icmPv4
        } else if (forceIPv6 && !forceIPv4) {
            pinger.addressStyle = .icmPv6
        }

        pinger.delegate = self
        pinger.start()
	    }

    /// Called by the table view selection delegate callback to stop the ping.
    
    func stop() {
        pinger?.stop()
        pinger = nil
        
        sendTimer?.invalidate()
        sendTimer = nil
    }

    /// Sends a ping.
    ///
    /// Called to send a ping, both directly (as soon as the SimplePing object starts up) and
    /// via a timer (to continue sending pings periodically).
    
    @objc func sendPing() {
        pinger!.send(with: nil)
    }

    // MARK: pinger delegate callback
    
    func simplePing(_ pinger: SimplePing, didStartWithAddress address: Data) {
       print("send ping")
        // Send the first ping straight away.
        sendPing()
        sendTimer = Timer.scheduledTimer(timeInterval: 0.1, target: self, selector: #selector(SimplePingTest.sendPing), userInfo: nil, repeats: true)
        //stop()
    }
    
    func simplePing(_ pinger: SimplePing, didFailWithError error: Error) {
        stop()
    }
    
    func simplePing(_ pinger: SimplePing, didSendPacket packet: Data, sequenceNumber: UInt16) {
    }
    
    func simplePing(_ pinger: SimplePing, didFailToSendPacket packet: Data, sequenceNumber: UInt16, error: Error) {
    }
    
    func simplePing(_ pinger: SimplePing, didReceivePingResponsePacket packet: Data, sequenceNumber: UInt16) {
    }
    
    func simplePing(_ pinger: SimplePing, didReceiveUnexpectedPacket packet: Data) {
    }
    
    // MARK: utilities
    
    /// Returns the string representation of the supplied address.
    ///
    /// - parameter address: Contains a `(struct sockaddr)` with the address to render.
    ///
    /// - returns: A string representation of that address.

    static func displayAddressForAddress(_ address: Data) -> String {
        var hostStr = [Int8](repeating: 0, count: Int(NI_MAXHOST));
        
        let success = getnameinfo(
            address.withUnsafeBytes { (ptr) -> UnsafePointer<sockaddr> in
                ptr.baseAddress!.assumingMemoryBound(to: sockaddr.self)
            },
            socklen_t(address.count),
            &hostStr,
            socklen_t(hostStr.count),
            nil,
            0,
            NI_NUMERICHOST
        ) == 0
        let result: String
        if success {
            result = String(cString: hostStr)
        } else {
            result = "?"
        }
        return result
    }

    /// Returns a short error string for the supplied error.
    ///
    /// - parameter error: The error to render.
    ///
    /// - returns: A short string representing that error.

    static func shortErrorFromError(_ error: Error) -> String {
        let error = error as NSError

        if error.domain == kCFErrorDomainCFNetwork as String, error.code == Int(CFNetworkErrors.cfHostErrorUnknown.rawValue) {
            if let failureObj = error.userInfo[kCFGetAddrInfoFailureKey as String] {
                if let failureNum = failureObj as? NSNumber {
                    if failureNum.intValue != 0 {
                        let f = gai_strerror(failureNum.int32Value)
                        if f != nil {
                            return String(cString: f!, encoding: .utf8)!
                        }
                    }
                }
            }
        }
        if let result = error.localizedFailureReason {
            return result
        }
        return error.localizedDescription
    }
    
}

var webViewObject: WKWebViewTest?
struct WebViewWrapper: UIViewControllerRepresentable {
    var url: String

    class Coordinator: NSObject, WKUIDelegate {
        var parent: WebViewWrapper

        init(parent: WebViewWrapper) {
            self.parent = parent
        }
        
        // Implement WKUIDelegate methods if needed
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    func makeUIViewController(context: Context) -> WKWebViewTest {
        let webViewTest = WKWebViewTest()
        webViewObject = webViewTest
        return webViewTest
    }

    func updateUIViewController(_ uiViewController: WKWebViewTest, context: Context) {
        // Update the view controller if needed
    }
}

class WKWebViewTest: UIViewController, TestViewController, WKUIDelegate {
    
    var webView: WKWebView!
    var url_string: String = ""
    
    override func loadView() {
        //let webConfiguration = WKWebViewConfiguration()
        webView = WKWebView(frame: .zero) //, configuration: webConfiguration
        webView.uiDelegate = self
        view = webView
    }


    override func viewDidLoad() {
        super.viewDidLoad()	
        //print("WKWebView: view did load reach")
        //if let url = URL(string: "http://" + self.url_string) {
        //    let request = URLRequest(url: url)
        //    webView.load(request)
        //}
        //let myURL = URL(string: )
        //let myRequest = URLRequest(url: myURL!)
        //webView.load(myRequest)

    }
    
    func make_request(url_string: String) {
        self.url_string = url_string
        //self.present(self, animated: true, completion: nil)

        if let url = URL(string: url_string) {
            let request = URLRequest(url: url)
            webView.load(request)
        }

    }
    
    func get_name() -> String {
        return "WKWebView"
    }

    func get_type() -> String {
        return "tcp";

    }
    
    func dismissWebView() {
        webView.removeFromSuperview()
    }
    
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Web page has finished loading
        print("Page loaded successfully!")
        dismissWebView()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        // Handle page load failure
        print("Page failed to load with error: \(error.localizedDescription)")
        dismissWebView()
    }
    
}



class UIWebViewTest: UIViewController, TestViewController , UIWebViewDelegate {
    
    var uiView: UIWebView!

    override func loadView() {
        super.loadView()
        uiView = UIWebView()
    }


    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    func make_request(url_string: String) {
        loadView()
        let webUrl : URL = URL(string: "http://" + url_string)!
        let requestObj = URLRequest(url: webUrl)
        uiView.loadRequest(requestObj)
        sleep(10)
    }
    
    func get_name() -> String {
        return "UIWebView"
    }

    func get_type() -> String {
        return "tcp";

    }
    
    func dismissWebView() {
        uiView.removeFromSuperview()
    }
    
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        // Web page has finished loading
        print("Page loaded successfully!")
        dismissWebView()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        // Handle page load failure
        print("Page failed to load with error: \(error.localizedDescription)")
        dismissWebView()
    }
    
}


class SFSafariViewControllerTest: UIViewController, TestViewController, SFSafariViewControllerDelegate {

    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    func make_request(url_string: String) {
        if let url = URL(string: "http://" + url_string) {
            let safariViewController = SFSafariViewController(url: url)
            safariViewController.delegate = self
            present(safariViewController, animated: true, completion: nil)
        }
        sleep(10)

    }



    func safariViewController(_ controller: SFSafariViewController, didCompleteInitialLoad didLoadSuccessfully: Bool) {
        print("Safari VC loaded")
        // This method is called when the initial load is completed (whether successful or not)
        // Dismiss the SFSafariViewController based on the result
        controller.dismiss(animated: true, completion: nil)
    }
    
    
    
    func get_name() -> String {
        return "SFSafariTab"
    }

    func get_type() -> String {
        return "tcp";

    }
    
}








