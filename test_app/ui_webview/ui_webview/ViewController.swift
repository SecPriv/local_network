//
//  ViewController.swift
//  wkwebview
//
//

import UIKit
import WebKit

class ViewController: UIViewController, WKUIDelegate {
    var webView: UIWebView!

    override func loadView() {
        //let webConfiguration = UIWebView()
        //webConfiguration.preferences.javaScriptEnabled = true
        webView = UIWebView()
        //webView.uiDelegate = self
        view = webView
    }

    override func viewDidLoad() {
        super.viewDidLoad()
    
        let url = URL(string: "http://192.168.2.1:9111")!
        webView.loadRequest(URLRequest(url: url))
    }


}
