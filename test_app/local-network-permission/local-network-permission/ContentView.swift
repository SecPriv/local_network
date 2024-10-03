//
//  ContentView.swift
//  local-network-permission
//
//  Created by  on 13.12.23.
//

import SwiftUI
import Foundation

let remote_endpoint = ":8394"


struct ContentView: View {
    var body: some View {
        VStack {
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundColor(.accentColor)
            Text("Hello, world!")
            
        }
        .padding()
        
        let _: () = run_parallel()
    }
    
}

