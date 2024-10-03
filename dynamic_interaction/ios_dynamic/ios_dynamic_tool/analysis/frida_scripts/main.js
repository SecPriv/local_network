function wait_for_class_loading(className) {
	const startTime = Date.now()
	let clazz = ObjC.classes[className]
	while (!clazz) {
		console.log(`ObjC.classes.${className} not set`)
		// Need to wait a little longer
		if (Date.now() - startTime > 5_000) {
			throw new Error(`ObjC.classes.${className} was not set after 5s, bailing out`)
		}
		clazz = ObjC.classes[className]
	}
	console.log(`ObjC.classes.${className} set`, ObjC.classes[className])
	return clazz
}

function read_info_plist() {
	console.log('reading info.plist')

	
	const NSBundle = wait_for_class_loading('NSBundle');
	// console.log(1)
	let mainBundle = NSBundle.mainBundle()
	// console.log(2)
	let plistUrl = new ObjC.Object(mainBundle.URLForResource_withExtension_("Info", "plist"))
	// console.log(3)
	let plistPath = plistUrl.path().toString()
	// console.log(4)
	console.log(`Path to plist: ${plistPath}`)

	const NSMutableDictionary = wait_for_class_loading('NSMutableDictionary');
	let dict = NSMutableDictionary.alloc().initWithContentsOfFile_(plistPath)//.toString()
	
	// remove UIApplicationShortcutItems, as they contain binary which is incompatible with JSON Object format
	dict.removeObjectForKey_("UIApplicationShortcutItems")

	const NSJSONWritingPrettyPrinted = 1
	const NOOPTIONS = 0

	const validate = wait_for_class_loading('NSJSONSerialization')
	if (validate.isValidJSONObject_(dict)) {

		let data = validate.dataWithJSONObject_options_error_(dict, NOOPTIONS, NULL)

		const NSString = wait_for_class_loading('NSString')
		const NSUTF8StringEncoding = 4
		let str = NSString.alloc().initWithData_encoding_(data, NSUTF8StringEncoding).toString()

		let jsonObj = JSON.parse(str)

		return jsonObj

	} 

	throw(new Error('Could not parse .plist to JSON Object -- Invalid JSON'))

}

/**
 * Hook all methods inside a given class, limited to maxHooks if param is provided
 * @param {string} className The class to be hooked
 * @param {int | undefined} maxHooks If provided, limits the number of hooked methods to maxHooks arbitrary methods
 */
function hook_class_methods(className, maxHooks) {
	let methods = ObjC.classes[className].$ownMethods
	let count = 0
	maxHooks = typeof maxHooks == "number" ? maxHooks : methods.length
	console.log(`Hooking ${className} (limit: ${maxHooks}/${methods.length} methods)`)

	for (const method of methods) {
		hook_class_method_basic(className, method)

		if (++count >= maxHooks)
			break
	}
}

/**
 * For a detailed description for the callback methods check out the firda doc: https://frida.re/docs/javascript-api/#instrumentation
 * @param {string} className the ObjC class name to be hooked, e.g. "NSURLRequest"
 * @param {string} methodName the class method to be hooked (ObjC header file notation, e.g. "- initWithURL:cachePolicy:timeoutInterval:"")
 * @param {(args: any[]) => {}} onEnterCallback callback receives an 'args' parameter, with the indices as follows: 0. 'self', 1. The method selector (object.name:), 2..n The method arguments
			You could print the backtrace inside this method as follows:
				```js
				console.log('called from:\n' +
			 		Thread.backtrace(this.context, Backtracer.ACCURATE)
			 	.map(DebugSymbol.fromAddress).join('\n') + '\n');
				 ```
 * @param {(retval: any) => {}} onLeaveCallback receives the value to be returned
 * @returns void
 */
function hook_class_method(className, methodName, onEnterCallback, onLeaveCallback)
{
	if (methodName.indexOf('copyWithZone') > -1) return

	var hook = ObjC.classes[className]
	if (typeof hook === "undefined") {
		console.error(`> ERROR: failed to hook ObjC.classes[${className}] class!`)
		return
	}

	hook = hook[methodName]
	if (typeof hook === "undefined") {
		console.error(`> ERROR: failed to hook ObjC.classes[${className}][${methodName}] method - invalid combination of class and method name!`)
		return
	}

	Interceptor.attach(hook.implementation, {
		onEnter(args) {
			let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
			// console.log('called from:\n' +
			//  		backtrace.join('\n') + '\n');
			onEnterCallback(args, backtrace)
		},
		onLeave(retval) {
			onLeaveCallback(retval)
		}
	})

	console.log(`done hooking method: ObjC.classes[${className}][${methodName}]`)
}

function hook_class_method_basic(className, methodName) {
	let onEnter = (args, backtrace) => {
		sendInvocationEvent(className, methodName, backtrace)
	}
	let onLeave = (retval) => {}

	hook_class_method(className, methodName, onEnter, onLeave)
}

function hook_url_method(className, methodName) {
	let onEnter = (args, backtrace) => {
		let myNSURL = new ObjC.Object(args[2])

		console.log("TASK WITH URL:")
		console.log(className, methodName, "url:", myNSURL)

		sendNetworkEvent(myNSURL.toString(), 'GET', backtrace)
	}
	let onLeave = (retval) => {}

	hook_class_method(className, methodName, onEnter, onLeave)
}

function hook_url_request_method(className, methodName) {
	let onEnter = (args, backtrace) => {
		let myNSURLRequest = new ObjC.Object(args[2])
		let myNSURL =  myNSURLRequest.URL()
		let method = myNSURLRequest.HTTPMethod().toString()

		// let url = myNSURL.absoluteString().toString();
		// console.log('Type of args[2] -> ' + myNSURL.$className)
		console.log("TASK WITH REQUEST:")
		console.log(className, methodName, "url:", myNSURLRequest)
		console.log('URL:', myNSURL)
		console.log('METHOD:', myNSURLRequest.HTTPMethod())

		sendNetworkEvent(myNSURL.toString(), method, backtrace)
	}
	let onLeave = (retval) => {}

	hook_class_method(className, methodName, onEnter, onLeave)
}

/**
 * Hook method where the first argument is of type AVMediaType. Invokes sendAudioVideoEvent(eventType, mediatype)
 * where eventType is the param provided this method calls and mediatype is 'audio' or 'video', based on the first argument of the hooked method
 */
function hook_audio_video_basic(className, methodName, eventType) {
	let onEnter = (args, backtrace) => {
		let mediaType = new ObjC.Object(args[2])

		let AVMediaTypeAudio = 'soun'
		let AVMediaTypeVideo = 'vide'

		console.log('AVCaptureDevice access status checked for type:', mediaType)

		if (mediaType == AVMediaTypeAudio) {
			console.log('audio access checked')
			sendAudioVideoEvent(className, methodName, eventType, 'audio')
		} else if (mediaType == AVMediaTypeVideo) {
			console.log('video access checked')
			sendAudioVideoEvent(className, methodName, eventType,'video')
		} else {
			console.warn(`WARNING: received AVCaptureDevice ${methodName} call for unknown type '${mediaType}'`)
		}
	}
	let onLeave = (retval) => {}

	hook_class_method(className, methodName, onEnter, onLeave)
}

var audio_video_hooked = false

rpc.exports = {
	hookClass(className, hookLimit) {
		hook_class_methods(className, hookLimit)
	},
	hookClassMethod(className, methodName) {
		hook_class_method_basic(className, methodName)
	},
	hookUrlDirect() {
		console.log('hooking url methods...')

		const methodsWithURLParam = ['- aggregateAssetDownloadTaskWithURLAsset:mediaSelections:assetTitle:assetArtworkData:options:',
			'- assetDownloadTaskWithURLAsset:assetTitle:assetArtworkData:options:',
			'- assetDownloadTaskWithURLAsset:destinationURL:options:',
			'- _AVAssetDownloadTaskWithURL:destinationURL:options:',
			'- dataTaskWithURL:completionHandler:',
			'- downloadTaskWithURL:completionHandler:',
			'- webSocketTaskWithURL:protocols:',
			'- webSocketTaskWithURL:',
			'- downloadTaskWithURL:',
			'- dataTaskWithURL:']
		for (const method of methodsWithURLParam) {
			hook_url_method("NSURLSession", method)
		}

		const methodsWithRequestParam = ['- uploadTaskWithRequest:fromFile:completionHandler:',
			'- uploadTaskWithRequest:fromData:completionHandler:',
			'- _downloadTaskWithRequest:downloadFilePath:',
			'- downloadTaskWithRequest:completionHandler:',
			'- dataTaskWithRequest:uniqueIdentifier:',
			'- webSocketTaskWithRequest:',
			'- uploadTaskWithRequest:fromFile:',
			'- uploadTaskWithRequest:fromData:',
			'- downloadTaskWithRequest:',
			'- dataTaskWithRequest:',
			'- dataTaskWithRequest:completionHandler:']

		for (const method of methodsWithRequestParam) {
			hook_url_request_method('NSURLSession', method)
		}
	},
	hookAudioVideoDirect() {
		console.log('hooking audio/video methods...')

		if (audio_video_hooked) {
			return true
			console.log('...already hooked')
		}

		hook_audio_video_basic('AVCaptureDevice', '+ authorizationStatusForMediaType:', 'status_check')
		hook_audio_video_basic('AVCaptureDevice', '+ requestAccessForMediaType:completionHandler:', 'access_request')

		audio_video_hooked = true

		return true
	},
	readInfoPlist() {
		return read_info_plist()
	}
}

// -- Util:

/**
 * Sends a message to the host frida process, informing it that a certain hooked class/method was invoked
 * @param {string} className The class name that was called
 * @param {string} methodName The name of the called method
 */
function sendInvocationEvent(className, methodName, backtrace) {
	sendMessage('invocation', {className, methodName, backtrace})
}

function sendNetworkEvent(url, method, backtrace) {
	sendMessage('network', {url, method, backtrace})
}

/**
 *
 * @param {string} className The class name that was called
 * @param {string} methodName The name of the called method
 * @param {string} access_mode "status_check" or "access_request"
 * @param {string} media_type "audio" or "video"
 */
function sendAudioVideoEvent(className, methodName, access_mode, media_type) {
	sendMessage('audiovideo', {className, methodName, access_mode, media_type})
}

/**
 * Send event data to the host frida process
 * @param {string} eventName
 * @param {object} data JSON-serializable data to be sent
 */
function sendMessage(eventName, data) {
	send({
		name: eventName
		, timestamp: (new Date()).getTime()/1000.0
		, ...data
	})
}

function get_timestamp()
{
	var today = new Date();
	var timestamp = today.getFullYear() + '-' + (today.getMonth() + 1) + '-' + today.getDate() + ' ' + today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds() + ":" + today.getMilliseconds();
	return timestamp;
}



/* Description: iOS 13 SSL Bypass based on https://codeshare.frida.re/@machoreverser/ios12-ssl-bypass/ and https://github.com/nabla-c0d3/ssl-kill-switch2
 *  Author: 	@apps3c
 */

try {
	Module.ensureInitialized("libboringssl.dylib");
} catch(err) {
	console.log("libboringssl.dylib module not loaded. Trying to manually load it.")
	Module.load("libboringssl.dylib");	
}

var SSL_VERIFY_NONE = 0;
var ssl_set_custom_verify;
var ssl_get_psk_identity;	

ssl_set_custom_verify = new NativeFunction(
	Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify"),
	'void', ['pointer', 'int', 'pointer']
);

/* Create SSL_get_psk_identity NativeFunction 
* Function signature https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_get_psk_identity
*/
ssl_get_psk_identity = new NativeFunction(
	Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity"),
	'pointer', ['pointer']
);

/** Custom callback passed to SSL_CTX_set_custom_verify */
function custom_verify_callback_that_does_not_validate(ssl, out_alert){
	return SSL_VERIFY_NONE;
}

/** Wrap callback in NativeCallback for frida */
var ssl_verify_result_t = new NativeCallback(function (ssl, out_alert){
	custom_verify_callback_that_does_not_validate(ssl, out_alert);
},'int',['pointer','pointer']);

Interceptor.replace(ssl_set_custom_verify, new NativeCallback(function(ssl, mode, callback) {
	//  |callback| performs the certificate verification. Replace this with our custom callback
	ssl_set_custom_verify(ssl, mode, ssl_verify_result_t);
}, 'void', ['pointer', 'int', 'pointer']));

Interceptor.replace(ssl_get_psk_identity, new NativeCallback(function(ssl) {
	return "notarealPSKidentity";
}, 'pointer', ['pointer']));
	
console.log("[+] Bypass successfully loaded ");	

// https://codeshare.frida.re/@zionspike/bypass-flutter-pinning-ios/


function bypass_SecTrustEvaluates() {
    // Bypass SecTrustEvaluateWithError
    var SecTrustEvaluateWithErrorHandle = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithErrorHandle) {
        var SecTrustEvaluateWithError = new NativeFunction(SecTrustEvaluateWithErrorHandle, 'int', ['pointer', 'pointer']);
        // Hooking SecTrustEvaluateWithError
        Interceptor.replace(SecTrustEvaluateWithErrorHandle,
            new NativeCallback(function(trust, error) {
                console.log('[!] Hooking SecTrustEvaluateWithError()');
                SecTrustEvaluateWithError(trust, NULL);
                if (error != 0) {
                    Memory.writeU8(error, 0);
                }
                return 1;
            }, 'int', ['pointer', 'pointer']));
    }

    // Bypass SecTrustGetTrustResult
    var SecTrustGetTrustResultHandle = Module.findExportByName("Security", "SecTrustGetTrustResult");
    if (SecTrustGetTrustResultHandle) {
        // Hooking SecTrustGetTrustResult
        Interceptor.replace(SecTrustGetTrustResultHandle, new NativeCallback(function(trust, result) {
            console.log("[!] Hooking SecTrustGetTrustResult");
            // Change the result to kSecTrustResultProceed
            Memory.writeU8(result, 1);
            // Return errSecSuccess
            return 0;
        }, "int", ["pointer", "pointer"]));
    }

    // Bypass SecTrustEveluate
    var SecTrustEvaluateHandle = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluateHandle) {
        var SecTrustEvaluate = new NativeFunction(SecTrustEvaluateHandle, "int", ["pointer", "pointer"]);
        // Hooking SecTrustEvaluate
        Interceptor.replace(SecTrustEvaluateHandle, new NativeCallback(function(trust, result) {
            console.log("[!] Hooking SecTrustEvaluate");
            var osstatus = SecTrustEvaluate(trust, result);
            // Change the result to kSecTrustResultProceed
            Memory.writeU8(result, 1);
            // Return errSecSuccess
            return 0;
        }, "int", ["pointer", "pointer"]));
    }
}

// Main
if (ObjC.available) {

    bypass_SecTrustEvaluates();

} 