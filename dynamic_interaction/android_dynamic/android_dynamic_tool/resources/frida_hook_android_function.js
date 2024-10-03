// Based on https://github.com/sensepost/objection/blob/master/objection/utils/assets/javahookmanager.js

class JavaHookManager {

    // create a new Hook for clazzName, specifying if we
    // want verbose logging of this class' internals.
    constructor(clazzName, verbose = false) {
        this.messageVerbose(`[I:1] Booting JavaHookManager for ${clazzName}...`);

        this.target = Java.use(clazzName);
        // store hooked methods as { method: x, replacements: [y1, y2] }
        this.hooking = [];
        this.available_methods = [];
        this.verbose = verbose;
        this.clazzName = clazzName
        this.populateAvailableMethods();
    }

    messageVerbose(message) {
        if (!this.verbose) {
            return;
        }
        console.log(`send: [v] ${message}`)
        send(`[v] ${message}`);
    }

    message(message) {
        console.log(`send: ${message}`)
        send(message);
    }

    // basically from:
    //  https://github.com/sensepost/objection/blob/fa6a8b8f9b68d6be41b51acb512e6d08754a2f1e/agent/src/android/hooking.ts#L43
    populateAvailableMethods() {
        this.messageVerbose(`[I:3] Populating available methods...`);
        this.available_methods = this.target.class.getDeclaredMethods().map((method) => {
            var m = method.toGenericString();

            // Remove generics from the method
            while (m.includes("<")) {
                m = m.replace(/<.*?>/g, "");
            }

            // remove any "Throws" the method may have
            if (m.indexOf(" throws ") !== -1) {
                m = m.substring(0, m.indexOf(" throws "));
            }

            // remove scope and return type declarations (aka: first two words)
            // remove the class name
            // remove the signature and return
            m = m.slice(m.lastIndexOf(" "));
            m = m.replace(` ${this.clazzName}.`, "");

            return m.split("(")[0];

        }).filter((value, index, self) => {
            return self.indexOf(value) === index;
        });

        this.messageVerbose(`[I:4] Have ${this.available_methods.length} methods...`);
    }

    validMethod(method) {
        if (!this.available_methods.includes(method)) {
            return false;
        }
        return true;
    }

    isHookingMethod(method) {
        if (this.hooking.map(element => {
            if (element.method == method) {
                return true;
            }
            return false;
        }).includes(true)) {
            return true;
        } else {
            return false;
        }
        ;
    }

    add_hook(m, f = null) {
        if (m === "*") {
            this.available_methods.forEach(function(method){
                this.add_hook(method);
            }, this);
            return;
        }
        if (!this.validMethod(m)) {
            this.message(`[E:1] Method ${m} is not valid for this class.`);
            return;
        }
        if (this.isHookingMethod(m)) {
            this.message(`[W:2] Already hooking ${m}. Bailing`);
            return;
        }

        this.message(`[I:2] Hookig ${m} and all overloads...`);

        var r = [];
        this.target[m].overloads.forEach(overload => {
            if (f == null) {
                overload.replacement = function () {
                    return overload.apply(this, arguments);
                }
            } else {
                overload.implementation = function () {
                    var ret = overload.apply(this, arguments);
                    return f(arguments, ret);
                }
            }

            r.push(overload);
        });

        this.hooking.push({method: m, replacements: r});
    }

    static hook(args, return_value) {
        send(`[H:1] Method called.`);
        send(`[H:2] Args: ` + JSON.stringify(args));
        send(`[H:3] Return Value: ` + JSON.stringify(return_value));
        for (const [key, value] of Object.entries(args)) {
            //send(`[H:x] Debug Value: ` + JSON.stringify(value));
            if (value !== null) {
                if (typeof value == "object" && !Array.isArray(value)) {
                    if (Java.use("android.net.Uri").class.isInstance(value)) {
                        send(`[H:4] URI: ` + value.toString());
                    }
                }
            }
        }
        return return_value
    }
}

function run(clazzName, methodName) {
    Java.performNow(function () {
        const hook = new JavaHookManager(clazzName);
        hook.add_hook(methodName, JavaHookManager.hook);
});
}

//run("className", "method");
