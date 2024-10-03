class BasicJavaClassHook {
    static getClassName() {
        return "";
    }

    static getRelevantMethods() {
        return [];
    }

    static getRelevantClassMethods() {
        return [];
    }

    static getHookConstructor() {
        return false;
    }

    constructor(fd_tracker = null) {
        if (new.target === BasicJavaClassHook || this.constructor.getClassName() === "") {
            throw new TypeError("Cannot construct Abstract instances directly");
        }
        this.clazzName = this.constructor.getClassName();
        this.target = Java.use(this.clazzName);
        this.fd_tracker = fd_tracker;
        this.track_fd = (fd_tracker !== null);
    }

    hookAll() {
        if (this.constructor.getHookConstructor()) this.hookConstructor();
        this.hookMethods();
    }

    hookMethods() {
        this.constructor.getRelevantMethods().forEach(function(method_name){
            this.hook_method(method_name);
        }, this);
        this.constructor.getRelevantClassMethods().forEach(function(method_name){
            this.hook_class_method(method_name);
        }, this);
    }

    hookConstructor() {
        let class_name = this.clazzName;
        let context = this;
        send(`[I:2] Hookig ${this.clazzName} constructor.`);
        let hook_implementation = this.constructorHookImplementation;
        this.target["$init"].overloads.forEach(overload => {
            overload.implementation = function () {
                let return_value = overload.apply(this, arguments);
                return_value = hook_implementation(class_name, this, arguments, return_value, context);
                return return_value;
            }
        });
    }

    hookMethod(method_name) {
        let class_name = this.clazzName;
        let context = this;
        send(`[I:2] Hookig ${this.clazzName}.${method_name}().`);
        let hook_implementation = this.instanceMethodHookImplementation;
        this.target[method_name].overloads.forEach(overload => {
            overload.implementation = function () {
                let return_value = overload.apply(this, arguments);
                return_value = hook_implementation(class_name, method_name, this, arguments, return_value, context);
                return return_value;
            }
        });
    }

    hookClassMethod(method_name) {
        let class_name = this.clazzName;
        let context = this;
        send(`[I:2] Hookig class method ${this.clazzName}.${method_name}().`);
        let class_hook_implementation = this.classMethodHookImplementation;
        this.target[method_name].overloads.forEach(overload => {
            overload.implementation = function () {
                let return_value = overload.apply(this, arguments);
                return_value = class_hook_implementation(class_name, method_name, this, arguments, return_value, context);
                return return_value;
            }
        });
    }

    constructorHookImplementation(class_name, obj, args, return_value, context) {
        return return_value;
    }

    instanceMethodHookImplementation(class_name, method_name, obj, args, return_value, context) {
        return return_value;
    }

    classMethodHookImplementation(class_name, method_name, clazz, args, return_value, context) {
        return return_value;
    }
}

class FileDescriptorTable {
    constructor() {
        this.fds = [];
    }

    getPathByFileDescriptor(fd) {
        if (fd in this.fds) {
            return this.fds[fd];
        }
        else return null;
    }

    getFileDescriptorByPath(path) {
        this.fds.forEach(function (value, fd) {
            if (path === value) {
                return fd;
            }
        })
        return null;
    }

    setFileDescriptor(fd, path) {
        this.fds[fd] = path;
    }
}

class JavaFileClassHook extends BasicJavaClassHook{

    static getClassName() {
        return "java.io.File";
    }

    static getRelevantMethods() {
        return [
            'createNewFile',
            'delete',
            'deleteOnExit',
            'exists',
            'isDirectory',
            'isFile',
            'lastModified',
            'length',
            'list',
            'listFiles',
            'renameTo',
            'setExecutable',
            'setLastModified',
            'setReadable',
            'setWritable',
        ];
    }

    static getRelevantClassMethods() {
        return [
            'createTempFile'
        ];
    }

    static getHookConstructor() {
        return true;
    }

    constructorHookImplementation(class_name, obj, args, return_value, context) {
        send(`[H:5] ${class_name}: ` + obj.getAbsolutePath());
        return return_value;
    }

    instanceMethodHookImplementation(class_name, method_name, obj, args, return_value, context) {
        send(`[H:6] ${class_name}: ${method_name}: ` + obj.getAbsolutePath());
        return return_value;
    }

    classMethodHookImplementation(class_name, method_name, clazz, args, return_value, context) {
        let file_name = "";
        if (typeof return_value == 'object' && !Array.isArray(return_value)) {
            if (Java.use("java.io.File").class.isInstance(return_value)) {
                file_name = return_value.getAbsolutePath();
            }
        }
        send(`[H:7] ${class_name}: ${method_name}: ` + file_name);
        return return_value;
    }
}

class JavaFileIOAccessClassHook extends BasicJavaClassHook{  // Still abstract

    getFileDescriptorFromObject(obj) {
        return null;
    }

    static getHookConstructor() {
        return true;
    }

    constructorHookImplementation(class_name, obj, args, return_value, context) {
        send(`[I:0] ${class_name}: ${JSON.stringify(args)}`);
        let file_name = "";
        if (typeof args[0] == 'object' && !Array.isArray(args[0])) {
            if (Java.use("java.io.File").class.isInstance(args[0])) {
                file_name = args[0].getAbsolutePath();
            }
            else if (Java.use("java.lang.String").class.isInstance(args[0])) {
                file_name = args[0];
            }
            else if (Java.use("java.io.FileDescriptor").class.isInstance(args[0])) {
                if (context.track_fd) {
                    let fd = args[0].hashCode();
                    if (fd !== null) {
                        let path = context.fd_tracker.getPathByFileDescriptor(fd);
                        if (path !== null) {
                            file_name = path;
                            send(`[I:1] ${class_name}: Resolved FD ${fd} to path ${path}.`);
                        }
                        else {
                            send(`[I:1] ${class_name}: Could not resolve FD ${fd}.`);
                        }
                    }
                }
            }
        }
        else if (typeof args[0] === 'string') {
            file_name = args[0];
        }
        if (context.track_fd && file_name !== "" && context.get_obj_file_descriptor(obj) !== null) {
            let fd = context.getFileDescriptorFromObject(obj);
            context.fd_tracker.setFileDescriptor(fd, file_name);
            send(`[I:2] ${class_name}: Saved FD ${fd} = path ${file_name}.`);
        }
        send(`[H:5] ${class_name}: ${file_name}`);
        return return_value;
    }
}

class JavaFileStreamClassHook extends JavaFileIOAccessClassHook{
    static getRelevantMethods() {
        return [
            'getFD',
        ];
    }

    getFileDescriptorFromObject(obj) {
        if (obj.getFileDescriptorFromObject().valid()) {
            return obj.getFileDescriptorFromObject().hashCode();
        }
        return null;
    }

    instanceMethodHookImplementation(class_name, method_name, obj, args, return_value, context) {
        send(`[I:0] ${class_name}: ${method_name}: ${return_value}`);
        return return_value;
    }
}

class JavaFileInputStreamClassHook extends JavaFileStreamClassHook{
    static getClassName() {
        return "java.io.FileInputStream";
    }
}

class JavaFileOutputStreamClassHook extends JavaFileStreamClassHook{
    static getClassName() {
        return "java.io.FileOutputStream";
    }
}

class JavaFileReaderClassHook extends JavaFileIOAccessClassHook{
    static getClassName() {
        return "java.io.FileReader";
    }
}

class JavaFileWriterClassHook extends JavaFileIOAccessClassHook{
    static getClassName() {
        return "java.io.FileWriter";
    }
}

class JavaFilesClassHook extends BasicJavaClassHook{

    static getClassName() {
        return "java.nio.file.Files";
    }

    static getRelevantClassMethods() {
        return [
            'copy',
            'createDirectory',
            'createFile',
            'createLink',
            'createSymbolicLink',
            'createTempDirectory',
            'createTempDirectory',
            'createTempFile',
            'createTempFile',
            'delete',
            'deleteIfExists',
            'exists',
            'find',
            'isDirectory',
            'isExecutable',
            'isHidden',
            'isReadable',
            'isRegularFile',
            'lines',
            'list',
            'move',
            'newBufferedReader',
            'newBufferedWriter',
            'newByteChannel',
            'newDirectoryStream',
            'newInputStream',
            'newOutputStream',
            'readAllBytes',
            'readAllLines',
            'size',
            'walk',
            'walkFileTree',
            'write'
        ];
    }

    classMethodHookImplementation(class_name, method_name, clazz, args, return_value, context) {
        send(`[I:0] ${class_name}: ${JSON.stringify(args)}`);
        let file_name = "";
        if (typeof args[0] == 'object' && !Array.isArray(args[0])) {
            if (Java.use("java.nio.file.Path").class.isInstance(args[0])) {
                let path_object = args[0];
                if (!args[0].isAbsolute()) {
                    path_object = path_object.toAbsolutePath();
                }
                file_name = path_object.toString();
            }
            else if (Java.use("java.io.File").class.isInstance(args[0])) {
                file_name = args[0].getAbsolutePath();
            }
            else if (Java.use("java.lang.String").class.isInstance(args[0])) {
                file_name = args[0];
            }
            else if (Java.use("java.io.FileDescriptor").class.isInstance(args[0])) {
                if (context.track_fd) {
                    let fd = args[0].hashCode();
                    if (fd !== null) {
                        let path = context.fd_tracker.getPathByFileDescriptor(fd);
                        if (path !== null) {
                            file_name = path;
                            send(`[I:1] ${class_name}: Resolved FD ${fd} to path ${path}.`);
                        }
                        else {
                            send(`[I:1] ${class_name}: Could not resolve FD ${fd}.`);
                        }
                    }
                }
            }
        }
        else if (typeof args[0] === 'string') {
            file_name = args[0];
        }
        send(`[H:7] ${class_name}: ${method_name}: ${file_name}`);
        return return_value;
    }
}

function run() {
    Java.performNow(function () {
        const fd_tracker = new FileDescriptorTable();

        const FileClass = new JavaFileClassHook(fd_tracker);
        FileClass.hookAll();

        const FileReaderClass = new JavaFileReaderClassHook(fd_tracker);
        FileReaderClass.hookAll();
        const FileWriterClass = new JavaFileWriterClassHook(fd_tracker);
        FileWriterClass.hookAll();

        const FileInputStreamClass = new JavaFileInputStreamClassHook(fd_tracker);
        FileInputStreamClass.hookAll();
        const FileOutputStreamClass = new JavaFileOutputStreamClassHook(fd_tracker);
        FileOutputStreamClass.hookAll();

        const FilesClass = new JavaFilesClassHook(fd_tracker);
        FilesClass.hookAll();
});
}

run();
