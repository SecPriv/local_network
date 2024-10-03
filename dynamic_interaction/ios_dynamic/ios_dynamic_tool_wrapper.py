import os
import subprocess
import signal

# Names of the scripts to start before the Analysis Tool
appium_sh = "start_appium.sh"
mitmproxy_sh = "start_mitmproxy.sh"
wireshark_sh = "start_tshark.sh"

# Time to wait after every tool's start-up to make sure the tool runs
startup_timeout = 3

class iOSDynamicToolWrapper():
    """
    Class to wrap the Analysis Tool.
    Initialize class variables and then simply call the start method.
    """
    appium_process = None
    mitmproxy_process = None
    wireshark_process = None
    device_id = None
    analysis_tool_process = None

    tool_args: str = None
    output_path: str = None
    udid: str = None
    bundle_id: str = None
    app_hash: str = None
    tool_path: str = None
    folder_path: str = None
    run_id: str = None
    out_dir: str = None
    folder_path: str = None

    def __init__(self, tool_args: str, udid: str, output_path: str, bundle_id: str, app_hash:str, tool_path: str, mitmproxy_port: int, run_id:str, no_mitmproxy: bool, appium_port: int) -> None:
        self.tool_args = tool_args
        self.udid = udid
        self.output_path = os.path.abspath(output_path)
        self.bundle_id = bundle_id
        self.app_hash = app_hash
        self.tool_path = os.path.abspath(tool_path)
        self.mitmproxy_port = mitmproxy_port
        self.run_id = run_id
        self.no_mitmproxy = no_mitmproxy
        self.appium_port = appium_port

    def get_pid(self, port):
        try:
            # Run the lsof command and capture its output
            result = subprocess.run(['lsof', '-t', f'-i:{port}'], capture_output=True, text=True, check=True)

            # Extract the process ID (PID) from the output
            pid = result.stdout.strip()

            return pid
        except subprocess.CalledProcessError:
            # Handle the case where the lsof command fails (e.g., if the port is not in use)
            print(f"No process found using port {port}")
            return None


    def _get_device_id(self):
        """
        Gets the id of the connected USB device. If not already set, it calls 'idevice_id' and uses the FIRST connected device.
        """
        if self.device_id is None:
            # gets device id. format of output is '<device-id> (USB)', hence we remove the (USB) part
            self.device_id = subprocess.check_output('idevice_id').decode("utf-8").split(' ')[0]
        return self.device_id

    def _start_appium(self, appium_sh:str):
        """
        Starts Appium in the specified environment 'folder_path'. Needs to be started BEFORE wireshark and mitmproxy to work consistently.
        """
        print(f"{os.path.join(self.tool_path, appium_sh)}")
        appium_pid = self.get_pid(self.appium_port)

        if appium_pid != None and len(appium_pid) > 0:
            subprocess.Popen(["kill", f"{appium_pid}"]) # kill appium

        self.appium_process = subprocess.Popen(['sh', os.path.join(self.tool_path, appium_sh), f"{self.appium_port}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.folder_path, preexec_fn=os.setsid)
        # Wait for 1 sec 'startup_timeout' times to make sure the tool is running.
        for i in range(startup_timeout):
            try:
                self.appium_process.communicate(timeout=1)
                return_code = self.appium_process.returncode
                if return_code is not None:
                    self._cleanup()
                    raise RuntimeError("Could not start Appium.")
            except subprocess.TimeoutExpired:
                pass

    def _start_mitmproxy(self, mitmproxy_sh:str):
        """
        Starts mitmproxy in the specified environment 'folder_path'.
        'os.setsid' is used to create a process group in order to terminate child-processes of mitmproxy.
        """
        print(f"{os.path.join(self.tool_path, mitmproxy_sh)}")
        mitm_pid = self.get_pid(self.mitmproxy_port)

        if mitm_pid != None and len(mitm_pid) > 0:
            subprocess.Popen(["kill", f"{mitm_pid}"]) # kill mitm

        self.mitmproxy_process = subprocess.Popen(['sh', os.path.join(self.tool_path, mitmproxy_sh), f"{self.mitmproxy_port}"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.folder_path, preexec_fn=os.setsid)
        # Wait for 1 sec 'startup_timeout' times to make sure the tool is running.
        for i in range(startup_timeout):
            try:
                self.mitmproxy_process.communicate(timeout=1)
                return_code = self.mitmproxy_process.returncode
                if return_code is not None:
                    self._cleanup()
                    raise RuntimeError("Could not start mitmproxy.")
            except subprocess.TimeoutExpired:
                pass

    def _start_dynamic_ios_analysis(self):
        """
        Starts the analysis tool in the specified environment 'folder_path'.
        """
        argument_list = self.tool_args.split(' ') # DS: for me adding the whole argument list did not work unfortunately
        argument_list.append("--appium_port")
        argument_list.append(f"{self.appium_port}")
        self.analysis_tool_process = subprocess.Popen(['python', os.path.join(self.tool_path, 'main.py'), '--udid', self.udid, '-i', self.bundle_id] + argument_list, cwd=self.folder_path)

    def _wait_for_analysis(self):
        """
        Waits for the analysis process to finish.
        """
        if self.analysis_tool_process is not None:
            self.analysis_tool_process.wait()

    def _cleanup(self):
        """
        Terminates all running processes and deletes the interface created for tshark.
        """
        if self.analysis_tool_process is not None:
            print("Terminating ios-dynamic-analysis tool...")
            self.analysis_tool_process.terminate()
            self.analysis_tool_process = None

        if self.appium_process is not None:
            print("Terminating Appium...")
            os.killpg(os.getpgid(self.appium_process.pid), signal.SIGTERM)
            self.appium_process = None

        if self.mitmproxy_process is not None:
            print("Terminating Mitmproxy...")
            # Apparently terminate is not enough to get rid of this process, as it starts child-processes.
            # Therefore, we use a process group for it and it's children and terminate the entire group.
            os.killpg(os.getpgid(self.mitmproxy_process.pid), signal.SIGTERM)
            self.mitmproxy_process = None

        if self.device_id is not None:
            # Remove the created 'rvictl' interface
            interface_removed = subprocess.check_output(["rvictl", "-x", self.device_id]).decode("utf-8")
            print(interface_removed)
            self.device_id = None

    def start(self):
        """
        Starts the analysis pipeline and all required tools, collects all data and stores it into the db.
        """

        # create a new folder named after the run-id of the pipeline run to gather all files
        self.folder_path = os.path.join(self.output_path, self.run_id)

        print(f"Creating folder for tool-output at {self.folder_path}")

        if not os.path.exists(self.folder_path):
            os.makedirs(self.folder_path)
        #else:
        #    raise RuntimeError(f"Folder already exists: {self.folder_path}")

        out_dir_rel = os.path.join(self.folder_path,'out')
        self.out_dir = os.path.abspath(out_dir_rel)

        # Step 3: for the tool, three services must be started beforehand
        print("Step 3: Starting required programs (Appium, mitmproxy, wireshark)...")
        # # Start Appium
        print("Starting Appium...")
        self._start_appium(appium_sh)
        print("Appium is running!")

        # Start wireshark
        #print("Starting Wireshark...")
        #self._start_wireshark(wireshark_sh)
        #print("Wireshark is running!")

        if not self.no_mitmproxy:
            # Start mitmproxy
            print("Starting mitmproxy...")
            self._start_mitmproxy(mitmproxy_sh)
            print("mitmproxy is running!")

        # Step 4: execute the analysis tool with the given parameters for the given app
        # run actual analysis
        print("Step 4: Running the analysis...")
        self._start_dynamic_ios_analysis()
        # Wait for tool to finish
        self._wait_for_analysis()


    def __del__(self):
        print('Initializing cleanup...')
        self._cleanup()

