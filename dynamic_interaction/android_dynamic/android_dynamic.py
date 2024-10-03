import json
import os
import subprocess
import signal
import csv
import time
from pathlib import Path
from typing import List

from android_dynamic_tool.main import AnalysisTool

# Time to wait after every tool's start-up to make sure the tool runs
startup_timeout = 3
TOOL_NAME = "android-dynamic"


class AndroidDynamicWrapper:
    """
    Class to wrap the dynamic-android analysis tool.
    Initialize class variables and then call the start method.
    """

    def __init__(self, output_path: str, pipeline_run_id: str, apk_path: str, adb_udid: str = None, launcher_package_name: str = None, mitm_proxy_addr: str = "192.168.3.1", pcapdroid_path: str = "./pcapDroid.apk", mitm_proxy_port: str = "8080", appium_port: str = 4723, no_frida_no_proxy: bool = False) -> None:
        # Set input variables
        self.output_path = os.path.abspath(output_path)
        self.pipeline_run_id = pipeline_run_id
        self.apk_path: Path = Path(apk_path).absolute()
        self.adb_udid: str = adb_udid
        self.launcher_package_name: str = launcher_package_name
        self.mitm_proxy_addr = mitm_proxy_addr
        self.pcapdroid_path = pcapdroid_path
        # Define additional variables
        self.mitmproxy_process = None
        self.analysis_tool_process = None
        self.folder_path = None
        self.out_dir = None
        self.mitm_proxy_port = mitm_proxy_port
        self.appium_port = appium_port
        self.no_frida_no_proxy = no_frida_no_proxy

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

    def pre_cleanup(self, mitmproxy, appium):
        if not self.no_frida_no_proxy:
            mitm_pid = self.get_pid(mitmproxy)
            if mitm_pid != None and len(mitm_pid) > 0:
                subprocess.Popen(["kill", f"{mitm_pid}"]) # kill mitmdump

        appium_pid = self.get_pid(appium)
        if appium_pid != None and len(appium_pid):
            subprocess.Popen(["kill", f"{appium_pid}"])# kill appium
        # `mitmproxy`, `appium` (`node`)


    def _start_mitmproxy(self, transparent: bool = True, mitmproxy_port: str = "8080"):
        """
        Starts mitmproxy in the specified environment 'folder_path'.
        'os.setsid' is used to create a process group in order to terminate child-processes of mitmproxy.
        """
        # Wait for 1 sec 'startup_timeout' times to make sure the tool is running.

        # important to add SSLKEYLOGFILE to decrypt later on wireshark files
        my_env = os.environ.copy()
        my_env["SSLKEYLOGFILE"] = os.path.join(self.folder_path, "keylogfile.txt")
        print(f"SSLKEYLOGFILE the path is: {os.path.join(self.folder_path, 'keylogfile.txt')}")
        mitm_path = os.path.join(self.folder_path, "dump.mitm")
        additional_args: List[str] = []
        if transparent:
            additional_args.append("--mode")
            additional_args.append("transparent")

        print(['mitmdump', '--ssl-insecure', '-p', mitmproxy_port, "-w", mitm_path] + additional_args)
        self.mitmproxy_process = subprocess.Popen(['mitmdump', '--ssl-insecure', '-p', mitmproxy_port, "-w", mitm_path] + additional_args,
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT,
                                                  cwd=self.folder_path,
                                                  env=my_env,
                                                  preexec_fn=os.setsid)

        for i in range(startup_timeout):
            try:
                self.mitmproxy_process.communicate(timeout=1)
                return_code = self.mitmproxy_process.returncode
                if return_code is not None:
                    self._cleanup()
                    raise RuntimeError("Could not start mitmproxy.")
            except subprocess.TimeoutExpired:
                pass

    def _start_analysis(self):
        """
        Starts the analysis tool in the specified environment 'folder_path'.
        """
        mitm_address = ''
        if not self.no_frida_no_proxy:
            mitm_address = f'{self.mitm_proxy_addr}:{self.mitm_proxy_port}'
        analysis_tool = AnalysisTool(
            apk_path=self.apk_path,
            adb_udid=self.adb_udid,
            launcher_package_name= self.launcher_package_name,
            capture_network_traffic_with_pcapdroid=True,
            pcapdroid_path=self.pcapdroid_path,
            mitmproxy_address=mitm_address,
            bypass_ssl_pinning= not self.no_frida_no_proxy,
            api_tracking = False,
            use_objection = False,
            appium_server_port=self.appium_port,
            appium_start_command=f'appium server --allow-insecure=execute_driver_script,adb_shell --relaxed-security --base-path /wd/hub -p {self.appium_port}' , # --allow-insecure=execute_driver_script,adb_shell      --relaxed-security --base-path /wd/hub
            random_seed="F19476B6A9",
            out_dir=self.out_dir,
            steps=25
        ) 
        analysis_tool.start_analysis()

    def _wait_for_analysis(self):
        """
        Waits for the analysis process to finish.
        """
        if self.analysis_tool_process is not None:
            self.analysis_tool_process.wait()

    def _cleanup(self):
        """
        Terminates all running processes.
        """
        if self.analysis_tool_process is not None:
            print("Terminating dynamic-android tool...")
            self.analysis_tool_process.terminate()
            self.analysis_tool_process = None

        if self.mitmproxy_process is not None:
            print("Terminating Mitmproxy...")
            # Apparently terminate is not enough to get rid of this process, as it starts child-processes.
            # Therefore, we use a process group for it and it's children and terminate the entire group.
            os.killpg(os.getpgid(self.mitmproxy_process.pid), signal.SIGTERM)
            self.mitmproxy_process = None

    def _collect_results(self):
        """
        Collects all results of each app that was analysed and stores them in the db.
        """
        # the output folder potentially contains results from multiple analysed apps
        # each in the respective folder named after the app's bundle id
        result_directory = self.out_dir

        # Iterate through all run folders
        #for run in os.scandir(result_directory):
        #run_directory = os.path.join(result_directory, run)
        # read metadata.csv
        with open(os.path.join(result_directory, 'metadata.csv'), 'w', newline='') as csvfile:
            metadata = list(csv.DictReader(csvfile, delimiter=";"))[0]
        # extract the hash
        sha256 = metadata['sha256_hash']
        # extract app id
        app_id = metadata['package_name']
        # extract analysis_stats.json
        result_json_path = os.path.join(result_directory, sha256, 'analysis_stats.json')
        # extract other paths
        appium_log_path = os.path.join(result_directory, sha256, 'appium.log')
        analysis_log_path = os.path.join(result_directory, sha256, 'analysis.log')
        pcap_path = os.path.join(result_directory, sha256, 'analysis.pcap')
        if result_json_path and os.path.exists(result_json_path):
            with open(result_json_path, 'r') as result_fp:
                result = json.load(result_fp)

            # Add to database
        else:
            print("analysis_stats.json not found")
            raise RuntimeError("Analysis results not found")

    def start(self):
        """
        Starts the analysis pipeline and all required tools, collects all data and stores it into the db.
        """
        # create a new folder named after the run-id of the pipeline run to gather all files
        self.folder_path = os.path.join(self.output_path, self.pipeline_run_id)

        print(f"Creating folder for tool-output at {self.folder_path}")

        if not os.path.exists(self.folder_path):
            os.makedirs(self.folder_path)
        else: 
            raise RuntimeError(f"Folder already exists: {self.folder_path}")


        self.pre_cleanup( self.mitm_proxy_port, self.appium_port)
        time.sleep(1)

        # out_dir_rel = os.path.join(self.folder_path, 'out')
        self.out_dir = os.path.abspath(self.folder_path)


        if not self.no_frida_no_proxy:
            # Step 3: for the tool, three services must be started beforehand
            print("Step 3: Start mitmproxy")
            # Start mitmproxy
            print("Starting mitmproxy...")
            #FIXME: add command line argument for transparent mode
            self._start_mitmproxy(transparent=False, mitmproxy_port = self.mitm_proxy_port)
            print("mitmproxy is running!")

        # Step 4: execute the analysis tool with the given parameters for the given app
        # run actual analysis
        print("Step 4: Running the analysis...")
        self._start_analysis()
        # Wait for tool to finish
        self._wait_for_analysis()

        # Step 5: collect the data and store in db
        print("Step 5: Collect the data and insert it into the database")

    def __del__(self):
        print('Initializing cleanup...')
        self._cleanup()
