import logging
import time
import subprocess
import os
import paramiko
from ui_automation.exploration_strategies import ExplorationStrategy, NonRepeatingRandomButtonExplorationStrategy, iOSBFSExplorationStrategy, iOSDFSExplorationStrategy, iOSExplorationStrategy, iOSAcceptOnlySystemDialogs


from analysis.events.ExternalEventReceiver import ExternalEventReceiver
from ui_automation.app_simulator import AppSimulator

from analysis.app_analyzer import AppAnalyzer


wireshark_sh = "start_tshark.sh"

class AnalysisPipeline:
    def __init__(self, bundle_id: str, xcode_org_id: str, analysis_output_folder: str, device_udid='auto', appium_host='localhost', appium_port=4723, event_receiver_port=8042, device_ip=None):
        """
        device_udid can be 'auto' iff exactly one iOS device is connected via USB
        """
        self.bundle_id = bundle_id
        self.xcode_org_id = xcode_org_id
        self.device_udid: str = device_udid
        self.appium_host: str = appium_host
        self.appium_port: int = appium_port
        self.tool_path: str = os.path.dirname(os.path.abspath(__file__))
        self.folder_path: str = os.path.abspath(os.getcwd())
        self.analysis_output_folder: str = analysis_output_folder
        self.device_ip: str = device_ip

        self.external_event_server: ExternalEventReceiver = ExternalEventReceiver(port=event_receiver_port)
        self.external_event_server.start()

        def connect_ssh(self):
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            host = "127.0.0.1"
            username = "root"
            password = "alpine"
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            proxy_jump_command=f'inetcat 44 -u {self.device_udid}'
            proxy = paramiko.ProxyCommand(proxy_jump_command)
            # Connect to the SSH server through the proxy
            ssh.connect(host, username=username, password=password, sock = proxy, timeout=10)
            transport = ssh.get_transport()
            transport.set_keepalive(3)
            return ssh
        except:
            raise RuntimeError("SSH error")

    def execute_tcpdump_start(self):
        self.execute_tcpdump_stop()
        self.execute_remove_tcpdump_file()
        tcpdump_command = " ".join(["/var/jb/usr/bin/tcpdump", "-i", "en0", "-w", "/var/mobile/Downloads/" + self.bundle_id + ".pcap", "&"])

        #Maybe join
        ssh_client = self.connect_ssh()
        shell = ssh_client.invoke_shell()
        shell.send(f'{tcpdump_command}\n')
        time.sleep(4) # without sleeping time tcpdump not running - also not working ssh_client.exec_command(tcpdump_command)
        ssh_client.close()


    def execute_tcpdump_stop(self):
        ssh_client = self.connect_ssh()
        tcpdump_kill = " ".join(["killall", "tcpdump"])
        ssh_client.exec_command(tcpdump_kill, timeout=10)
        ssh_client.close()

    def execute_remove_tcpdump_file(self):
        ssh_client = self.connect_ssh()
        #self.bundle_id
        remove_file = " ".join(["rm", "/var/mobile/Downloads/*.pcap"])
        ssh_client.exec_command(remove_file, timeout=10)
        ssh_client.close()


    def cleanup_tcpdump(self, run: str):
        self.execute_tcpdump_stop()
        self.pull_tcpdump(run)
        self.execute_remove_tcpdump_file()


    def pull_tcpdump(self, run: str):
        destination = os.path.join(self.folder_path, "out")
        destination = os.path.join(destination, f"tcpdump_{self.bundle_id}_{run}.pcap")
        frida_pull_process = subprocess.Popen(["frida-pull", '-D', self.device_udid, "/var/mobile/Downloads/" + self.bundle_id + ".pcap", destination])
        frida_pull_process.wait(timeout=240)

        # check exitcode to determine whether the download was successful
        return_code = frida_pull_process.returncode
        if return_code > 0:
            raise RuntimeError("Could not dump pcap file.")

    def _start_wireshark(self, wireshark_sh:str):
        """
        Starts Wireshark in the specified environment 'folder_path'. First, it reads the id of the connected USB-device.
        Then, it creates an interface with rvictl.
        Finally, it starts tshark with the newly created interface.
        """
        self.wireshark_process = None
        self._cleanup_wireshark() #just to be sure nothing is running
        #print(self.device_udid)
        rvictl_interface = subprocess.check_output(["rvictl", "-s", self.device_udid]).decode("utf-8").split(' ')[6].strip()
        # Wait for 1 sec 'startup_timeout' times to make sure the tool is running.
        #print(self.tool_path)
        #print(self.folder_path)
        self.wireshark_process = subprocess.Popen(['sh', os.path.join(self.tool_path, wireshark_sh), rvictl_interface], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.folder_path)
        for i in range(3):
            try:
                self.wireshark_process.communicate(timeout=1)
                return_code = self.wireshark_process.returncode
                print(return_code)
                if return_code is not None:
                    self._cleanup_wireshark()
                    raise RuntimeError("Could not start Wireshark.")
            except subprocess.TimeoutExpired:
                pass

    def _cleanup_wireshark(self):
        if self.wireshark_process is not None:
            print("Terminating Wireshark...")
            self.wireshark_process.terminate()
            self.wireshark_process = None

        if self.device_udid is not None:
            # Remove the created 'rvictl' interface
            interface_removed = subprocess.check_output(["rvictl", "-x", self.device_udid]).decode("utf-8")
            print(interface_removed)

    def close(self):
        """ Call this only once, after all apps have been analyzed """
        self.external_event_server.stop_notifying()
        self.external_event_server.stop()
        self.external_event_server = None

    def run_analysis(self, simulation_steps, no_frida: bool = False):
        """ Returns bundle id of analyzed app """
        # start wireshark
        print("Starting Wireshark...")
        self._start_wireshark(wireshark_sh)
        self.execute_tcpdump_start()
        print("Wireshark is running!")

        simulator = AppSimulator(self.xcode_org_id,
            self.device_udid, self.appium_host, self.appium_port, self.device_ip)

        analyzer = AppAnalyzer(
            self.bundle_id, self.analysis_output_folder, self.device_udid)

        self.external_event_server.start_notifying(analyzer)

        try:
            if not no_frida:
                analyzer.start_session()
            else:
                analyzer.start_app_without_frida()
        except Exception as ex:
            self._cleanup_wireshark()
            self.cleanup_tcpdump("0")

            logging.exception('failed to start session')
            raise ex

        logging.info(
            'dynamic analysis started, waiting 30s before starting UI simulation to ensure app init')
        try:
            simulator.start(self.bundle_id, 10, iOSAcceptOnlySystemDialogs)
            time.sleep(20)
        except Exception as ex:
            logging.exception("UI simulation could not be completed")
            raise ex
        finally:
            self._cleanup_wireshark()
            self.cleanup_tcpdump("1")


        print("Starting Wireshark...")
        self._start_wireshark(wireshark_sh)
        self.execute_tcpdump_start()
        print("Wireshark is running!")

        logging.info('Starting Simulation...')

        try:
            simulator.start(self.bundle_id, simulation_steps, iOSDFSExplorationStrategy)
        except Exception as ex:
            logging.exception("UI simulation could not be completed")
            raise ex
        finally:
            self._cleanup_wireshark()
            self.cleanup_tcpdump("2")


        logging.info('Simulation ended...')

        analyzer.end_session()
        self.external_event_server.stop_notifying()

        return self.bundle_id
