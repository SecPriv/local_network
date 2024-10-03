"""
Wrapper implementation for the analysis tool.
Run this file with --help to get possible options.
"""
from datetime import datetime
from .ios_dynamic_tool_wrapper import iOSDynamicToolWrapper
from .app_installer import AppInstaller

import signal
import sys
import argparse
import os
import subprocess
import re

def exit_on_error(error: str):
    """
    Exits on error and updates pipeline run.
    """
    print(error)
    exit(1)

def id_in_output_path(output_path, bundle_id):
    for f in os.listdir(output_path):
        if f.startswith(bundle_id + "-"):
            return True

    return False


def uninstall_non_required_apps(udid, bundle_id, app_installer) -> None:
    required = ["com..WebDriverAgentRunner.xctrunner", "com..WebDriverAgentRunner","com.apple.dt.XcodePreviews", "com.apple.camera", "com.apple.sidecar", "com.apple.appleseed.FeedbackAssistant", "com.apple.webapp", "com.apple.PosterBoard", "com.apple.AppStore", "com.apple.mobilecal", "com.apple.mobilemail", "com.apple.Maps", "com.nemoapps.malayfree", "com.apple.mobilesafari", "com.apple.Preferences", "com..WebDriverAgentRunner.xctrunner", "com..WebDriverAgentRunner", "org.coolstar.SileoStore", "secpriv.DisplayAdID", "com.apple.facetime", "com.apple.DocumentsApp", "com.apple.findmy", "com.apple.Fitness", "com.apple.freeform", "com.apple.Health", "com.apple.Home", "com.apple.Magnifier", "com.apple.measure", "com.apple.MobileSMS", "com.apple.Music", "com.apple.mobilenotes", "com.apple.mobilephone", "com.apple.mobileslideshow", "com.apple.podcasts", "com.apple.reminders", "com.apple.shortcuts", "com.apple.stocks", "com.apple.tips", "com.apple.Translate", "com.apple.VoiceMemos", "com.apple.Passbook", "com.apple.weather", "com.-v2.WebDriverAgentRunner.xctrunner", "com.-v2.WebDriverAgentRunner", "xyz.willy.Zebra", "com.apple.MobileStore", "com.samiiau.loader"]
    required.append(bundle_id)
    #frida_ps_output = subprocess.check_output(['frida-ps', '-D', udid, "-ai"]).decode("utf-8")
    #identifiers.remove("Identifier")
    identifiers = app_installer.get_installed_apps()
    for identifier in identifiers:
        identifier = identifier.strip()
        if identifier not in required:
            print(f"uninstalling {identifier} as it is not required")
            try:
                app_installer.uninstall(identifier)
            except RuntimeError as e:
                print(e)


def skip_closing(line):
    required = ["com..WebDriverAgentRunner", "org.coolstar.SileoStore", "com.-v2.WebDriverAgentRunner.xctrunner", "com.-v2.WebDriverAgentRunner", "xyz.willy.Zebra", "com.samiiau.loader"]
    required.append("Identifier")
    for bundle_id in required:
        if bundle_id in line:
            return True
    return False

def close_apps(udid):
    frida_ps_output = subprocess.check_output(['frida-ps', '-D', udid, "-a"]).decode("utf-8")

    for line in frida_ps_output.splitlines():
        if not skip_closing(line):
            pid_match = re.match(r'^(\d+)\s+', line)
            if pid_match:
                pid = pid_match.group(1)
                print(f"Got {line} and killing process {pid}")
                subprocess.call(["frida-kill", "-D", udid, pid.strip()])

def main():
    """
    The main entry point for this wrapper
    """
    parser = argparse.ArgumentParser(description='Wrapper for the dynamic ios analysis tool.',
                                     epilog='Either --apps-file-path or --apps-to-analyse or both must be present.')

    parser.add_argument('-t', '--tool-args', help='arguments for the dynamic analysis tool', required=True)
    parser.add_argument('-f', '--ipa-path', help='path to the ipa file that should be installed and analysed',
                        required=True)
    parser.add_argument('-a', '--app-id', help='bundle id of the app to be analysed', required=True)
    parser.add_argument('-o', '--output-path', default='./out',
                        help='Path to a folder for the output of the tools. Default: "./out"')
    parser.add_argument('-p', '--tool-path', default='./ios_dynamic/ios_dynamic_tool',
                        help='Path to the folder of the dynamic tool. Default: "./ios_dynamic/ios_dynamic_tool"')
    parser.add_argument('-m', '--mitmproxy-port', default=8080, help="Port for mitmproxy.")
    parser.add_argument('-u', '--udid', help='udid of the physical device the analysis is performed on', required=True)
    parser.add_argument('-np', '--no-mitmproxy', help='execute analysis without running mitmproxy', action="store_true")
    parser.add_argument('-ap', '--appium-port', help='The port appium is running', default=4723, type=int)


    def signal_handler(sig, frame):
        print('Initializing cleanup...')
        print('Terminated due to interrupt.')
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    args = parser.parse_args()
    tool_args = args.tool_args
    ipa_path = args.ipa_path
    bundle_id = args.app_id
    tool_path = args.tool_path
    output_path = args.output_path
    udid = args.udid
    mitmproxy_port = args.mitmproxy_port
    no_mitmproxy = args.no_mitmproxy
    appium_port = args.appium_port


    try:
        #Step 0: check if app already analyzed
        if os.path.exists(os.path.join(output_path, bundle_id)) or id_in_output_path(output_path, bundle_id):
            print("App already analyzed terminating")
            raise RuntimeError(f"Folder already exists")
        else:
            print(f"Creating folder for tool-output at {os.path.join(output_path, bundle_id)}")

            os.makedirs(os.path.join(output_path, bundle_id))

        app_installer = AppInstaller(ipa_path, udid)
        uninstall_non_required_apps(udid, bundle_id,app_installer)

        # Step 1: install target app onto device identified by udid
        print("Step 1: Installing app onto device...")
        app_installer.install()
        app_hash = app_installer.get_app_hash()
        #app_hash = ""

        # Steps 2-4: Run analysis tool
        tool_wrapper = iOSDynamicToolWrapper(tool_args=tool_args, udid=udid, output_path=output_path,
                                             bundle_id=bundle_id,
                                             app_hash=app_hash, tool_path=tool_path, mitmproxy_port=mitmproxy_port,
                                             run_id=f"{bundle_id}", #-{datetime.today().strftime('%Y-%m-%d-%H-%M-%S')}
                                             no_mitmproxy=no_mitmproxy, appium_port= appium_port
                                             )
        tool_wrapper.start()

        # Step 5: Uninstall target app from device
        print("Step 5: Uninstalling app...")
        app_installer.uninstall(bundle_id)

    except RuntimeError as e:
        import traceback
        print(traceback.format_exc())
        exit_on_error(error=f'ERROR: {e}')

    print("#####################")
    print("# ANALYSIS FINISHED #")
    print("#####################")


if __name__ == '__main__':
    main()
