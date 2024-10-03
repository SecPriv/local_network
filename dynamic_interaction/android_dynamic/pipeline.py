import argparse
import os.path
from datetime import datetime
import csv

# local
from android_dynamic import AndroidDynamicWrapper

# Name of this analysis tool
TOOL_NAME = "android-dynamic-tool-wrapper"


def log_line(file, apk, time, message):
    if not os.path.exists(file):
        with open(file, 'w') as f:
            csvwriter = csv.writer(f)
            csvwriter.writerow(["App", "Time", "Message"])

    with open(file, "a") as f:
        csvwriter = csv.writer(f)
        csvwriter.writerow([apk, time, message])

    return


def main():
    """
    The main entry point for this wrapper
    """
    parser = argparse.ArgumentParser(description='Wrapper for the dynamic android analysis tool')
    parser.add_argument('-f', '--apk-path', help='path to the apk file that should be installed and analysed',
                        required=True)
    parser.add_argument('-a', '--adb-udid', help='adb udid', type=str, default="35091JEGR09076",
                        required=True)

    parser.add_argument('-l', '--launcher-package-name', help='package name', type=str,
                        default="com.google.android.apps.nexuslauncher",
                        required=True)

    parser.add_argument("-t", "--transparent", help="set if MITMPROXY should be started in transparent mode",
                        action='store_true')
    parser.add_argument('-lo', '--log-output', default='./log-output.csv',
                        help='Path to the log file')
    parser.add_argument('-nfnp','--no-frida-no-proxy', action='store_true')


    parser.add_argument('-ap', '--appium-port', default='4723',
                        help='Appium port')
    parser.add_argument('-mpp', '--mitm-proxy-port', default='8080',
                        help='Mitm proxy port')
    parser.add_argument('-mpa', '--mitm-proxy-addr', default='192.168.3.1',
                        help='Mitm proxy address')
    parser.add_argument('-pp', '--pcapdroid-path', default='./pcapDroid.apk',
                        help='Path to the pcapdroid apk')

    parser.add_argument('-o', '--output-path', default='./out',
                        help='Path to a folder for the output of the tools. Default: "./out"')

    # Parse command line arguments
    args = parser.parse_args()
    apk_path = args.apk_path
    output_path = args.output_path

    id: str = os.path.basename(apk_path)
    id = id[0:len(id) - 4] #+ f"_{datetime.today().strftime('%Y-%m-%d')}"


    result_path = os.path.join(output_path, id)
    print(result_path)
    if os.path.exists(result_path):
        print(f"already exists skipping: {id}")
        exit()

    try:
        print("Created database indices successfully")

        # Initialize dynamic analysis tool
        tool_wrapper = AndroidDynamicWrapper(
            output_path=output_path,
            pipeline_run_id=id,
            apk_path=apk_path,
            adb_udid=args.adb_udid,
            launcher_package_name=args.launcher_package_name,
            mitm_proxy_addr=args.mitm_proxy_addr,
            pcapdroid_path=args.pcapdroid_path,
            mitm_proxy_port=args.mitm_proxy_port,
            appium_port=args.appium_port,
            no_frida_no_proxy = args.no_frida_no_proxy
        )

        # Start dynamic analysis
        tool_wrapper.start()

        # Update state to success
        log_line(args.log_output, apk_path, datetime.today().strftime('%Y-%m-%d %H:%M:%S'), 'success')

    except RuntimeError as e:
        # Change the state of pipline_run in the database
        log_line(args.log_output, apk_path, datetime.today().strftime('%Y-%m-%d %H:%M:%S'), 'error')
        # Output Error message
        print(f"ERROR: {e}")
        exit(1)

    print("#####################")
    print("# ANALYSIS FINISHED #")
    print("#####################")


if __name__ == '__main__':
    main()
