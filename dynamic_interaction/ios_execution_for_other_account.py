import json
import argparse
import subprocess
import sys
import signal
import os

# iOS execution wrapper for the dynamic analysis tool
# that can handle multiple output folders -> required if multiple phones execute the analysis in parallel
# in general, iOS apps can only be installed on a device with the account logged in which downloaded them as they are encrypted for the account.

class AppData:
    def __init__(self, app_id, app_path):
        self.app_id = app_id
        self.app_path = app_path


def id_in_output_path(output_path, bundle_id):
    for f in os.listdir(output_path):
        if f.startswith(bundle_id + "-"):
            return True

    return False



def load_file(file_path, output_folders: [str]):
    result = []

    with open(file_path, "r") as f:
        data = json.load(f)
        for item in data:
            result.append(AppData(item.get("app_id", ""), item.get("app_path", "")))

    return result



def signal_handler(sig, frame):
    print('Initializing cleanup...')
    print('Terminated due to interrupt.')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)



parser = argparse.ArgumentParser(description='Wrapper for the dynamic ios analysis tool.',
                                    epilog='Either --apps-file-path or --apps-to-analyse or both must be present.')

parser.add_argument('-f', '--mapping-file', help='path to the ipa file that should be installed and analysed',
                    required=True)

parser.add_argument('-tw', '--tool-args-wrapper', help='arguments for the dynamic analysis tool', required=True)
parser.add_argument('-ta', '--tool-args-analysis', help='arguments for the dynamic analysis tool', required=True)
parser.add_argument('-o', '--output-folder', help='output folder',
                    required=True)


def is_already_processed(output_folders: [str], app):
    for output_folder in output_folders:
        if os.path.exists(os.path.join(output_folder, app.app_id)) or id_in_output_path(output_folder, app.app_id):
            return True

    return False

args = parser.parse_args()

output_folders = args.output_folder.split(",")


apps_to_process = load_file(args.mapping_file, output_folders)

for app in apps_to_process:

    if is_already_processed(output_folders, app):
        continue

    analysis_tool_process = None
    try:
        print("running:")
        print(['timeout', '60m',  'python', '-m', 'ios_dynamic.ios_dynamic_db_wrapper', '-t', args.tool_args_analysis,  '-a', app.app_id, '--ipa-path', os.path.join('', app.app_path)] + args.tool_args_wrapper.split(' '))
        analysis_tool_process = subprocess.call(['timeout', '60m', 'python', '-m', 'ios_dynamic.ios_dynamic_db_wrapper', '-t', args.tool_args_analysis,  '-a', app.app_id, '--ipa-path', os.path.join('', app.app_path)] + args.tool_args_wrapper.split(' '))
    except Exception as e:
        print("Got Exception")
        print(e)
        print(e.with_traceback)
        if analysis_tool_process is not None:
            print("Terminating analysis wrapper...")
            analysis_tool_process.terminate()
