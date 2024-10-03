import json
import argparse
import subprocess
import sys
import signal
import os

# iOS execution wrapper for the dynamic analysis tool


class AppData:
    def __init__(self, app_id, app_path):
        self.app_id = app_id
        self.app_path = app_path

def load_file(file_path):
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


args = parser.parse_args()


apps_to_process = load_file(args.mapping_file)

for app in apps_to_process:
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
