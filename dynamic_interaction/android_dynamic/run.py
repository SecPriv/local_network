import json
import argparse
import subprocess
import sys
import signal
import os


class AppData:
    def __init__(self, app_id, app_path):
        self.app_id = app_id
        self.app_path = app_path

def load_apks(folder_path):
    result = []
    for f in os.listdir(folder_path):
        if ".split." in f:
            continue
        #print(f)
        #print(f[0: len(f)-4])

        result.append(os.path.join(folder_path, f))

    return result

def already_analyzed(output_folders, apk_path):
    apk = os.path.basename(apk_path)
    print(output_folders)
    print(apk[0: len(apk)-4])
    for output_folder in output_folders:
        if apk[0: len(apk)-4] in os.listdir(output_folder):
            print(output_folder)
            return True
    return False


def signal_handler(sig, frame):
    print('Initializing cleanup...')
    print('Terminated due to interrupt.')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)



parser = argparse.ArgumentParser(description='Wrapper for the dynamic ios analysis tool.',
                                    epilog='Either --apps-file-path or --apps-to-analyse or both must be present.')

parser.add_argument('-p', '--apk-path', help='path to the apk folder that should be analysed',
                    required=True)
parser.add_argument('-o', '--output-path', help='output path',
                    required=True)

parser.add_argument('-ta', '--tool-args-analysis', help='arguments for the dynamic analysis tool', required=True)


args = parser.parse_args()


apps_to_process = load_apks(args.apk_path)

output_paths = args.output_path.split(",")

for app in apps_to_process:
    analysis_tool_process = None
    if already_analyzed(output_paths, app):
        print(app)
        continue
    try:
        print("running:")
        command = ['timeout', '60m', 'python', 'pipeline.py', '-f', app ] + args.tool_args_analysis.split(' ')
        print(command)
        analysis_tool_process = subprocess.call(command)
        #exit()
    except Exception as e:
        print("Got Exception")
        print(e)
        print(e.with_traceback)
        if analysis_tool_process is not None:
            print("Terminating analysis wrapper...")
            analysis_tool_process.terminate()
        #exit()
