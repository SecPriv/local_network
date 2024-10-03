import threading
import pickle
import argparse
from ios import parse_iOS_permission_results, get_ios_dataset, analyze_ios
from android import get_android_dataset, analyze_android
from util import search_for_local_leaks
import gc
from classes import MitmResult

# Helper scritp to run the analysis of the network scans on a server, and only work with those results locally.

def get_arguments():
    # Create argument parser
    parser = argparse.ArgumentParser(description='Scan Detection')

    # Add arguments
    parser.add_argument('-f', action='store_true', help='Only run Frida scan detection')
    parser.add_argument('-a', action='store_true', help='Run Android scan detection')
    parser.add_argument('-i', action='store_true', help='Run iOS scan detection')
    parser.add_argument('--dataset', type=str, help='Dataset name')
    parser.add_argument('--ip', type=str, help='IP CIDR')

    # Parse the arguments
    return parser.parse_args()

permission = parse_iOS_permission_results(
    "../../data/plist_results/2024_01_20_all.njson"
)



def analyze_frida_run(dataset):
    mitm_result = []
    for app in dataset:
        pcap_1 = search_for_local_leaks(app.pcap_app_1.replace(".pcap", "_decrypted.pcap"))
        pcap_2 = search_for_local_leaks(app.pcap_app_2.replace(".pcap", "_decrypted.pcap"))
        mitm_result.append(MitmResult(app.app_id, pcap_1, pcap_2))       
    return mitm_result

def android_run(dataset_name: str, my_ip_cidr: str, frida_run: bool = False, only_frida: bool = False):
    dataset, dataset_failed = get_android_dataset(
        f"/results/local_network/android/dynamic/{dataset_name}/"
    )
    dataset_name = dataset_name.replace("/", "_")
    with open(f"./pickle_files/{dataset_name}.pickle", "wb") as file:
        pickle.dump(dataset, file)
    with open(f"./pickle_files/{dataset_name}_failed.pickle", "wb") as file:
        pickle.dump(dataset_failed, file)
    if not only_frida:
        dataset_result = analyze_android(dataset, my_ip_cidr)
        with open(f"./pickle_files/{dataset_name}_result.pickle", "wb") as file:
            pickle.dump(dataset_result, file)

    if frida_run:
        mitm_result = analyze_frida_run(dataset)
        with open(f"./pickle_files/{dataset_name}_mitm_result.pickle", "wb") as file:
            pickle.dump(mitm_result, file)



def ios_run(dataset_name: str, my_ip_cidr: str, frida_run: bool = False, only_frida: bool = False):
    dataset, dataset_failed = get_ios_dataset(
        f"results/local_network/iOS/dynamic/{dataset_name}/", permission
    )
    dataset_name = dataset_name.replace("/", "_")
    with open(f"./pickle_files/{dataset_name}.pickle", "wb") as file:
        pickle.dump(dataset, file)
    with open(f"./pickle_files/{dataset_name}_failed.pickle", "wb") as file:
        pickle.dump(dataset_failed, file)
    if not only_frida:
        dataset_result = analyze_ios(dataset, my_ip_cidr)
        with open(f"./pickle_files/{dataset_name}_result.pickle", "wb") as file:
            pickle.dump(dataset_result, file)
    if frida_run:
        mitm_result = analyze_frida_run(dataset)
        with open(f"./pickle_files/{dataset_name}_mitm_result.pickle", "wb") as file:
            pickle.dump(mitm_result, file)






# parallel --eta --jobs 2 --colsep ',' -a ios_input.txt python3 scan_detection.py -i --dataset {1} --ip {2}
if __name__ == "__main__":
    args = get_arguments()
    if args.a:
        if "frida_run" in args.dataset:
            android_run(args.dataset, args.ip, frida_run=True, only_frida=args.f)
        else:
            android_run(args.dataset, args.ip)

    if args.i:
        if "frida_run" in args.dataset:
            ios_run(args.dataset, args.ip, frida_run=True, only_frida=args.f)
        else:
            ios_run(args.dataset, args.ip)






