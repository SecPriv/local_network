import zipfile
import os
import shutil
import yara
import argparse
import json
import plistlib
import re

# Extracts the permission messages and Bonjour services from the Info.plist and InfoPlist.strings files of an iOS app

def get_all_ipa(folder):
    files = set()
    for f in os.listdir(folder):
        current_path = os.path.join(folder, f)
        if os.path.isfile(current_path) and f.endswith("ipa"):
            files.add(current_path)

    return files


def get_tmp_path(ipa_path):
    return os.path.join(os.path.dirname(ipa_path), os.path.basename(ipa_path).replace(".ipa", "_tmp"))


def unzip_ipa(ipa_path):
    try:
        destination = get_tmp_path(ipa_path)
        with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
            zip_ref.extractall(destination)

        return True
    except zipfile.BadZipFile:
        return False


def remove_tmp(ipa_path):
    destination = get_tmp_path(ipa_path)
    shutil.rmtree(destination)
    return


def modules_callback(data):
    print(data)
    return yara.CALLBACK_CONTINUE


def get_rules_from_matches(matches):
    result = []
    for match in matches:
        result.append(match.rule)
    return result


def get_Field(dict_object, field):
    for k, v in dict_object.items():
        if k == field:
            return v
        if type(v) == type(dict()):
            result = get_Field(v, field)
            if result != None:
                return result

    return None


def parse_plist(filepath):
    try:
        with open(filepath, 'rb') as infile:
            plist = plistlib.load(infile)
            return plist
    except:
        #print(f"Error: could not read plist")
        #print(f"File: {filepath}")
        pass

    try:
        with open(filepath, 'rb') as fp:
            localization_strings = fp.read()

        # define a regex pattern for a comment like /* this is a comment */
        pattern = rb'\/\*([\s\S]*?)\*\/'
        # replace all matches with empty string
        re.sub(pattern, '', localization_strings)
        plist_localization = {}
        items = localization_strings.splitlines()
        if len(items) <= 1:
            items= localization_strings.split(b";")

        for line in items:
            line = line.decode("utf-8")
            key_value = line.split('=')
            if len(key_value) > 1:
                key = key_value[0].replace('"', '').replace("'", '').strip()
                value = key_value[1].replace('"', '').replace("'", '').replace(';', '').strip()
                plist_localization[key] = value

        return plist_localization
    except Exception as e:
        pass


    try:
        with open(filepath, 'r') as fp:
            localization_strings = fp.read()

        pattern = r'\/\*([\s\S]*?)\*\/'
        # replace all matches with empty string
        re.sub(pattern, '', localization_strings)
        items = localization_strings.splitlines()
        if len(items) <= 1:
            items= localization_strings.split(";")


        plist_localization = {}
        for line in items:
            key_value = line.split('=')
            if len(key_value) > 1:
                key = key_value[0].replace('"', '').replace("'", '').strip()
                value = key_value[1].replace('"', '').replace("'", '').replace(';', '').strip()
                plist_localization[key] = value

        return plist_localization
    except Exception as e:
        print(f'Could not parse file {filepath}: {e}')

    return {"NSLocalNetworkUsageDescription": "ERROR: could not parse permission file"}


def get_permission_text(filepath, key_string):
    plist = parse_plist(filepath)
    if key_string not in plist:
        recursive = get_Field(plist, key_string)
        if recursive != None:
            return recursive
        print(f"Error: {key_string} not in app even it should be")
        print(f"File: {filepath}")
        return f"Error {key_string} matching {filepath}"
    else:
        return plist[key_string]


def analyze_folder(path, rule_path):
    result = {}
    for root, dirs, files in os.walk(path):
        for file in files:
            try:
                if file == "Info.plist" or file == "InfoPlist.strings":
                    file_path = os.path.join(root, file)
                    external_vars = {}
                    external_vars["filename"] = file
                    external_vars["path"] = root
                    external_vars["ext"] = ".ipa"
                    rules = yara.compile(rule_path, externals=external_vars)
                    matches = rules.match(file_path, timeout=180)
                    if len(matches) > 0:
                        matches = get_rules_from_matches(matches)
                        current_dict = {}
                        if "hasNSLocalNetworkUsageDescription" in matches:
                            network_string =  get_permission_text(file_path, "NSLocalNetworkUsageDescription")
                            current_dict["NSLocalNetworkUsageDescription"] = network_string
                        if "hasNSBonjourServices" in matches:
                            bonjour_strings = get_permission_text(file_path, "NSBonjourServices")
                            current_dict["NSBonjourServices"] = bonjour_strings
                        result[file_path] = current_dict



            except yara.Error as e:
                print(f"Error Yara {e}")
                print(f"File: {os.path.join(root, file)}")

    return result


def write_output(output_file, results):
    with open(output_file, "a") as f:
        f.write(json.dumps(results))
        f.write("\n")


def main(ipa_path, rule_path, output_file):
    if unzip_ipa(ipa_path):
        results = analyze_folder(get_tmp_path(ipa_path), rule_path)
        if results != {}:
            results["app"] = ipa_path
            write_output(output_file, results)
        remove_tmp(ipa_path)
    else:
        write_output(output_file, {"error": "unzip error", "app": ipa_path})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Yara iOS analyzer')
    parser.add_argument('--path', help='Path to ipa file', required=True)
    parser.add_argument('--output', help='Output file', required=True)

    parser.add_argument('--rule-path', help='Path to yara rules folder',
                        default="./rules/iOS_permission.yara")

    args = parser.parse_args()
    main(args.path, args.rule_path, args.output)
