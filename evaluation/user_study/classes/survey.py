from classes.demography import Age, Gender, IT_Background, IOS_Version, Demography
from classes.scale import ATIScale, ScaleValue
from enum import Enum
from typing import Optional, List
import csv

# Survey parsing code
class Answer(Enum):
    yes = 1
    no = 2
    dont_know = 0

class NoResponse():
    dont_know: bool = False
    dont_want_to_answer: bool = False
    other: str = ""

    def __str__(self) -> str:
        if self.dont_know:
            return "don't know"
        elif self.dont_want_to_answer:
            return "don't want to answer"
        elif self.other:
            return self.other
        else:
            return ""
    
    def __repr__(self) -> str:
        return self.__str__()
class LocalNetworkKnowledge():
    know_local_network: bool
    local_network_meaning: Optional[str] = None
    not_answered: Optional[NoResponse] = None

    def __str__(self) -> str:
        if self.not_answered:
            return f"has not explained local network because: {self.not_answered}"
        elif self.know_local_network:
            return f"Knows local network: {self.local_network_meaning}"
        else:
            return "Does not know local network"
    
    def __repr__(self) -> str:
        return self.__str__()


class LocalNetworkCheck(Enum):
    mostly_internet = -1 
    devices_connected = 1
    others_can_connect = 2
    wikipedia = -2
    physical_close_devices = -3
    within_antenna_range = -4
    none_of_above = -5
    dont_know = 0

class HomeScenario(Enum):
    bluetooth = -1
    internet_access = -2
    smart_cast = 1
    discover_other_phones = 2
    none_of_above = 3
    dont_know = 0

class GrantedScenarios():
    read_wifi_password: Answer # Q54 - false
    user_profiling: Answer # Q56 - true
    aproximate_location: Answer # Q57 - true
    cross_user_tracking: Answer # Q58 -true
    local_data_access: Answer # Q59 -false
    detect_other_devices: Answer # Q62 -true
    sensitive_device: Answer # Q79 - true
    exposing_devices: Answer # Q60 - true
    phone_become_visible: Answer # Q61 -false

    def __str__(self) -> str:
        return f"read_wifi_password: {self.read_wifi_password}, user_profiling: {self.user_profiling}, aproximate_location: {self.aproximate_location}, cross_user_tracking: {self.cross_user_tracking}, local_data_access: {self.local_data_access}, detect_other_devices: {self.detect_other_devices}, sensitive_device: {self.sensitive_device}, exposing_devices: {self.exposing_devices}, phone_become_visible: {self.phone_become_visible}"
    
    def __repr__(self) -> str:
        return self.__str__()


class OutsideScenarios():
    connect_smart_tv: Answer # Q65 - false
    other_mobile_phones: Answer # Q66 - false
    connect_smart_tv_at_home: Answer # Q67 - false

    def __str__(self) -> str:
        return f"connect_smart_tv: {self.connect_smart_tv}, other_mobile_phones: {self.other_mobile_phones}, connect_smart_tv_at_home: {self.connect_smart_tv_at_home}"
    
    def __repr__(self) -> str:
        return self.__str__()

class CafeScenarios():
    connect_smart_tv: Answer # Q68 - true
    other_mobile_phones: Answer # Q70 - true
    record_noise: Answer # Q75 - false

    def __str__(self) -> str:
        return f"connect_smart_tv: {self.connect_smart_tv}, other_mobile_phones: {self.other_mobile_phones}, record_noise: {self.record_noise}"
    
    def __repr__(self) -> str:
        return self.__str__()

class AtWorkScenarios():
    connect_printer: Answer # Q69 - true
    other_mobile_phones: Answer # Q77 - true
    customers_phone: Answer # Q78 - false

    def __str__(self) -> str:
        return f"connect_printer: {self.connect_printer}, other_mobile_phones: {self.other_mobile_phones}, customers_phone: {self.customers_phone}"
    
    def __repr__(self) -> str:
        return self.__str__()



class Survey:
    consent: bool
    prolific_id: str # Q76
    encountered_permission: Answer #Q64
    local_network_knowledge: LocalNetworkKnowledge
    ln_knowledge_check: List[LocalNetworkCheck] # Q45
    at_home: List[HomeScenario] # Q3.3
    granted_scenarios: GrantedScenarios
    outside_scenarios: OutsideScenarios 
    cafe_scenarios: CafeScenarios 
    at_work_scenarios: AtWorkScenarios 
    ati_scale: ATIScale #Q7.2
    demographics: Demography
    attantance_check: bool #Q71
    time: int

    def __str__(self) -> str:
        if not self.consent:
            return "Did not consent to the survey"
        else:
            return f"id:{self.prolific_id}, seen permission: {self.encountered_permission}, local network knowledge: {self.local_network_knowledge}, ln_knowledge_check: {self.ln_knowledge_check}, at_home: {self.at_home}, granted_scenarios: {self.granted_scenarios}, outside_scenarios: {self.outside_scenarios}, cafe_scenarios: {self.cafe_scenarios}, at_work_scenarios: {self.at_work_scenarios}, ati_scale: {self.ati_scale}, demographics: {self.demographics}, attantance_check: {self.attantance_check}"
        


class EvaluatedSurvey():
    survey: Survey
    sanety_check_passed: bool = True
    ati_scale_value: float
    has_it_background: bool
    know_what_ln_is: bool
    ln_count_score: int # Max 6
    at_home_score: int # Max 4
    outside_score: int # Max 3
    cafe_score: int # Max 3
    work_score: int # Max 3
    user_profiling_score: int # Max 6
    cross_user_tracking_score: int # Max 4
    devices_owned_score: int # Max 3
    sensitive_devices_score: int # Max 2
    devices_exposed_score: int # Max 4
    proximity_score: int # Max 7
    network_boundaries_score: int # Max 6

    def __str__(self) -> str:
        return f"Survey: {self.survey}, sanety_check_passed: {self.sanety_check_passed}"
    
    def __repr__(self) -> str:
        return self.__str__()

# parse functions


def parse_answer(answer: str) -> Answer:
    if answer == "1":
        return Answer.yes
    elif answer == "2":
        return Answer.no
    elif answer == "4":
        return Answer.dont_know
    

    
def parse_local_network_knowledge(row: List) -> LocalNetworkKnowledge:
    local_network_knowledge: LocalNetworkKnowledge = LocalNetworkKnowledge()
    if row[20] == "1":
        local_network_knowledge.know_local_network = True
        local_network_knowledge.local_network_meaning = row[21]
        no_response: NoResponse = NoResponse()
        if len(local_network_knowledge.local_network_meaning) == 0:
            if row[22] == "1":
                no_response.dont_know = True
            elif row[22] == "2":
                no_response.dont_want_to_answer = True
            else:
                no_response.other= row[23]
        local_network_knowledge.not_answered = no_response
    else:
        local_network_knowledge.know_local_network = False
    
    return local_network_knowledge
    


def parse_local_network_knowledge_check(data: str) -> List[LocalNetworkCheck]:
    # data should be a list of answers separated by commas if multiple
    result: List[LocalNetworkCheck] = []
    if len(data) == 0:
        print("Error: ln knowledge check is empty")
        return result
    
    for answer in data.split(","):
        answer = answer.strip()
        if len(answer) == 0:
            continue

        if answer == "1":
            result.append(LocalNetworkCheck.mostly_internet)
        elif answer == "2":
            result.append(LocalNetworkCheck.devices_connected)
        elif answer == "3":
            result.append(LocalNetworkCheck.others_can_connect)
        elif answer == "4":
            result.append(LocalNetworkCheck.wikipedia)
        elif answer == "5":
            result.append(LocalNetworkCheck.physical_close_devices)
        elif answer == "6":
            result.append(LocalNetworkCheck.within_antenna_range)
        elif answer == "0":
            result.append(LocalNetworkCheck.none_of_above)
        elif answer == "7":
            result.append(LocalNetworkCheck.dont_know)
        else:
            print(f"Error: unknown answer in ln knowledge check: {answer}")

    return result

def parse_at_home_scenario(data: str) -> List[HomeScenario]:
    # data should be a list of answers separated by commas if multiple
    result: List[HomeScenario] = []
    if len(data) == 0:
        print("Error: ln knowledge check is empty")
        return result
    
    for answer in data.split(","):
        answer = answer.strip()
        if len(answer) == 0:
            continue

        if answer == "1":
            result.append(HomeScenario.bluetooth)
        elif answer == "3":
            result.append(HomeScenario.internet_access)
        elif answer == "4":
            result.append(HomeScenario.smart_cast)
        elif answer == "5":
            result.append(HomeScenario.discover_other_phones)
        elif answer == "0":
            result.append(HomeScenario.none_of_above)
        elif answer == "6":
            result.append(HomeScenario.dont_know)
        else:
            print("Error: unknown answer in home scenarios")

    return result


def parse_granted_scenarios(row: List) -> GrantedScenarios:
    granted_scenarios: GrantedScenarios = GrantedScenarios()
    granted_scenarios.read_wifi_password = parse_answer(row[26])
    granted_scenarios.user_profiling = parse_answer(row[27])
    granted_scenarios.aproximate_location = parse_answer(row[28])
    granted_scenarios.cross_user_tracking = parse_answer(row[29])
    granted_scenarios.local_data_access = parse_answer(row[30])
    granted_scenarios.detect_other_devices = parse_answer(row[31])
    granted_scenarios.sensitive_device = parse_answer(row[32])
    granted_scenarios.exposing_devices = parse_answer(row[33])
    granted_scenarios.phone_become_visible = parse_answer(row[34])
    return granted_scenarios


def parse_outside_scenarios(row: List) -> OutsideScenarios:
    outside_scenarios: OutsideScenarios = OutsideScenarios()
    outside_scenarios.connect_smart_tv = parse_answer(row[35])
    outside_scenarios.other_mobile_phones = parse_answer(row[36])
    outside_scenarios.connect_smart_tv_at_home = parse_answer(row[37])
    return outside_scenarios

def parse_cafe_scenarios(row: List) -> CafeScenarios:
    cafe_scenarios: CafeScenarios = CafeScenarios()
    cafe_scenarios.connect_smart_tv = parse_answer(row[38])
    cafe_scenarios.other_mobile_phones = parse_answer(row[40])
    cafe_scenarios.record_noise = parse_answer(row[42])
    return cafe_scenarios

def parse_work_scenarios(row: List) -> AtWorkScenarios:
    work_scenarios: AtWorkScenarios = AtWorkScenarios()
    work_scenarios.connect_printer = parse_answer(row[39])
    work_scenarios.other_mobile_phones = parse_answer(row[41])
    work_scenarios.customers_phone = parse_answer(row[43])
    return work_scenarios

def parse_scale_value(value: str) -> ScaleValue:
    if value == "1":
        return ScaleValue.completely_disagree
    elif value == "2":
        return ScaleValue.largely_diagree
    elif value == "3":
        return ScaleValue.slightly_disagree
    elif value == "4":
        return ScaleValue.slightly_agree
    elif value == "5":
        return ScaleValue.largely_agree
    elif value == "6":
        return ScaleValue.completely_agree

def parse_ati_scale(row: List) -> ATIScale:
    ati_scale: ATIScale = ATIScale()
    ati_scale.occupy_in_technical_details = parse_scale_value(row[44])
    ati_scale.testing_new_technical_function = parse_scale_value(row[45])
    ati_scale.deal_with_technical_details = parse_scale_value(row[46])
    ati_scale.try_out_new_technical_function = parse_scale_value(row[47])
    ati_scale.enjoy_spending_time_on_technical_systems = parse_scale_value(row[48])
    ati_scale.enough_that_it_work = parse_scale_value(row[49])
    ati_scale.understand_technical_system = parse_scale_value(row[50])
    ati_scale.enough_to_know_basic = parse_scale_value(row[51])
    ati_scale.full_use_of_functionalities = parse_scale_value(row[52])
    return ati_scale

def parse_age(age: str) -> Age:
    if age == "1":
        return Age.under_18
    elif age == "2":
        return Age.between_18_24
    elif age == "3":
        return Age.between_25_34
    elif age == "4":
        return Age.between_35_44
    elif age == "5":
        return Age.between_45_54
    elif age == "6":
        return Age.between_55_64
    elif age == "7":
        return Age.over_65
        
def parse_gender(gender: str, description: str) -> Gender:
    result: Gender = Gender()
    if gender == "1":
        result.male = True
    elif gender == "2":
        result.female = True
    elif gender == "3":
        result.non_binary = True
    elif gender == "4":
        result.own_description = description
    elif gender == "5":
        result.not_to_say = True
    
    return result

def parse_it_background(it_background: str) -> List[IT_Background]:
    result: List[IT_Background] = []
    for answer in it_background.split(","):
        answer = answer.strip()
        if len(answer) == 0:
            print("Error: empty answer in it background")
        
        if answer == "1":
            result.append(IT_Background.work_related)
        elif answer == "2":
            result.append(IT_Background.education_related)
        elif answer == "3":
            result.append(IT_Background.selft_taught)
        elif answer == "4":
            result.append(IT_Background.no_background)
    return result

def parse_ios_version(version: str) -> IOS_Version:
    if version == "1":
        return IOS_Version.ios_17
    elif version == "2":
        return IOS_Version.ios_16
    elif version == "3":
        return IOS_Version.ios_15
    elif version == "4":
        return IOS_Version.ios_14
    elif version == "5":
        return IOS_Version.ios_13
    elif version == "6":
        return IOS_Version.ios_12_or_lower
    elif version == "":
        return IOS_Version.dont_know
    else:
        print(f"Error: unknown ios version {version}")
    


def parse_demographics(row: List) -> Demography:
    demographics: Demography = Demography()
    demographics.age = parse_age(row[53])
    demographics.gender = parse_gender(row[54], row[55])
    demographics.country = row[56]
    demographics.it_background = parse_it_background(row[57])
    demographics.ios_version = parse_ios_version(row[58])
    return demographics

def parse_row(row: List) -> Survey:
    survey: Survey = Survey()
    survey.prolific_id = row[18]
    if row[17] == "1":
        survey.consent = True
    else:
        print("did not consent")
        survey.consent = False
    
    survey.time = int(row[5])
    survey.encountered_permission = parse_answer(row[19])
    survey.local_network_knowledge = parse_local_network_knowledge(row)
    survey.ln_knowledge_check = parse_local_network_knowledge_check(row[24])
    survey.at_home = parse_at_home_scenario(row[25])
    survey.granted_scenarios = parse_granted_scenarios(row)
    survey.outside_scenarios = parse_outside_scenarios(row)
    survey.cafe_scenarios = parse_cafe_scenarios(row)
    survey.at_work_scenarios = parse_work_scenarios(row)
    survey.ati_scale = parse_ati_scale(row)
    survey.demographics = parse_demographics(row)


    if row[59] == "1":
        survey.attantance_check = True
    else:
        print("attantance check failed")
        survey.attantance_check = False

    return survey





def parse_survey(file_path: str) -> List[Survey]:
    # Read the survey file
    result: List[Survey] = []
    with open(file_path) as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row[0].startswith("2024"): # skip non data rows
                continue
            

            if len(row[18]) < 1:
                print("prolific id is empty")
                continue
            if len(row) < 61:
                print("row is not complete")
                continue
            # FIXME: add check if completed and in prolific ids
            # Parse the row
            result.append(parse_row(row))
    return result