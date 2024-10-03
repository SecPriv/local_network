from classes.survey import Survey, EvaluatedSurvey, AtWorkScenarios, CafeScenarios, OutsideScenarios, GrantedScenarios, HomeScenario, LocalNetworkCheck, LocalNetworkKnowledge, NoResponse, Answer, parse_survey
from classes.demography import Age, Gender, IT_Background, IOS_Version, Demography
from classes.scale import ATIScale, ScaleValue
from typing import List, Tuple, Dict
import statistics
import pandas as pd
from collections import Counter

# Evaluaton helper code

def evaluate_answer(answer: Answer, expected: Answer) -> bool:
    if answer == expected:
        return True
    return False

def evaluate_outside_scenarios(outside_scenario: OutsideScenarios) -> int:
    count = 0
    if evaluate_answer(outside_scenario.connect_smart_tv, Answer.no):
        count += 1
    if evaluate_answer(outside_scenario.other_mobile_phones, Answer.no):
        count += 1
    if evaluate_answer(outside_scenario.connect_smart_tv_at_home, Answer.no):
        count += 1
    
    return count # Max 3

def evaluate_cafe_scenarios(cafe_scenario: CafeScenarios) -> int:
    count = 0
    if evaluate_answer(cafe_scenario.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(cafe_scenario.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(cafe_scenario.record_noise, Answer.no):
        count += 1
    return count # Max 3

def evaluate_at_work_scenarios(at_work_scenario: AtWorkScenarios) -> int:
    count = 0
    if evaluate_answer(at_work_scenario.connect_printer, Answer.yes):
        count += 1
    if evaluate_answer(at_work_scenario.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(at_work_scenario.customers_phone, Answer.no):
        count += 1
    return count # Max 3

def evaluate_user_profiling(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.outside_scenarios.connect_smart_tv, Answer.no):
        count += 1
    if evaluate_answer(survey.outside_scenarios.connect_smart_tv_at_home, Answer.no):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.connect_printer, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    return count # Max 6
    

def evaluate_cross_user_tracking(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.outside_scenarios.other_mobile_phones, Answer.no):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.customers_phone, Answer.no):
        count += 1
    return count # Max 4


def evaluate_devices_owned(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.outside_scenarios.connect_smart_tv, Answer.no):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.connect_printer, Answer.yes):
        count += 1
    return count # Max 3

def evaluate_sensitive_devices(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.cafe_scenarios.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.connect_printer, Answer.yes):
        count += 1
    return count # Max 2

def evaluate_devices_exposed(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.cafe_scenarios.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.connect_printer, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    return count # Max 4


def evaluate_proximity(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.outside_scenarios.connect_smart_tv, Answer.no):
        count += 1
    if evaluate_answer(survey.outside_scenarios.other_mobile_phones, Answer.no):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.connect_printer, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.customers_phone , Answer.no):
        count += 1
    return count # Max 7

def evaluate_network_boundary(survey: Survey) -> int:
    count = 0
    if evaluate_answer(survey.outside_scenarios.connect_smart_tv_at_home, Answer.no):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.connect_smart_tv, Answer.yes):
        count += 1
    if evaluate_answer(survey.cafe_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.connect_printer, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.other_mobile_phones, Answer.yes):
        count += 1
    if evaluate_answer(survey.at_work_scenarios.customers_phone , Answer.no):
        count += 1

    return count # Max 6



def evaluate_ATI_scale(atiScale: ATIScale) -> (float, bool):
    values: List[int] = []
    sanety_check_passed = True
    # mean
    values.append(atiScale.occupy_in_technical_details.value)
    values.append(atiScale.testing_new_technical_function.value)
    values.append(atiScale.deal_with_technical_details.value) # 7 -
    values.append(atiScale.try_out_new_technical_function.value)
    values.append(atiScale.enjoy_spending_time_on_technical_systems.value)
    values.append(atiScale.enough_that_it_work.value) # 7 - 
    values.append(atiScale.understand_technical_system.value)
    values.append(atiScale.enough_to_know_basic.value) # 7 - 
    values.append(atiScale.full_use_of_functionalities.value)
    #  check - all 1 or 6
    tmp_mean = statistics.mean(values)
    if tmp_mean == 1 or tmp_mean == 6:
        sanety_check_passed = False 

    # invert 3, 6,8 
    values[2] = 7 - values[2]
    values[5] = 7 - values[5]
    values[7] = 7 - values[7]
    return statistics.mean(values), sanety_check_passed


def evaluate_background(it_background: IT_Background) -> (bool, bool):
    if IT_Background.no_background in it_background:
        return False, True
    elif len(it_background)> 0:
        return True, True
    else:
        print("IT Background is empty?")
        print(it_background)
        return False, False


def evaluate_ln_knowledge_check(ln_knowledge: List[LocalNetworkKnowledge]) -> (int, bool):
    count = 0
    sanety_check_passed = True
    if LocalNetworkCheck.dont_know in ln_knowledge:
        return -1, sanety_check_passed
    
    if LocalNetworkCheck.none_of_above in ln_knowledge and len(ln_knowledge) > 1:
        print("None of the above and other knowledge")
        sanety_check_passed =  False

    if LocalNetworkCheck.mostly_internet not in ln_knowledge:
        count += 1
    if LocalNetworkCheck.devices_connected in ln_knowledge:
        count += 1
    if LocalNetworkCheck.others_can_connect in ln_knowledge:
        count += 1
    if LocalNetworkCheck.wikipedia not in ln_knowledge:
        count += 1
    if LocalNetworkCheck.physical_close_devices not in ln_knowledge:
        count += 1
    if LocalNetworkCheck.within_antenna_range not in ln_knowledge:
        count += 1

    
    return count, sanety_check_passed

def evaluate_at_home(home_scenario_answers: List[HomeScenario]) -> (int, bool):
    count = 0
    sanety_check_passed = True
    if HomeScenario.dont_know in home_scenario_answers:
        return -1, sanety_check_passed
    if HomeScenario.none_of_above in home_scenario_answers and len(home_scenario_answers) > 1 :
        print("None of above and other answers")
        sanety_check_passed = False

    if HomeScenario.bluetooth not in home_scenario_answers:
        count += 1
    if HomeScenario.internet_access not in home_scenario_answers:
        count += 1
    if HomeScenario.smart_cast in home_scenario_answers:
        count += 1
    if HomeScenario.discover_other_phones in home_scenario_answers:
        count += 1
    
    return count, sanety_check_passed


def evaluate_ln_knowledge(local_network_knowledge: LocalNetworkKnowledge) -> bool:
    if not local_network_knowledge.know_local_network:
        return False
    
    if local_network_knowledge.know_local_network and local_network_knowledge.not_answered.dont_know:
        return False
    
    return True # needs manual check


def evaluate_survey(survey: Survey) -> EvaluatedSurvey:
    result: EvaluatedSurvey = EvaluatedSurvey()
    result.survey = survey
    # Sanety check - last question
    result.sanety_check_passed = survey.attantance_check
    # ATI scale
    ati_values, sanety_check_passed = evaluate_ATI_scale(survey.ati_scale)
    result.ati_scale_value = ati_values
    if not sanety_check_passed:
        print("ATI check failed")
        result.sanety_check_passed = sanety_check_passed # all 1 or 6

    it_background, sanety_check_passed = evaluate_background(survey.demographics.it_background)
    result.has_it_background = it_background
    if not sanety_check_passed:
        print("IT Background check failed")
        result.sanety_check_passed = sanety_check_passed # no IT background and other IT background

    ln_knowledge_score, sanety_check_passed = evaluate_ln_knowledge_check(survey.ln_knowledge_check)
    if not sanety_check_passed:
        print("ln knowledge check failed")
        result.sanety_check_passed = sanety_check_passed # none of the above or don't know + other answer
    result.ln_count_score = ln_knowledge_score

    at_home_score, sanety_check_passed = evaluate_at_home(survey.at_home)
    if not sanety_check_passed:
        print("At home check failed")
        result.sanety_check_passed = sanety_check_passed # none of the above or don't know + other answer
    
    result.at_home_score = at_home_score

    result.know_what_ln_is = evaluate_ln_knowledge(survey.local_network_knowledge)
    result.outside_score = evaluate_outside_scenarios(survey.outside_scenarios)
    result.cafe_score = evaluate_cafe_scenarios(survey.cafe_scenarios)
    result.work_score = evaluate_at_work_scenarios(survey.at_work_scenarios)

    result.user_profiling_score = evaluate_user_profiling(survey)
    result.cross_user_tracking_score = evaluate_cross_user_tracking(survey)
    result.devices_owned_score = evaluate_devices_owned(survey)
    result.sensitive_devices_score = evaluate_sensitive_devices(survey)
    result.devices_exposed_score = evaluate_devices_exposed(survey)
    result.proximity_score = evaluate_proximity(survey)
    result.network_boundaries_score = evaluate_network_boundary(survey)


    return result

def evaluate_surveys(surveys: List[Survey]) -> List[EvaluatedSurvey]:
    result: List[EvaluatedSurvey] = []
    for survey in surveys:
        result.append(evaluate_survey(survey))
    return result










def evaluate_questions(evaluated_suverys: List[EvaluatedSurvey], path: str):
    questions = {}
    total = 0
    for survey in evaluated_suverys:
        if not survey.sanety_check_passed:
            continue
        total += 1
        if LocalNetworkCheck.mostly_internet in survey.survey.ln_knowledge_check:
            questions["1_mostly_internet"] = questions.get("1_mostly_internet", 0) + 1
        if LocalNetworkCheck.devices_connected not in survey.survey.ln_knowledge_check:
            questions["1_devices_connected"] = questions.get("1_devices_connected", 0) + 1
        if LocalNetworkCheck.others_can_connect not in survey.survey.ln_knowledge_check:
            questions["1_others_can_connect"] = questions.get("1_others_can_connect", 0) + 1
        if LocalNetworkCheck.wikipedia in survey.survey.ln_knowledge_check:
            questions["1_wikipedia"] = questions.get("1_wikipedia", 0) + 1
        if LocalNetworkCheck.physical_close_devices in survey.survey.ln_knowledge_check:
            questions["1_physical_close_devices"] = questions.get("1_physical_close_devices", 0) + 1
        if LocalNetworkCheck.within_antenna_range in survey.survey.ln_knowledge_check:
            questions["1_within_antenna_range"] = questions.get("1_within_antenna_range", 0) + 1
        if LocalNetworkCheck.dont_know in survey.survey.ln_knowledge_check:
            questions["1_dont_know"] = questions.get("1_dont_know", 0) + 1
        if LocalNetworkCheck.none_of_above in survey.survey.ln_knowledge_check:
            questions["1_none_of_above"] = questions.get("1_none_of_above", 0) + 1


        if HomeScenario.bluetooth in survey.survey.at_home:
            questions["2_bluetooth"] = questions.get("2_bluetooth", 0) + 1
        if HomeScenario.internet_access in survey.survey.at_home:
            questions["2_internet_access"] = questions.get("2_internet_access", 0) + 1
        if HomeScenario.smart_cast not in survey.survey.at_home:
            questions["2_cast"] = questions.get("2_cast", 0) + 1
        if HomeScenario.discover_other_phones not in survey.survey.at_home:
            questions["2_other_phones"] = questions.get("2_other_phones", 0) + 1
        if HomeScenario.none_of_above  in survey.survey.at_home:
            questions["2_none_of_above"] = questions.get("2_none_of_above", 0) + 1
        if HomeScenario.dont_know in survey.survey.at_home:
            questions["2_dont_know"] = questions.get("2_dont_know", 0) + 1

        # granted scenario 
        if not evaluate_answer(survey.survey.granted_scenarios.read_wifi_password, Answer.no):
            questions["3_read_wifi_password"] = questions.get("3_read_wifi_password", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.yes):
            questions["3_user_profiling"] = questions.get("3_user_profiling", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.yes):
            questions["3_aproximate_location"] = questions.get("3_aproximate_location", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.cross_user_tracking, Answer.yes):
            questions["3_cross_user_tracking"] = questions.get("3_cross_user_tracking", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.local_data_access, Answer.no):
            questions["3_local_data_access"] = questions.get("3_local_data_access", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.yes):
            questions["3_detect_other_devices"] = questions.get("3_detect_other_devices", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.yes):
            questions["3_sensitive_device"] = questions.get("3_sensitive_device", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.exposing_devices, Answer.yes):
            questions["3_exposing_devices"] = questions.get("3_exposing_devices", 0) + 1
        if not evaluate_answer(survey.survey.granted_scenarios.phone_become_visible, Answer.no):
            questions["3_phone_become_visible"] = questions.get("3_phone_become_visible", 0) + 1

        # outside scenario
        if not evaluate_answer(survey.survey.outside_scenarios.connect_smart_tv, Answer.no):
            questions["4_connect_smart_tv"] = questions.get("4_connect_smart_tv", 0) + 1
        if not evaluate_answer(survey.survey.outside_scenarios.other_mobile_phones, Answer.no):
            questions["4_other_mobile_phones"] = questions.get("4_other_mobile_phones", 0) + 1
        if not evaluate_answer(survey.survey.outside_scenarios.connect_smart_tv_at_home, Answer.no):
            questions["4_connect_smart_tv_at_home"] = questions.get("4_connect_smart_tv_at_home", 0) + 1

        # cafe scenario
        if not evaluate_answer(survey.survey.cafe_scenarios.connect_smart_tv, Answer.yes):
            questions["5_connect_smart_tv"] = questions.get("5_connect_smart_tv", 0) + 1
        if not evaluate_answer(survey.survey.cafe_scenarios.other_mobile_phones, Answer.yes):
            questions["5_other_mobile_phones"] = questions.get("5_other_mobile_phones", 0) + 1
        if not evaluate_answer(survey.survey.cafe_scenarios.record_noise, Answer.no):
            questions["5_record_noise"] = questions.get("5_record_noise", 0) + 1

        # at work scenario
        if not evaluate_answer(survey.survey.at_work_scenarios.connect_printer, Answer.yes):
            questions["6_connect_printer"] = questions.get("6_connect_printer", 0) + 1
        if not evaluate_answer(survey.survey.at_work_scenarios.other_mobile_phones, Answer.yes):
            questions["6_other_mobile_phones"] = questions.get("6_other_mobile_phones", 0) + 1
        if not evaluate_answer(survey.survey.at_work_scenarios.customers_phone, Answer.no):
            questions["6_customers_phone"] = questions.get("6_customers_phone", 0) + 1

    df = pd.DataFrame(questions, index=[0]) #.to_csv(path, index=False)
    df.iloc[0] = df.iloc[0] / total
    df = df.transpose()
    df.to_csv(path, sep=";")
        




def get_ati_total_score(evaluated_surveys: List[EvaluatedSurvey]) -> (float, float):
    result: List[float] = []
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            result.append(survey.ati_scale_value)
    return statistics.mean(result), statistics.stdev(result)


def get_demographic_results(evaluated_surveys: List[EvaluatedSurvey], number_of_results = 1) -> (List[tuple[Age, int ]], List[tuple[Gender, int]], List[tuple[str, int]], List[tuple[IOS_Version, int]], List[tuple[bool, int]]):
    age_results: List[Age] = []
    gender_results: List[Gender] = []
    country_results: List[str] = []
    ios_version_results: List[IOS_Version] = []
    it_background_results: List[bool] = []

    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            age_results.append(survey.survey.demographics.age)
            country_results.append(survey.survey.demographics.country)
            ios_version_results.append(survey.survey.demographics.ios_version)
            if survey.survey.demographics.ios_version == IOS_Version.dont_know or survey.survey.demographics.ios_version == IOS_Version.ios_12_or_lower or survey.survey.demographics.ios_version == IOS_Version.ios_13:
                print(survey.survey.prolific_id, survey.survey.demographics.ios_version)
            gender = survey.survey.demographics.gender
            if gender.male:
                gender_results.append("Male")
            elif gender.female:
                gender_results.append("Female")
            elif gender.non_binary:
                gender_results.append("Non-binary")
            elif gender.not_to_say:
                gender_results.append("Not to say")
            else:
                gender_results.append(gender.own_description)
            
            it_background_results.append(survey.has_it_background)


    return Counter(age_results).most_common(number_of_results), Counter(gender_results).most_common(number_of_results), Counter(country_results).most_common(number_of_results), Counter(ios_version_results).most_common(number_of_results), Counter(it_background_results).most_common(number_of_results)

def get_percentage_demographic(evaluated_surveys: List[EvaluatedSurvey], number_of_results = 1):
    result = get_demographic_results(evaluated_surveys, number_of_results)
    counter = 0
    for i in evaluated_surveys:
        if i.sanety_check_passed:
            counter += 1
    
    for i in range(len(result)):
        for j in range(len(result[i])):
            result[i][j] = (result[i][j][0], f"{result[i][j][1]} ({result[i][j][1]/counter*100:.2f}%" )
    return result


def get_ln_check_results(evaluated_surveys: List[EvaluatedSurvey]) -> (float, float):
    result: List[float] = []
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            result.append(survey.ln_count_score)
    return statistics.mean(result), statistics.stdev(result)


def get_home_scenario_results(evaluated_surveys: List[EvaluatedSurvey]) -> (float, float):
    result: List[float] = []
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            result.append(survey.at_home_score)
    return statistics.mean(result), statistics.stdev(result)



def evaluate_manual_to_csv(evaluated_suverys: List[EvaluatedSurvey], file_path) -> None:
    data = []
    header = ["id", "ln_explaination", "ln_not_answered_other", "ln_score", "home_score"]
    for survey in evaluated_suverys:
        if survey.sanety_check_passed and survey.know_what_ln_is:
            row = []
            row.append(survey.survey.prolific_id)
            row.append(survey.survey.local_network_knowledge.local_network_meaning)
            row.append(survey.survey.local_network_knowledge.not_answered.other)
            row.append(survey.ln_count_score)
            row.append(survey.at_home_score)
            data.append(row)

    pd.DataFrame(data, columns=header).to_csv(file_path, index=False)


# into hours, minutes and seconds
def convert_seconds(seconds):
    seconds = seconds % (24 * 3600)
    hour = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60
     
    return "%d:%02d:%02d" % (hour, minutes, seconds)


def get_survey_time(evaluated_surveys: List[EvaluatedSurvey]) -> (str, str, str):
    result = []
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            result.append(survey.survey.time)
    return convert_seconds(statistics.mean(result)), convert_seconds(statistics.median(result)), convert_seconds(statistics.stdev(result))














#########################################
## Use Cases                            #
#########################################
# 
# Evaluate use cases from Q3.3
# 

def evaluate_use_cases(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    questions = {}
    for survey in evaluated_surveys:
        if not survey.sanety_check_passed:
            continue
        if HomeScenario.bluetooth not in survey.survey.at_home:
            questions["bluetooth_true"] = questions.get("bluetooth_true",  0) + 1
        elif HomeScenario.bluetooth in survey.survey.at_home:
            questions["bluetooth_false"] = questions.get("bluetooth_false", 0) + 1
        if HomeScenario.internet_access not in survey.survey.at_home:
            questions["internet_access_true"] = questions.get("internet_access_true", 0) + 1
        elif HomeScenario.internet_access in survey.survey.at_home:
            questions["internet_access_false"] = questions.get("internet_access_false", 0) + 1
        if HomeScenario.smart_cast in survey.survey.at_home:
            questions["smart_cast_true"] = questions.get("smart_cast_true", 0) + 1
        elif HomeScenario.smart_cast not in survey.survey.at_home:
            questions["smart_cast_false"] = questions.get("smart_cast_false",  0) + 1
        if HomeScenario.discover_other_phones in survey.survey.at_home:
            questions["discover_other_phones_true"] = questions.get("discover_other_phones_true", 0) + 1
        elif HomeScenario.discover_other_phones not in survey.survey.at_home:
            questions["discover_other_phones_false"] = questions.get("discover_other_phones_false",  0) + 1
        if HomeScenario.none_of_above not in survey.survey.at_home:
            questions["none_of_above_true"] = questions.get("none_of_above_true", 0) + 1
        elif HomeScenario.none_of_above in survey.survey.at_home:
            questions["none_of_above_false"] = questions.get("none_of_above_false", 0) + 1
        if HomeScenario.dont_know in survey.survey.at_home:
            questions["dont_know"] = questions.get("dont_know", 0) + 1
    return questions




def count_answers(answers: List[Answer], answer: Answer) -> Dict[str, int]:
    result = {
        "count_true": 0,
        "count_false": 0,
        "count_dont_know": 0
    }
    wrong_answer = Answer.no if answer == Answer.yes else Answer.yes

    for a in answers:
        if evaluate_answer(a, answer):
            result["count_true"] = result.get("count_true", 0) + 1
        elif evaluate_answer(a, wrong_answer):
            result["count_false"] = result.get("count_false", 0) + 1
        elif evaluate_answer(a, Answer.dont_know):
            result["count_dont_know"] = result.get("count_dont_know", 0) + 1
        else:
            print("error neither true nor false nor don't know")
    return result

def count_permission_seen(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    answers = [survey.survey.encountered_permission for survey in evaluated_surveys if survey.sanety_check_passed]
    return count_answers(answers, Answer.yes)


def count_ln_knowledge(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    result = {
        "true": 0,
        "false": 0,
    }
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            if survey.know_what_ln_is:
                result["true"] = result.get("true", 0) + 1
            else:
                result["false"] = result.get("false", 0) + 1
    return result

#########################################
## Attacker Models                      #
#########################################
# 1) Threat of exposing offline devices (Q60)
#
def evaluate_exposing_devices(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:

    answers = [survey.survey.granted_scenarios.exposing_devices for survey in evaluated_surveys if survey.sanety_check_passed]

    return count_answers(answers, Answer.yes)


# 2) People co-locating (Q58)
#
#
def evaluate_co_locating(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:

    answers = [survey.survey.granted_scenarios.cross_user_tracking for survey in evaluated_surveys if survey.sanety_check_passed]

    return count_answers(answers, Answer.yes)



# 3) Location Profiling (Q56, Q57)
def evaluate_location_profiling(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    result = {
        "count_true": 0,
        "count_profiling": 0,
        "count_location": 0,
        "count_false": 0,
        "count_dont_know": 0
    }
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            if evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.yes) and evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.yes):
                result["count_true"] += 1
            elif evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.no) or evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.no):
                result["count_false"] += 1
            elif evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.yes) and not evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.yes):
                result["count_location"] += 1
            elif not evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.yes) and evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.yes):
                result["count_profiling"] += 1
            elif evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.dont_know) or evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.dont_know):
                result["count_dont_know"] += 1
            else:
                print("error neither true nor false nor don't know")
    return result

def evaluate_location_profiling_only_location(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    answers = [survey.survey.granted_scenarios.aproximate_location for survey in evaluated_surveys if survey.sanety_check_passed and evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.dont_know)]
    return count_answers(answers, Answer.yes)

def evaluate_location_profiling_only_profiling(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    answers = [survey.survey.granted_scenarios.user_profiling for survey in evaluated_surveys if survey.sanety_check_passed and evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.dont_know)]
    return count_answers(answers, Answer.yes)

# 4) Devise Profiling (Q62, Q79)
#
def evaluate_device_profiling(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    result = {
        "count_true": 0,
        "count_sensitive": 0,
        "count_device": 0,
        "count_false": 0,
        "count_dont_know": 0
    }
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            if evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.yes) and evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.yes):
                result["count_true"] += 1
            elif evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.no) or evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.no):
                result["count_false"] += 1
            elif evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.yes) and not evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.yes):
                result["count_sensitive"] += 1
            elif not evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.yes) and evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.yes):
                result["count_device"] += 1
            elif evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.dont_know) or evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.dont_know):
                result["count_dont_know"] += 1
            else:
                print("error neither true nor false nor don't know")
                print(survey.survey.granted_scenarios.sensitive_device)
                print(survey.survey.granted_scenarios.exposing_devices)
    return result

def evaluate_at_least_on_threat(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    result = {"true": 0, "false": 0, "dont_know": 0}
    for survey in evaluated_surveys:
        if survey.sanety_check_passed:
            if (evaluate_answer(survey.survey.granted_scenarios.exposing_devices, Answer.yes) or 
                evaluate_answer(survey.survey.granted_scenarios.cross_user_tracking, Answer.yes) or 
                (evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.yes) and evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.yes)) or 
                (evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.yes) and evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.yes))):
                result["true"] += 1
            elif (evaluate_answer(survey.survey.granted_scenarios.exposing_devices, Answer.dont_know) and 
                evaluate_answer(survey.survey.granted_scenarios.cross_user_tracking, Answer.dont_know) and 
                (evaluate_answer(survey.survey.granted_scenarios.aproximate_location, Answer.dont_know) and evaluate_answer(survey.survey.granted_scenarios.user_profiling, Answer.dont_know)) and 
                (evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.dont_know) and evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.dont_know))):
                result["dont_know"] += 1
            else:
                result["false"] += 1
    return result


def evaluate_device_profiling_stat_test(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    result = evaluate_device_profiling(evaluated_surveys)
    result["count_dont_know"] = result["count_dont_know"] + result["count_sensitive"]
    result["count_dont_know"] = result["count_dont_know"] + result["count_device"]
    del result["count_device"]
    del result["count_sensitive"]


    return result



def evaluate_device_profiling_only_sensitive(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    answers = [survey.survey.granted_scenarios.sensitive_device for survey in evaluated_surveys if survey.sanety_check_passed and evaluate_answer(survey.survey.granted_scenarios.detect_other_devices, Answer.dont_know)]
    return count_answers(answers, Answer.yes)

def evaluate_device_profiling_only_device(evaluated_surveys: List[EvaluatedSurvey]) -> Dict[str, int]:
    answers = [survey.survey.granted_scenarios.detect_other_devices for survey in evaluated_surveys if survey.sanety_check_passed and evaluate_answer(survey.survey.granted_scenarios.sensitive_device, Answer.dont_know)]
    return count_answers(answers, Answer.yes)
