from enum import Enum

# Classes for scales used in the survey
class ScaleValue(Enum):
    completely_disagree = 1
    largely_diagree = 2
    slightly_disagree = 3
    slightly_agree = 4
    largely_agree = 5
    completely_agree = 6


#Q7.2
class ATIScale:
    occupy_in_technical_details: ScaleValue   #Q7.2.1
    testing_new_technical_function: ScaleValue #Q7.2.2
    deal_with_technical_details: ScaleValue #Q7.2.3 - reverse
    try_out_new_technical_function: ScaleValue #Q7.2.4
    enjoy_spending_time_on_technical_systems: ScaleValue #Q7.2.5
    enough_that_it_work: ScaleValue #Q7.2.6 - reverse
    understand_technical_system: ScaleValue #Q7.2.7
    enough_to_know_basic: ScaleValue #Q7.2.8 - reverse
    full_use_of_functionalities: ScaleValue #Q7.2.9

    def __str__(self) -> str:
        return f"ATI Scale: {self.occupy_in_technical_details}, {self.testing_new_technical_function}, {self.deal_with_technical_details}, {self.try_out_new_technical_function}, {self.enjoy_spending_time_on_technical_systems}, {self.enough_that_it_work}, {self.understand_technical_system}, {self.enough_to_know_basic}, {self.full_use_of_functionalities}"

    def __repr__(self) -> str:
        return self.__str__()
