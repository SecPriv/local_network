from enum import Enum
from typing import List

# Classes for demographic data from the survey

class Age(Enum):
    under_18 = 1
    between_18_24 = 2
    between_25_34 = 3
    between_35_44 = 4
    between_45_54 = 5
    between_55_64 = 6
    over_65 = 7


class Gender():
    male = False
    female = False
    non_binary = False
    own_description = ""
    not_to_say = False

    def __str__(self) -> str:
        if self.male:
            return "Male"
        elif self.female:
            return "Female"
        elif self.non_binary:
            return "Non-binary"
        elif self.own_description:
            return self.own_description
        elif self.not_to_say:
            return "Prefer not to say"
    
    def __repr__(self) -> str:
        return self.__str__()



class IT_Background(Enum):
    work_related =1
    education_related = 2
    selft_taught = 3
    no_background = 4

class IOS_Version(Enum):
    ios_17 = 17
    ios_16 = 16
    ios_15 = 15
    ios_14 = 14
    ios_13 = 13
    ios_12_or_lower = 12
    dont_know = 0
    not_using = -1

class Demography:
    age: Age # Q52
    gender: Gender # Q53 and # Q53.4
    country: str
    it_background: List[IT_Background] # Q 52
    ios_version: IOS_Version # Q53

    def __str__(self) -> str:
        return f"Age: {self.age}, gender: {self.gender}, country: {self.country}, IT Background: {self.it_background}, iOS Version: {self.ios_version}"
    
    def __repr__(self) -> str:
        return self.__str__()