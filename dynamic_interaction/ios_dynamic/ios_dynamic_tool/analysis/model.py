from dataclasses import dataclass
from enum import Enum

from .constants import FridaEventIdentifiers


class Map(dict):
    """
    Example:
    m = Map({'first_name': 'Eduardo'}, last_name='Pool', age=24, sports=['Soccer'])
    """

    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    self[k] = v

        if kwargs:
            for k, v in kwargs.items():
                self[k] = v

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]


@dataclass
class FridaEvent(Map):
    """
    Contains the bare minimum fields needed to represent an event received from a frida script.
    The actual event may contain additional fields.
    """

    name: str

    # UNIX timestamp with milliseconds after the comma, e.g. 1627976403.844
    timestamp: float


@dataclass
class InvocationEvent(FridaEvent):
    """
    The actual event might include more infos sent by the frida script,
    but this class specifies the minimum included fields
    """

    identifier_name = FridaEventIdentifiers.InvocationEvent

    className: str
    methodName: str


@dataclass
class NetworkEvent(FridaEvent):
    identifier_name = FridaEventIdentifiers.NetworkEvent

    url: str
    method: str


class AudioVideoInvocationEventAccessType(Enum):
    MICROPHONE = "audio"
    CAMERA = "video"


@dataclass
class AudioVideoInvocationEvent(FridaEvent):
    """ Used to communicate camera and microphone access events. Both use AVCaptureDevice API """
    identifier_name = FridaEventIdentifiers.AudioVideoInvocationEvent

    url: str
    method: str
    access_type:  AudioVideoInvocationEventAccessType
