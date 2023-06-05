import requests
import csv
from bs4 import BeautifulSoup
import socket
from concurrent.futures import ThreadPoolExecutor,wait
from tqdm import tqdm
from fake_useragent import UserAgent
import concurrent.futures

def craw(url):
    ua = UserAgent()
    headers = {"User-Agent": ua.random}
    try:
        response = requests.get(url="https://" + url, headers=headers, timeout=5)
        # print(url)
        response.encoding = response.apparent_encoding
        ip_address = socket.gethostbyname(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string
        contents = len(response.text)
        with open('res/res.csv', 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([url, ip_address, response.status_code, title, contents])
    except Exception as e:
        pass
if __name__ == '__main__':
    url_list = []
    with open('data/url.txt') as f:
        for i in f:
            if i:
                if i.strip() not in url_list:
                    url_list.append(i.strip())
    with tqdm(total=len(url_list), desc='url响应进度', bar_format="{l_bar}{bar:30}{r_bar}", colour='black') as pbar:
        with ThreadPoolExecutor(20) as pool:
            futures = [pool.submit(craw, res_url) for res_url in url_list]
            for future in concurrent.futures.as_completed(futures):
                future.result()
                pbar.update(1)
        wait(futures)
    print("end of object")