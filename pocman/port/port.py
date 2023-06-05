import concurrent.futures
from tqdm import tqdm
import requests
from concurrent.futures import ThreadPoolExecutor,wait
from fake_useragent import UserAgent
def carw(url):
    response = requests.get(url, headers=hd, timeout=3)
    if response.status_code != 403:
        with open('./res_url.txt','a') as w:
            w.write(url + ",code:" + str(response.status_code) + "\n")

if __name__ == '__main__':
    ua = UserAgent()
    hd = {"User-Agent": ua.random}
    url_list = []
    for i in range(800,60000):
        url = f"https://scan.fintoch.io:{str(i)}/"
        url_list.append(url)
    with tqdm(total=len(url_list)) as pbar:
        with ThreadPoolExecutor(30) as pool:
            futures = [pool.submit(carw, req_url) for req_url in url_list]
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)
        wait(futures)
    print("end")