u_list = []
with open('./url2.txt') as f:
    for i in f:
        if i.strip() not in u_list:
            u_list.append(i.strip())
with open('data/url.txt', 'a') as w:
    for i in u_list:
        w.write(i + '\n')