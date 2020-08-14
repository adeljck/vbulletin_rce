# coding:utf-8
from shodan import Shodan

API_KEY = "EEFr2PmVoBV33oRnLuoXs4fmqeWafcJV"
proxies = {'socks5': '127.0.0.1:1086'}
api = Shodan(API_KEY, proxies=proxies)
results = api.search("http.favicon.hash:-601665621",page=9)
print(results["total"])
print(results)
with open("results.txt", "a") as fo:
    for result in results['matches']:
        if result["port"] == 80:
            fo.write("http://"+result["ip_str"] + "\n")
        if result["port"] == 443:
            fo.write("https://"+result["ip_str"] + "\n")
