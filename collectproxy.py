import base64
import copy
import json
import os
import random
import re
import socket
import subprocess
import time
import datetime
import requests
import yaml
import queue
import threading
import geoip2.database
import uuid


WORKDIR = os.path.dirname(os.path.realpath('__file__'))

OUTPUT = "%s/output/openproxy.txt" % WORKDIR


def get_sub_collection():
    today = datetime.datetime.today()
    sub_path = 'https://raw.githubusercontent.com/rxsweet/collectSub/main/sub'
    path_year = sub_path+'/'+str(today.year)
    path_mon = path_year+'/'+str(today.month)
    path_yaml = path_mon+'/'+str(today.month)+'-'+str(today.day)+'.yaml'
    path_yaml = 'https://ghproxy.com/https://raw.githubusercontent.com/rxsweet/collectSub/main/sub/2022/11/11-20.yaml'
    response = requests.get(path_yaml)
    if response.ok:
        return response.content.decode("utf8")

    raise Exception("Get Collection Error %s" % response.status_code)


def check_port_status(ip, port):
    status = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((ip, port))
        s.shutdown(socket.SHUT_RDWR)
        status = True
    except Exception as _:
        pass
    finally:
        s.close()

    return status


def check_v2ray_status(proxy):
    global geoip_reader
    status = None
    config_tepmlate = {
        'mixed-port': 0,
        'log-level': 'debug',
        'proxies': [],
        'rules': ['MATCH,proxy']
    }
    config = copy.deepcopy(config_tepmlate)
    server = copy.deepcopy(proxy)
    server['name'] = 'proxy'
    config['proxies'].append(server)
    config['port'] = random.randint(20000, 50000)
    config_path = "%s/config/%s.yaml" % (WORKDIR, str(uuid.uuid1()))
    with open(config_path, "w", encoding="utf8") as fc:
        fc.write(yaml.safe_dump(config))
    s = subprocess.Popen(['clash', "-f", config_path],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.2)
    try:
        response = requests.get('http://api.ipify.org',
                                proxies={
                                    'http': 'http://127.0.0.1:%s' % config['port'],
                                    'https': 'http://127.0.0.1:%s' % config['port'],
                                }, headers={
                                    'User-Agent': 'v2rayN/5.37'
                                }, timeout=5, verify=False
                                )
        if not response.ok:
            raise Exception("Http Error %s" % response.status_code)

        try:
            ip = response.content.decode("utf8")
            country = geoip_reader.country(ip).country.iso_code
            print(ip, country)
            if country is None:
                raise Exception("")
            status = country
        except Exception as _:
            status = "NONE"
    except Exception as e:
        print(e)
        pass
    finally:
        s.terminate()

    return status


def save_v2ray_config(proxy, country):
    global name_count
    status = False
    try:
        v2ray = {
            "v": "2",
            "ps": str(proxy['name']),
            "add": proxy['server'],
            "port": proxy['port'],
            "type": "auto",
            "id": proxy['uuid'],
            "aid": proxy['alterId'],
            "net": "tcp",
            "path": "/",
            "host": proxy['server'],
            "tls": ""
        }
        try:
            v2ray['tls'] = 'tls'
        except Exception as _:
            pass
        try:
            v2ray['net'] = proxy['network']
        except Exception as _:
            pass
        try:
            v2ray['path'] = proxy['ws-opts']['path']
        except Exception as _:
            pass
        try:
            v2ray['host'] = proxy['ws-opts']['headers']['Host']
        except Exception as _:
            pass
        try:
            if country not in name_count:
                name_count[country] = 0
            v2ray['ps'] = '%s-%s' % (country,
                                     str(name_count[country]).zfill(3))
            name_count[country] += 1
        except Exception as _:
            pass

        with open(OUTPUT, "a", encoding="utf8") as v:
            v.write("%s://%s\n" % (proxy['type'], base64.b64encode(
                json.dumps(v2ray).encode("utf8")).decode("utf8")))
            status = True
    except Exception as e:
        print(e)

    return status


def analyse_sub(sub):
    proxies = []
    response = requests.get(sub, headers={
        'User-Agent': 'v2rayN/5.37'
    })
    if response.status_code != 200:
        print("Http Error %s" % response.status_code)
        return
    content = response.content.decode('utf8')
    if len(content) <= 100:
        print("Empty Content")
        return
    if 'proxies' in content.lower():
        print("handle clash sub")
        data = yaml.unsafe_load(content)
        for proxy in data['proxies']:
            try:
                if proxy['type'] == 'vmess' or proxy['type'] == 'vless':
                    proxies.append(proxy)
            except Exception as _:
                pass
    else:
        print("handle v2ray sub")
        data = base64.b64decode(content)
        for s in data.decode("utf8").split("\n"):
            if len(s) == 0:
                continue
            try:
                if 'vmess' in s or 'vless' in s:
                    url = s.replace("\r", "").replace(
                        "vmess://", "").replace("vless://", "")
                    v = json.loads(base64.b64decode(url).decode("utf8"))
                    proxy = {
                        "name": v['ps'],
                        "server": v['add'],
                        "port": v['port'],
                        "type": "vmess",
                        "uuid": v['id'],
                        "alterId": v['aid'],
                        "cipher": "auto",
                        "tls": v['tls'] == 'tls',
                        "skip-cert-verify": True,
                        "network": v['net'],
                        "ws-opts": {
                            "path": v['path'],
                            "headers": {
                                "Host": v['host']
                            }
                        },
                        "ws-path": v['path'],
                        "ws-headers": {
                            "Host": v['host']
                        },
                        "udp": True
                    }
                    proxies.append(proxy)

            except Exception as _:
                pass

    return proxies


def check_proxy(proxy):
    if re.search(r'公告|流量|套餐|严禁|剩余', str(proxy['name'])):
        print("%s -> pass" % (proxy['name']))
        return
    if check_port_status(proxy['server'], int(proxy['port'])) is False:
        print("%s -> port closed" % (proxy['name']))
        return
    country = check_v2ray_status(proxy)
    if country is None:
        print("%s -> server down" % (proxy['name']))
        return
    if save_v2ray_config(proxy, country) is False:
        print("%s -> save fail" % (proxy['name']))
        return


def check_proxy_thread(sid):
    global running
    print("THREAD %s START" % sid)
    while running:
        proxy = check.get()
        check_proxy(proxy)
    print("THREAD %s STOPED" % sid)


if os.path.exists(OUTPUT):
    os.unlink(OUTPUT)

data = yaml.load(get_sub_collection(), Loader=yaml.FullLoader)
pool = []
check = queue.Queue(10)
running = True
geoip_reader = geoip2.database.Reader('%s/Country.mmdb' % WORKDIR)
name_count = {}


for i in range(10):
    threading.Thread(target=check_proxy_thread, args=(i,)).start()

for group in data:
    for sub in data[group]:
        try:
            for proxy in analyse_sub(sub):
                if "%s%s%s" % (proxy['server'], proxy['port'], proxy['uuid']) in pool:
                    continue
                pool.append("%s%s%s" %
                            (proxy['server'], proxy['port'], proxy['uuid']))
                if proxy is not None:
                    check.put(proxy)
        except Exception as e:
            print(e)

while True:
    if check.empty():
        running = False
    time.sleep(1)
