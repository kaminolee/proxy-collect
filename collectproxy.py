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
import logging

logging.basicConfig(level=logging.INFO,
                    format="[%(levelname)s] [%(asctime)s] %(message)s",
                    datefmt='%Y-%m-%d %H:%M:%S'
                    )

WORKDIR = os.path.dirname(os.path.realpath('__file__'))

OUTPUT = "%s/output/%s.txt" % (WORKDIR,
                               time.strftime("%Y%m%d%H%M%S", time.localtime()))


def get_sub_collection():
    today = datetime.datetime.today()
    sub_path = 'https://raw.githubusercontent.com/rxsweet/collectSub/main/sub'
    path_year = sub_path+'/'+str(today.year)
    path_mon = path_year+'/'+str(today.month)
    path_yaml = path_mon+'/'+str(today.month)+'-'+str(today.day)+'.yaml'
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


def check_proxy_status(proxy):
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
    time.sleep(1)
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
            if country is None:
                raise Exception("")
            status = country
        except Exception as _:
            status = "NA"
    except Exception as _:
        pass
    finally:
        s.terminate()

    return status


def rename_proxy(proxy, country):
    global name_count
    global clash_servers
    status = None
    try:
        if country not in name_count:
            name_count[country] = 0
        proxy['name'] = '%s-%s' % (country,
                                     str(name_count[country]).zfill(3))
        name_count[country] += 1
        clash_servers.append(proxy)
        status = proxy['name']
    except Exception as _:
        pass

    return status


def analyse_sub(sub):
    logging.info("Get Sub %s" % sub)
    proxies = []
    response = requests.get(sub, headers={
        'User-Agent': 'v2rayN/5.37'
    })
    if response.status_code != 200:
        logging.error("Get Sub Http Error %s" % response.status_code)
        return
    content = response.content.decode('utf8')
    if len(content) <= 100:
        logging.error("Get Sub Empty Content")
        return
    if 'proxies' not in content.lower():
        urls = base64.b64decode(content).decode("utf8")
        try:
            logging.info("convert to clash")
            response = requests.get("http://127.0.0.1:25500/sub?target=clash&url=%s"%urls.replace("\n","|").replace("\r",""))
            content = response.content.decode("utf8")
        except Exception as e:
            logging.error("Convert Sub Error %s"%str(e))
            return
    
    logging.info("load clash sub")
    data = yaml.unsafe_load(content)
    for proxy in data['proxies']:
        try:
            proxies.append(proxy)
        except Exception as _:
            pass

    return proxies


def check_proxy(proxy, index):
    if re.search(r'公告|流量|套餐|严禁|剩余', str(proxy['name'])):
        logging.info("[%s]%s -> pass" % (index, proxy['name']))
        return
    if check_port_status(proxy['server'], int(proxy['port'])) is False:
        logging.info("[%s]%s -> port closed" % (index, proxy['name']))
        return
    country = check_proxy_status(proxy)
    if country is None:
        logging.info("[%s]%s -> server down" % (index, proxy['name']))
        return
    save = rename_proxy(proxy, country)
    if save is None:
        logging.info("[%s]%s -> save fail" % (index, proxy['name']))
        return
    logging.info("[%s]%s -> %s" % (index, proxy['name'], save))


def check_proxy_thread(sid):
    global running
    global index
    logging.info("THREAD %s START" % sid)
    while running:
        try:
            proxy = check.get(timeout=1)
            index += 1
            check_proxy(proxy, index)
        except Exception as _:
            pass
    logging.info("THREAD %s STOPED" % sid)


if os.path.exists(OUTPUT):
    os.unlink(OUTPUT)

data = yaml.load(get_sub_collection(), Loader=yaml.FullLoader)
pool = []
check = queue.Queue(10)
running = True
geoip_reader = geoip2.database.Reader('%s/Country.mmdb' % WORKDIR)
name_count = {}
v2ray_servers = []
clash_servers = []
index = 0

logging.info("Set Output %s" % OUTPUT)

for i in range(20):
    threading.Thread(target=check_proxy_thread, args=(i,)).start()

for group in data:
    for sub in data[group]:
        try:
            for proxy in analyse_sub(sub):
                if "%s%s%s" % (proxy['server'], proxy['port'], proxy['type']) in pool:
                    continue
                pool.append("%s%s%s" %
                            (proxy['server'], proxy['port'], proxy['type']))
                if proxy is not None:
                    check.put(proxy)
        except Exception as e:
            logging.error(e)

while True:
    if check.empty():
        running = False
        break
    time.sleep(1)

while threading.active_count() != 1:
    logging.debug("RUNNING THREAD %s" % threading.active_count())
    time.sleep(1)

logging.info("generate clash subscription")

clash_servers = sorted(clash_servers, key=lambda e: e.__getitem__('name'))

clash_subscription = {
    'mixed-port': 7891,
    'mode': 'rule',
    'profile': {
        'store-selected': False
    },
    'proxies': clash_servers,
    'proxy-groups': [
        {
            'name': 'balanced',
            'type': 'load-balance',
            'strategy': 'round-robin',
            'url': 'http://www.gstatic.com/generate_204',
            'interval': 300,
            'proxies': [cs['name'] for cs in clash_servers]
        }
    ],
    'rules': [
        'MATCH,balanced'
    ]
}

with open("%s/output/clash.yaml" % WORKDIR, "w", encoding="utf8") as f:
    f.write(yaml.safe_dump(clash_subscription))
