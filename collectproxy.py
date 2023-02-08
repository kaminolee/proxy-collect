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
import urllib3
import dns.resolver

start_time = int(time.time())

logging.basicConfig(level=logging.INFO,
                    format="[%(levelname)s] [%(asctime)s] %(message)s",
                    datefmt='%Y-%m-%d %H:%M:%S'
                    )

WORKDIR = os.path.dirname(os.path.realpath('__file__'))

OUTPUT = "%s/output/%s.txt" % (WORKDIR,
                               time.strftime("%Y%m%d%H%M%S", time.localtime()))


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_subscriptions():
    subscriptions = []

    # local file
    with open("subscriptions.txt", "r", encoding="utf8") as f:
        for line in f.readlines():
            sub = line.replace("\n", "")
            if len(sub) > 0:
                subscriptions.append(sub)

    # collectSub
    try:
        today = datetime.datetime.today()
        sub_path = 'https://raw.githubusercontent.com/rxsweet/collectSub/main/sub'
        path_year = sub_path+'/'+str(today.year)
        path_mon = path_year+'/'+str(today.month)
        path_yaml = path_mon+'/'+str(today.month)+'-'+str(today.day)+'.yaml'
        logging.debug(path_yaml)
        response = requests.get(path_yaml)
        if response.ok:
            collection = yaml.safe_load(response.content.decode("utf8"))
            for group in collection:
                for sub in collection[group]:
                    subscriptions.append(sub)
    except Exception as e:
        logging.error("Get sub from collectSub fail %s" % str(e))

    return subscriptions


def get_proxies():
    proxies = []

    return proxies


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

def domain_to_host(domain):
    hosts = []
    try:
        answers = dns.resolver.resolve(domain,'A')
        for rdata in answers:
            hosts.append(str(rdata))
    except Exception as _:
        pass

    try:
        answers = dns.resolver.resolve(domain,'AAAA')
        for rdata in answers:
            hosts.append(str(rdata))
    except Exception as _:
        pass
    if len(hosts) == 1:
        logging.debug("Resolve %s to %s"%(domain,hosts[0]))
        return hosts[0]
    else:
        return domain

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
        response = requests.get('https://api.ip.sb/ip',
                                proxies={
                                    'http': 'http://127.0.0.1:%s' % config['port'],
                                    'https': 'http://127.0.0.1:%s' % config['port'],
                                }, headers={
                                    'User-Agent': 'v2rayN/5.37'
                                }, timeout=10, verify=False
                                )
        if not response.ok:
            raise Exception("Http Error %s" % response.status_code)

        try:
            ip = response.content.decode("utf8").replace(" ","").replace("\n","")
            status  = ip
        except Exception as e:
            logging.error("Get ip fail: %s"%str(e))
            status = "未知"
    except Exception as _:
        pass
    finally:
        s.terminate()

    return status


def rename_proxy(proxy, country,ip):
    global name_count
    global clash_servers
    status = None
    try:
        if country not in name_count:
            name_count[country] = 0
        proxy['name'] = '%s-%s-%s' % (country,
                                   str(name_count[country]).zfill(3),ip)
        name_count[country] += 1
        clash_servers.append(proxy)
        status = proxy['name']
    except Exception as _:
        pass

    return status


def analyse_sub(sub):
    global stats_count
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
        try:
            urls = base64.b64decode(content).decode("utf8")
        except Exception as _:
            urls = content
        try:
            logging.info("convert to clash")
            response = requests.get(
                "http://127.0.0.1:25500/sub?target=clash&url=%s" % urls.replace("\n", "|").replace("\r", ""))
            content = response.content.decode("utf8")
        except Exception as e:
            logging.error("Convert Sub Error %s" % str(e))
            return

    logging.info("load clash sub")
    data = yaml.unsafe_load(content)
    logging.info("Get proxies %s" % str(len(data['proxies'])))
    for proxy in data['proxies']:
        try:
            proxies.append(proxy)
        except Exception as _:
            pass

    return proxies


def check_proxy(proxy, index):
    global stats_fail
    global stats_success
    if re.search(r'公告|流量|套餐|严禁|剩余', str(proxy['name'])):
        stats_fail += 1
        logging.info("[%s]%s -> pass" % (index, proxy['name']))
        return
    if check_port_status(proxy['server'], int(proxy['port'])) is False:
        stats_fail += 1
        logging.info("[%s]%s -> port closed" % (index, proxy['name']))
        return
    ip = check_proxy_status(proxy)
    if ip is None:
        stats_fail += 1
        logging.info("[%s]%s -> server down" % (index, proxy['name']))
        return
    try:
        country = geoip_reader.country(ip).country.names['zh-CN']
        if country is None:
            raise Exception("Country is None")
    except Exception as e:
        logging.error("Get Location Fail %s"%ip)
        country = "未知"
    save = rename_proxy(proxy, country,ip)
    if save is None:
        stats_fail += 1
        logging.info("[%s]%s -> save fail" % (index, proxy['name']))
        return
    logging.info("[%s]%s -> %s" % (index, proxy['name'], save))
    stats_success += 1


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

pool = []
check = queue.Queue(10)
running = True
geoip_reader = geoip2.database.Reader('%s/Country.mmdb' % WORKDIR)
name_count = {}
clash_servers = []
index = 0

stats_count = 0
stats_success = 0
stats_fail = 0
stats_repeat = 0

SUBSCRIPTIONS = []
PROXIES = []

logging.info("Set Output %s" % OUTPUT)

# import subs and proxies
SUBSCRIPTIONS = get_subscriptions()
PROXIES = get_proxies()

# start check proxy thread
for i in range(20):
    threading.Thread(target=check_proxy_thread, args=(i,)).start()

# check proxies
# TODO

# check subscriptions
for sub in SUBSCRIPTIONS:
    try:
        for proxy in analyse_sub(sub):
            proxy['server'] = domain_to_host(proxy['server'])
            if "%s%s%s" % (proxy['server'], proxy['port'], proxy['type']) in pool:
                stats_repeat +=1
                continue
            pool.append("%s%s%s" %
                        (proxy['server'], proxy['port'], proxy['type']))
            if proxy is not None:
                stats_count +=1
                check.put(proxy)
    except Exception as e:
        logging.error(e)

# waiting for queue empty
while True:
    if check.empty():
        running = False
        break
    time.sleep(1)

# waiting for thread empty
while threading.active_count() != 1:
    logging.debug("RUNNING THREAD %s" % threading.active_count())
    time.sleep(1)

# generate clash config
logging.info("generate clash subscription")

clash_servers = sorted(clash_servers, key=lambda e: e.__getitem__('name'))

clash_subscription = {
    'mixed-port': 7892,
    'mode': 'rule',
    'allow-lan': True,
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

end_time = int(time.time())

with open("result.txt","w",encoding="utf8") as fr:
    fr.write("""
Running Time: %ss
Check Proxies: %s
Success Proxies: %s
Fail Proxies: %s
Repeat Proxies: %s
"""%(end_time - start_time,stats_count,stats_success,stats_fail,stats_repeat))