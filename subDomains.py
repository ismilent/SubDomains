#! python3
# author: Smilent

import uvloop
import socket
import string
import aiodns
import asyncio
import argparse
import struct
import itertools
from tqdm import tqdm
from operator import attrgetter

host_attr=attrgetter('host')
MAX_SEMAPHORE_NUM = 512 # 最大信号数量


# resolver DNS
async def resolver_dns(semaphore, resolver, domain, wildcard=None, ignore_priv=False):
    '''
    DNS解析函数，基于coroutine
    :param semaphore: 协程数量
    :param resolver: DNSResolver object
    :param domain: 解析域名
    :param wildcard: 泛解析IPs
    :param ignore_priv: 是否忽略内网ip
    :return:
    '''
    try:
        async with semaphore:
            result = await resolver.query(domain,'A')
    except Exception as e:
        pass
    else:
        tmp = sorted(map(host_attr,result))

        if ignore_priv:
            tmp = [ip for ip in tmp if not is_private_ips(ip)]

        if not tmp: return

        if wildcard and tmp in wildcard:
            pass
        else:

            tqdm.write('\r' + domain + '\t' + ' '.join(tmp))


async def wait_with_progress(coroutines):
    for f in tqdm(asyncio.as_completed(coroutines),total=len(coroutines)):
        await f


def generate_dict_random(source, dict_len=3):
    '''
    Generate random sub domain dictionary
    :param source: 子域名生成来源
    :param dict_len: 子域名生产长度，最大为4
    :return: 返回一个子域名generator
    '''
    print('[+] Generating sub dictionary, lenth %d' % dict_len)
    dict_len = dict_len if dict_len <= 4 else 4
    print('[+] Generating sub dictionary, lenth %d' % dict_len)
    for i in range(dict_len):
        for sub_name in itertools.product(source, repeat=i+1):
            yield ''.join(sub_name)


def is_private_ips(ip):
    '''
    私有IP检查
    :param ip: 被检查的ip
    :return: bool
    '''
    networks = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "224.0.0.0/4",
    ]

    for network in networks:
        try:
            ipaddr = struct.unpack('>I', socket.inet_aton(ip))[0]

            netaddr, bits = network.split('/')

            network_low = struct.unpack('>I', socket.inet_aton(netaddr))[0]
            #network_high = (network_low | 1 << (32 - int(bits))) - 1
            network_high = 4294967295 >> int(bits) ^ network_low

            if ipaddr <= network_high and ipaddr >= network_low:
                return True
        except Exception as e:
            continue

    return False

def init_sub_dictionary():
    pass

def main(domain, sub_file_path, generate, ignore_priv):
    domain = domain
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy()) # Using uvloop event loop policy
    loop = asyncio.get_event_loop()
    resolver = aiodns.DNSResolver(loop=loop)

    try:
        ips = loop.run_until_complete(asyncio.ensure_future(
            resolver.query('783283123884192918.'+domain.strip(),'A')))
    except Exception as e:
        wildcard = None
    else:
        wildcard = sorted(map(host_attr,ips))
        print(wildcard)
        tqdm.write('Wildcard find...' + ''.join(wildcard))


    print('[+] Setting up max semaphore number',MAX_SEMAPHORE_NUM)
    semaphore = asyncio.Semaphore(MAX_SEMAPHORE_NUM)

    print('[+] Generate subdomians dictionary...')

    tasks = []
    sub_domain_dict = None

    if generate:
        sub_domain_dict = generate_dict_random(string.ascii_lowercase+'0123456789', 4)
    else:
        with open(sub_file_path, 'r') as f:
            sub_domain_dict = (line.strip() for line in f.readlines())

    print('[+] Starting brute %s subdomains...'%domain)

    for line in sub_domain_dict:
        subname = line+'.'+domain
        tasks.append(asyncio.ensure_future(
            resolver_dns(semaphore,resolver,subname, wildcard, ignore_priv)))
    try:
        loop.run_until_complete(wait_with_progress(tasks))
    except KeyboardInterrupt as e:
        print('[-] Cancel task...')
        for task in asyncio.Task.all_tasks():
            task.cancel()
        loop.stop()
        loop.run_forever()
    finally:
        loop.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='SubDomain Scan Program', usage='python3 %(prog)s <option> <domain>', prog='subDomainsCollect.py'
    )
    parser.add_argument('-f', '--file', dest='sub_file_path', help='Sub domains dictionary.',
                        action='store',default='www.txt')
    parser.add_argument('-r', '--recurive', dest='recurive', help='Max recurive for sub domain.',
                        action='store', default='1')
    parser.add_argument('-i', '--ignore-private', dest='ignore_priv',
                        action='store_true', help='Ignore private IPs', default=False)
    parser.add_argument('-g', '--generate', dest='generate', help='Generate sub dictionary',
                        action='store', default=None)
    parser.add_argument('-gl', '--generate-length', dest='gen_len', help='Generate sub dictionary length',
                        action='store', default=3)
    parser.add_argument('-d', '--domain', help='The target domain.', dest='domain',
                        action='store', default=None)

    parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    print(args)
    if not args.domain:
        parser.parse_args(['-h'])
    main(args.domain, args.sub_file_path, args.generate, args.ignore_priv)
