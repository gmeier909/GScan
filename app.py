"""
Created by GMeier
Desc:
    获取ip段,ip范围的所有取值ip
    探测存活主机
    单url漏洞扫描
Plan:
    后续增加多地址批量检测
    通过扫描的存活主机进行端口存活检测
    通过存活端口进行批量漏洞扫描
"""


import os
import glob

import requests
import yaml
import ipaddress
import socket
import fire
import requests


# TODO: 探测主机存活
def is_ip_alive(ips):
    res = []
    for ip in ips:
        try:
            # 创建一个socket对象
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 连接到指定的IP地址和端口号
            s.connect((ip, 80))
            # 连接成功，返回True
            res.append(ip)
        except Exception as e:
            pass
        finally:
            # 关闭socket连接
            s.close()
    return res


def get_all_ips_from_array(arr):
    ips = []

    for line in arr:

        # 检查行中的IP地址表示法类型
        if '/' in line:
            # IP地址段表示法，例如：192.168.7.0/24
            network = ipaddress.ip_network(line, strict=False)
            ips.extend([str(ip) for ip in network.hosts()])
        elif '-' in line:
            # IP地址范围表示法，例如：192.168.7.10-20
            start_ip, end_ip = line.split('-')
            start_ip_parts = start_ip.split('.')
            end_ip_parts = end_ip.split('.')

            for i in range(int(start_ip_parts[-1]), int(end_ip_parts[-1]) + 1):
                ip_parts = start_ip_parts[:-1] + [str(i)]
                ip = '.'.join(ip_parts)
                ips.append(ip)
        else:
            # 单个IP地址
            ips.append(line)
    else:
        targets = ips
    return targets


class Gscan:
    """
    从文件中提取出ip地址信息获取他们的所有ip地址
    """

    def getIps(self, filename):
        with open(filename, 'r', encoding="utf-8") as file:
            ipsText = file.read().strip().splitlines()
            file.close()
        res = get_all_ips_from_array(ipsText)
        print(res)

    """
    根据IP地址获取存活主机数
    """

    def getActive(self, filename):
        with open(filename, 'r', encoding="utf-8") as file:
            ipsText = file.read().strip().splitlines()
            file.close()
        res = is_ip_alive(ipsText)
        for item in res:
            print(f"{item} is active")

    """
    获取所有IP地址以及主机存活
    """

    def scan(self, filename):
        with open(filename, 'r', encoding="utf-8") as file:
            ipsText = file.read().strip().splitlines()
            file.close()
        allIps = get_all_ips_from_array(ipsText)
        print(allIps)
        allActive = is_ip_alive(allIps)
        print(allActive)

    def poc(self, url):
        # TODO:现在是单url扫描,也可以根据上面的代码改为多地址扫描
        for yaml_file in getPoc():
            with open(yaml_file, 'r', encoding="utf-8") as file:
                config = yaml.safe_load(file)
                file.close()
            yamlName = config['name']
            thisVerify = False
            print(f"=============开始扫描:{yamlName}=============")
            for rule_name, rule_data in config['rules'].items():
                method = rule_data['method']
                path = rule_data['path']
                expression = rule_data['expression']
                # TODO：是否跟随重定向
                try:
                    follow_redirects = rule_data['follow_redirects']
                except:
                    follow_redirects = False
                # TODO: 获取请求头
                try:
                    headers = rule_data['headers']
                except:
                    headers = []
                # TODO: 获取请求体
                try:
                    # POC文件中不一定有这个参数,不存在则会报错
                    body = rule_data['body']
                except:
                    body = ""

                # TODO: 因为POC中我们的验证内容是response,所以这里也要命名为response，这样eval就可以直接验证是否成功，所以POC的expression需要使用requests的验证规则
                response = requests.request(method=method, url=f"http://{url}{path}", data=body, headers=headers, timeout=3,
                                            verify=False)
                verify = eval(expression)
                # TODO: 如果verify为真就为真,否则相反,因为这里是循环，所以需要这个局部变量
                thisVerify = verify if verify else False
            # TODO：循环结束判断是否全部verify为真
            if thisVerify:
                print(f"[+]{yamlName}:{method}:{url}验证成功")
            else:
                print(f"[-]{yamlName}:{method}:{url}验证失败")
            print(f"=============结束扫描:{yamlName}=============")


# 获取POC
def getPoc():
    # 指定POC目录
    directory = 'poc'
    # 读取目录下的所有YAML和YML文件
    yaml_files = glob.glob(os.path.join(directory, '*.yaml')) + glob.glob(os.path.join(directory, '*.yml'))
    return yaml_files


if __name__ == '__main__':
    fire.Fire(Gscan)
