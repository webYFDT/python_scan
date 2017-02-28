#!/usr/bin/python
#coding:utf-8
from scapy.all import *
from Tkinter import *

class tcp_scan(object):
	"""docstring for tcp_scan"""
	def __init__(self):
		super(tcp_scan, self).__init__()
		self.top = Tk()
		self.top.title('tcp_scan')

		fm1=LabelFrame(self.top,height = 200,width = 300,text ='data')
		#dst.get()
		label1=Label(fm1,text='dst:',width=7)
		label1.grid(row = 0, column = 0)
		self.dst=StringVar()############
		entry1 = Entry(fm1,textvariable=self.dst,width = 10)
		entry1.grid(row = 0, column = 1)

		label2=Label(fm1,text='start_port:',width=8)
		label2.grid(row = 0, column = 2)
		self.start_port=IntVar()##############
		entry2= Entry(fm1,textvariable=self.start_port,width = 5)
		entry2.grid(row = 0, column = 3)
		fm1.pack(fill=X)

		label3=Label(fm1,text='end_port:',width=8)
		label3.grid(row = 0, column = 4)
		self.end_port=IntVar()#######
		entry3= Entry(fm1,textvariable=self.end_port,width = 5)
		entry3.grid(row = 0, column = 5)

		groups=[('SYN','S',0),('FIN','F',1),('NULL','',2),('XMAS','FUP',3)]
		self.FLAGS = StringVar()####
		for Text,Value,i in groups:
			r=Radiobutton(fm1, text=Text, variable=self.FLAGS,value=Value)
			r.grid(row = 1, column = i)

		begin=Button(fm1,text='begin',command=self.scan)
		begin.grid(row = 2, column = 2)
		quit=Button(fm1,text='quit',command=fm1.quit)
		quit.grid(row=3,column=2)
		fm1.pack(fill=X)
		fm2=LabelFrame(self.top,height = 200,width = 300,text ='open_port')
		self.resoult_data=Message(fm2,text='')
		self.resoult_data.grid(row = 3,column = 0)
		fm2.pack(fill=X)
		
			


#	def scan(Dst,FLags,*Dport):
	def scan(self):
		Dport=range(self.start_port.get(),self.end_port.get()+1)
		Res,Unans=sr(IP(dst=self.dst.get())/TCP(flags=self.FLAGS.get(),sport=RandShort(),dport=Dport),inter=0.5,retry=2,timeout=1)
		O_DPort=''
		#SYN
		if self.FLAGS.get()=='S':
			num_port=len(Res)
			for i in range(num_port):
				FLags=Res[i][1][TCP].flags
				DPort=Res[i][1][TCP].sport
				if FLags==18:
					O_DPort=O_DPort+str(DPort)+'\n'
				else:
					pass #no open
		#FIN,NULL,Xams
		else:
			num_port=len(Unans)
			for i in range(num_port):
				DPort=Unans[i][TCP].dport
				O_DPort=O_DPort+str(DPort)+'\n'
				print O_DPort
		self.resoult_data.config(text=O_DPort)
		return
def main():
	d=tcp_scan()
	mainloop()
if __name__=='__main__':
	main()


