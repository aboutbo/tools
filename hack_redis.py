# -*- coding: utf-8 -*-
# author: xiwu
# description: check redis for unauth, slave-rce, weak_pass

import socket
import sys

weak_pass_dict = ['admin', '123456']


def unauth_check(ip, port):

    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    s.send('*1\r\n$4\r\nINFO\r\n'.encode('UTF-8'))
    response = s.recv(1024)
    if 'NOAUTH Authentication required' in response.decode('UTF-8'):
        print('redis needs authentication!')
        return False
    else:
        print('redis unauth!')
        return True


def find_weak_pwd(ip, port):
    print('attempt to find weak password：')
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    for pass_ in weak_pass_dict:
        s.send(("*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n" %
                (len(pass_), pass_)).encode('UTF-8'))
        response = s.recv(1024)
        if '+OK' in response.decode('utf-8'):
            print('存在弱口令，密码：%s' % (pass_))
            return pass_
    print('weak password not found!')
    return False


def privilege(ip, port, *args):
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' % (len(passwd), passwd)).encode('utf-8'))
    s.send('*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\nDIR\r\n$11\r\n/root/.ssh/\r\n'.
           encode('UTF-8'))
    response = s.recv(1024)
    if 'Permission denied' in response.decode('UTF-8'):
        print('It\'s not root permission!')
        return False
    elif '+OK' in response.decode('UTF-8'):
        print('It\'s root permission!')
        return True
    else:
        print('Detecting permission failed!')
        return False


def slave_rce(ip, port, *args):
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' % (len(passwd), passwd)).encode('utf-8'))
    s.send('*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$3\r\n123\r\n'.encode('UTF-8'))
    response = s.recv(1024)
    if 'ERR unknown command' in response.decode('UTF-8'):
        print('It does not support "MODULE" command!')
        return False
    elif 'Error loading the extension' in response.decode('UTF-8'):
        print('You can exploit "Master-Slave RCE"')
        return True
    else:
        print('Detecting slave-rec failed!')
        return False


if __name__ == '__main__':
    ip=sys.argv[1]
    port=int(sys.argv[2])
    if unauth_check(ip, port):
        if not privilege(ip, port):
            slave_rce(ip, port)
    else:
        passwd = find_weak_pwd(ip, port)
        if passwd:
            if privilege(ip, port, passwd):
                slave_rce(ip, port, passwd)
