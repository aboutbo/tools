# -*- coding: utf-8 -*-
# author: xiwu
# description: check redis for unauth, slave-rce, weak_pass

import socket
import sys
import argparse

# 默认内置字典
weak_pass_dict = ['admin', '123456', 'foobared']


def connect_test(ip, port):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.close()
        return True
    except Exception as e:
        print(e)
        return False


# 未授权访问检查
def unauth_check(ip, port):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send('*1\r\n$4\r\nINFO\r\n'.encode('UTF-8'))
        response = s.recv(1024)
        s.close()
        if 'NOAUTH Authentication required' in response.decode('UTF-8'):
            print('redis needs authentication!')
            # flag:0, redis needs authentication
            flag = 0
            return flag
        elif 'redis_version' in response.decode('UTF-8'):
            print('redis unauth!')
            # flag:1, redis unauth
            flag = 1
            return flag
        else:
            print('It\'s not redis!')
            # flag:2, not redis
            flag = 2
            return flag
    except Exception as e:
        print(e)
        # flag:3, connection exception
        flag = 3
        return flag


# 密码爆破
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
    s.close()
    print('weak password not found!')
    return False


# root权限检查
def privilege(ip, port, *args):
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' %
                (len(passwd), passwd)).encode('utf-8'))
    s.send(
        '*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\nDIR\r\n$11\r\n/root/.ssh/\r\n'
        .encode('UTF-8'))
    response = s.recv(1024)
    s.close()
    if 'Permission denied' in response.decode('UTF-8'):
        print('It\'s not root permission!')
        return False
    elif '+OK' in response.decode('UTF-8'):
        print('It\'s root permission!')
        return True
    else:
        print('Detecting permission failed!')
        return False


# master-slave RCE检查
def slave_rce(ip, port, *args):
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(port)))
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' %
                (len(passwd), passwd)).encode('utf-8'))
    s.send('*3\r\n$6\r\nMODULE\r\n$4\r\nLOAD\r\n$3\r\n123\r\n'.encode('UTF-8'))
    response = s.recv(1024)
    s.close()
    if 'ERR unknown command' in response.decode('UTF-8'):
        print('It does not support "MODULE" command!')
        return False
    elif 'Error loading the extension' in response.decode('UTF-8'):
        print('You can exploit "Master-Slave RCE"')
        return True
    else:
        print('Detecting slave-rec failed!')
        return False


# 加载字典文件
def load_pwd_from_file(file_path):
    weak_pass_dict = list()
    with open(file_path) as f:
        for line in f:
            weak_pass_dict.append(line.strip())
    return weak_pass_dict


# 加载IP:port文件
def load_port_from_file(file_path):
    ip_port_list = list()
    with open(file_path) as f:
        for line in f:
            ip_port_list.append(line.strip())
    return ip_port_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='detect redis!')
    parser.add_argument('-H',
                        '--host',
                        dest='host',
                        metavar='ip',
                        help='IP address')
    parser.add_argument('-p',
                        '--port',
                        dest='port',
                        metavar='port',
                        type=int,
                        default=6379,
                        help='redis port, default: 6379')
    parser.add_argument('-f',
                        '--file',
                        dest='file_path',
                        metavar='file_path',
                        help='path of redis IP file, format: ip,port')
    parser.add_argument('-a',
                        '--auth',
                        dest='passwd_path',
                        metavar='passwd_file_path',
                        help='path of redis password')
    parser.add_argument('-o',
                        '--output',
                        dest='output_file',
                        metavar='file_path',
                        help='file path for output')
    args = parser.parse_args()

    if args.output_file:
        with open(args.output_file, 'w+') as f:
            pass

    if args.passwd_path:
        weak_pass_dict = load_pwd_from_file(args.passwd_path)

    if args.file_path:
        ip_port_list = load_port_from_file(args.file_path)
        for each in ip_port_list:
            print(each)
            UNAUTH = 'AUTH'
            PASSWD = 'NOT_FOUND'
            M_S_RCE = 'NO_M_S_RCE'
            PRIVILEGE = 'ROOT'
            ip = each.split(',')[0].strip('"')
            port = int(each.split(',')[1].strip('"'))
            if connect_test(ip, port):
                flag = unauth_check(ip, port)
                if flag == 1:
                    UNAUTH = 'UNAUTH'
                    if not privilege(ip, port):
                        PRIVILEGE = 'NO_ROOT'
                        if slave_rce(ip, port):
                            M_S_RCE = 'Master-Slave-RCE'
                elif flag == 0:
                    passwd = find_weak_pwd(ip, port)
                    if passwd:
                        PASSWD = passwd
                        if not privilege(ip, port, passwd):
                            if slave_rce(ip, port, passwd):
                                M_S_RCE = 'Master-Slave-RCE'
                else:
                    continue

                # 无法利用的情况不输出：1. AUTH & password:NOT_FOUND  2. UNAUTH & NO_ROOT & NO_M_S_RCE
                with open(args.output_file, 'a') as f:
                    if (UNAUTH == 'AUTH' and PASSWD == 'NOT_FOUND') or (
                            UNAUTH == 'UNAUTH' and PRIVILEGE == 'NO_ROOT'
                            and M_S_RCE == 'NO_M_S_RCE'):
                        pass
                    else:
                        f.write(
                            '{ip}:{port}, {UNAUTH}, password:{PASSWD}, {PRIVILEGE}, {M_S_RCE}\n'
                            .format(ip=ip,
                                    port=str(port),
                                    UNAUTH=UNAUTH,
                                    PASSWD=PASSWD,
                                    PRIVILEGE=PRIVILEGE,
                                    M_S_RCE=M_S_RCE))

    else:
        ip = args.host
        port = args.port
        if connect_test(ip, port):
            flag = unauth_check(ip, port)
            if flag == 1:
                if not privilege(ip, port):
                    slave_rce(ip, port)
            elif flag == 0:
                passwd = find_weak_pwd(ip, port)
                if passwd:
                    if not privilege(ip, port, passwd):
                        slave_rce(ip, port, passwd)

    print('detection done!')
