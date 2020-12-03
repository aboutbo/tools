# -*- coding: utf-8 -*-
# author: xiwu
# description: check redis for unauth, slave-rce, weak_pass
# todo: sensitive information check in redis keys

import socket
import sys
import argparse
import re

# 默认内置字典
weak_pass_dict = ['admin', '123456', 'foobared']

# 敏感信息关键字
sensitive_keyword = [
    'password', 'passwd', 'username', 'cookie', 'session', 'token'
]


# 判断是否为邮箱
def is_email(string):
    emails = re.findall(r'[a-z0-9A-Z_]{1,19}@[0-9a-zA-Z]{1,13}\.[a-z]{1,6}',
                        string)
    if emails != ['']:
        return emails
    else:
        return False


# 判断是否为手机号
def is_phone(string):
    iphones = re.findall(
        r'((13[0-9]|14[5-9]|15[012356789]|166|17[0-8]|18[0-9]|19[8-9])[0-9]{8})',
        string)
    res = []
    if iphones != []:
        for i in iphones:
            lens = string.find(i[0])
            if (string[lens - 1:lens].isdigit()) or (string[lens + 11:lens +
                                                            12].isdigit()):
                pass
            else:
                res.append(i[0])
        if res != []:
            return res
        else:
            return False
    else:
        return False


# 判断是否为身份证号
def is_id_card(string):
    coefficient = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    parityBit = '10X98765432'
    idcards = re.findall(
        r'([1-9]\d{5}[1-9]\d{3}((0\d)|(1[0-2]))(([0|1|2]\d)|3[0-1])((\d{4})|\d{3}[xX]))',
        string)
    res = []
    if idcards != []:
        for idcard in idcards:
            sumnumber = 0
            for i in range(17):
                sumnumber += int(idcard[0][i]) * coefficient[i]
            if parityBit[sumnumber % 11] == idcard[0][-1]:
                res.append(idcard[0])
        if res != []:
            return res
        else:
            return False
    else:
        return False


# 搜索敏感关键词
def search_keyword(string):
    for each in sensitive_keyword:
        if re.search(each, string, flags=re.IGNORECASE):
            return True
    return False


# 随机取key检查value是否包含敏感信息
def find_sensitive_info(ip, port, *args):
    socket.setdefaulttimeout(5)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
    except Exception as e:
        print(e)
        return False
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' %
                (len(passwd), passwd)).encode('utf-8'))
        s.recv(1024)
    s.send('*1\r\n$9\r\nRANDOMKEY\r\n'.encode('UTF-8'))
    response = s.recv(1024)

    # 判断是否为空
    if '-1' in response.decode('utf-8', 'ignore'):
        print('no keys')
        return False
    # 提取Key的值
    key_name = re.findall(b'\r\n(.*?)\r\n', response)[0].decode('utf-8', 'ignore')

    # print(key_name)
    # print('*2\r\n$3\r\nGET\r\n${key_length}\r\n{key}\r\n'.format(key_length=len(key_name),key=key_name))
    s.send(('*2\r\n$3\r\nGET\r\n${key_length}\r\n{key}\r\n'.format(
        key_length=len(key_name), key=key_name)).encode('UTF-8'))
    response = s.recv(1024)
    s.close()

    key_value = response.decode('utf-8', 'ignore')
    # print(key_value)
    
    # 判断value
    # 匹配id card number
    id_card = is_id_card(key_value)

    # 匹配mobile
    mobile = is_phone(key_value)

    # 匹配email
    email = is_email(key_value)

    # 判断key name，搜索敏感词
    sen_kw = search_keyword(key_name)

    if id_card or mobile or email or sen_kw:
        print(key_name + ': ' + key_value)
        return key_name + ': ' + key_value
    else:
        return False


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
        try:
            s.connect((ip, int(port)))
        except Exception as e:
            print(e)
            return False
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
    try:
        s.connect((ip, int(port)))
    except Exception as e:
        print(e)
        return False
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
    try:
        s.connect((ip, int(port)))
    except Exception as e:
        print(e)
        return False
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' %
                (len(passwd), passwd)).encode('utf-8'))
        s.recv(1024)
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
    try:
        s.connect((ip, int(port)))
    except Exception as e:
        print(e)
        return False
    if args:
        passwd = args[0]
        s.send(('*2\r\n$4\r\nAUTH\r\n$%s\r\n%s\r\n' %
                (len(passwd), passwd)).encode('utf-8'))
        s.recv(1024)
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
            SENSITIVE_INFO = 'NO_SENSITIVE_INFO'
            ip = each.split(',')[0].strip('"')
            port = int(each.split(',')[1].strip('"'))
            if connect_test(ip, port):
                flag = unauth_check(ip, port)
                if flag == 1:
                    UNAUTH = 'UNAUTH'
                    res = find_sensitive_info(ip, port)
                    if res:
                        SENSITIVE_INFO = res
                    if not privilege(ip, port):
                        PRIVILEGE = 'NO_ROOT'
                        if slave_rce(ip, port):
                            M_S_RCE = 'Master-Slave-RCE'
                elif flag == 0:
                    passwd = find_weak_pwd(ip, port)
                    if passwd:
                        res = find_sensitive_info(ip, port, passwd)
                        if res:
                            SENSITIVE_INFO = res
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
                            '{ip}:{port}, {UNAUTH}, password:{PASSWD}, {PRIVILEGE}, {M_S_RCE}, {SENSITIVE_INFO}\n'
                            .format(ip=ip,
                                    port=str(port),
                                    UNAUTH=UNAUTH,
                                    PASSWD=PASSWD,
                                    PRIVILEGE=PRIVILEGE,
                                    M_S_RCE=M_S_RCE,
                                    SENSITIVE_INFO=SENSITIVE_INFO))

    else:
        ip = args.host
        port = args.port
        if connect_test(ip, port):
            flag = unauth_check(ip, port)
            if flag == 1:
                find_sensitive_info(ip, port)
                if not privilege(ip, port):
                    slave_rce(ip, port)
            elif flag == 0:
                passwd = find_weak_pwd(ip, port)
                if passwd:
                    find_sensitive_info(ip, port, passwd)
                    if not privilege(ip, port, passwd):
                        slave_rce(ip, port, passwd)

    print('detection done!')
