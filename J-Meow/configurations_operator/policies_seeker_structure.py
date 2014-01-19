import logging
import re
from netaddr import IPSet
from jonus_parse.configuration_soup import port_cal

__author__ = 'bazooka'


class ParametersTuple(object):
    """
    A structure to store the searching information
    """

    def __merge(self, dict1={}, dict2={}):
        """
        In recursive dict, merge the leaf list by list.extend method.
        """
        for key, val in dict2.items():
            if key in dict1.keys():
                if isinstance(val, list):
                    dict1[key].extend(val)
                else:
                    self.__merge(dict1[key], val)
            else:
                dict1[key] = val
        return dict1


    def __init__(self, src_ip='any', src_zone=None, dst_ip='any', dst_zone=None,
                 application_set=[]):

        self.src_ip = src_ip
        self.src_zone = src_zone
        self.dst_ip = dst_ip
        self.dst_zone = dst_zone
        applications = {}
        for application in application_set:
            applications = self.__merge(applications, application)
        self.application = applications

    def valid(self):
        """
        Make sure the input parameters class stick to the form of below example
        parameters_tuple(src_zone = 'untrust', src_ip = ['100.1.4.2/32', '100.1.2.0/24'],
                             dst_zone = 'trust', dst_ip = ['10.1.3.0/30'],
                             application = {'tcp': {'dst-port': ['80', '20'], 'src-port': ['any', '5-20']}}
                             )
        """

        def ip_validate(ip):
            ip_validator = re.compile('^((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)/(\d{1,2})$')
            if ip_validator.match(ip) != None and int(ip_validator.match(ip).groups()[3]) <= 32:
                return True

            return False

        def application_validate(application):
            """
                Unfold the ports from 1-3 to [1,2,3], keep 'any' in it origin form
            """
            try:
                for tuple in application.values():
                    if not isinstance(tuple, dict) or not isinstance(tuple['src-port'], list) or not isinstance(
                            tuple['dst-port'], list):
                        return False

                    src_port_list = []
                    for port in tuple['src-port']:
                        if not port_validate(port):
                            return False
                        src_port_list.extend(port_cal(port))
                    tuple['src-port'] = src_port_list

                    dst_port_list = []
                    for port in tuple['dst-port']:
                        if not port_validate(port):
                            return False
                        dst_port_list.extend(port_cal(port))
                    tuple['dst-port'] = dst_port_list
            except Exception as e:
                logging.warn(str(application) + ' is not a valid application input, and the error is "' + str(e) + '"')
                return False
            else:
                return True

        def port_validate(port):
            port_validator = re.compile(r'(\d+-\d+)|(\d*)|any')
            if port_validator.match(port) is None:
                return False
            return True

        src_ip = IPSet([])
        for ip in self.src_ip:
            if ip == 'any':
                ip = '0.0.0.0/0'
            if not ip_validate(ip):
                return False
            src_ip.add(ip)
        self.src_ip = src_ip

        dst_ip = IPSet([])
        for ip in self.dst_ip:
            if ip == 'any':
                ip = '0.0.0.0/0'
            if not ip_validate(ip):
                return False
            dst_ip.add(ip)
        self.dst_ip = dst_ip

        if not application_validate(self.application):
            return False

        return True


class LoginInform:
    """
    A structure to store the login information
    """

    def __init__(self, host='100.100.100.254', port=23, username='test', password='test123', finish='SRX'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.finish = finish

    def populate(self, dict):
        self.host = dict['host']
        self.port = dict['port']
        self.username = dict['username']
        self.password = dict['password']

class DBLoginInform:
    """
    A structure to store the login information
    """

    def __init__(self, host='100.100.100.254', port=23, username='test', password='test123', scheme='test'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.scheme = scheme

    def populate(self, dict):
        self.host = dict['host']
        self.port = dict['port']
        self.username = dict['username']
        self.password = dict['password']

db_login_info = DBLoginInform(host='localhost', username='J-MEOW',password='', scheme='test' )