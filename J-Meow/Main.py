import logging
import os
from configurations_operator.policies_seeker_realtime import login_inform, PoliciesSeeker, parameters_tuple

__author__ = 'bazooka'
import re

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

def ip_validate(ip):
    ip_validator = re.compile(r'^((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)$')
    if ip_validator.match(ip) != None:
        return True

    return False
def valid_parameters(tuple):
    for i in range(len(tuple.src_ip)):
        if re.match(r'^((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)$', tuple.src_ip[i]):
            tuple.src_ip[i] += '/32'
    for i in range(len(tuple.dst_ip)):
        if re.match(r'^((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)$', tuple.dst_ip[i]):
            tuple.dst_ip[i] += '/32'
    return True

def start_to_seek(login_tuple):
    while(1):
        while(1):
            print('Please input the policy you need to create \n')

            src_zone = input('The from-zone is ? \n')

            src_ip = input('The source ips are (please write in this form: 10.1.2.1/32,10.1.2.4/30...) ? \n')
            src_ip = src_ip.split(',')
            logging.debug('src_ip '+ str(src_ip))

            dst_zone = input('The to-zone is ? \n')


            dst_ip = input('The destination ips are (please write in this form: 10.1.2.1/32,10.1.2.4/30...) ? \n')
            dst_ip = dst_ip.split(',')
            logging.debug('dst_ip '+ str(dst_ip))
            application_set = []
            while(1):
                protocol = input('''The protocol is (
                1. tcp
                2. udp
                3. any
                ) ? \n''')
                if protocol == '1':
                    protocol = 'tcp'
                elif protocol == '2':
                    protocol = 'udp'
                else:
                    protocol = '0'
                logging.debug('protocol  '+ str(protocol))

                src_ports = input('The source ports are (please write in this form: 10,23,12,1-2 or any)? \n ')
                src_ports = src_ports.split(',')
                logging.debug('src_ports  '+ str(src_ports))
                dst_ports = input('The destination ports are (please write in this form: 10,23,12,1-2 or any)?  \n ')
                dst_ports = dst_ports.split(',')
                logging.debug('dst_ports  '+ str(dst_ports))
                application_set.append({protocol:{'dst-port': dst_ports, 'src-port': src_ports}})
                answer = input('More application? (Y/N)\n')
                if answer.lower() == 'n':
                    break
            print("The policy you wanna to check is following:")
            print("src_zone = '%s', src_ip = %s," %(src_zone, src_ip))
            print("dst_zone = '%s', dst_ip = %s," %(dst_zone, dst_ip))
            print("application_set = %s \n" %str(application_set))

            tuple = parameters_tuple(src_zone = src_zone, src_ip = src_ip, dst_zone = dst_zone, dst_ip = dst_ip,
                                     application_set = application_set)
            if not valid_parameters(tuple):
                print('''
                    The parameters you entered are not totally correct.
                ''')
                print('From zone "%s" to zone "%s"'%src_zone %dst_zone)
                print('Source ip are "%s" and destination ip are"%s"'%str(src_ip) %str(dst_ip))

            #start to seek

            seeker = PoliciesSeeker(login_tuple)
            #  local configuration
            # if os.path.isfile('./configurations/' + str(host)):
            #     seeker.load_conf(str(host))
            #     seeker.load_app_default()

            #  remote configuration
            seeker.load_app_default()

            policies = seeker.seek_with_two_equal(tuple)
            assert isinstance(policies, list)
            if policies is None or len(policies) != 0:
                seeker.fetch_policies(policies, tuple.src_zone, tuple.dst_zone)
            else:
                print('there is no policies to be modified')

            answer = input('Any more policy you wanna check on this device? (Y/N)')
            if answer.lower() == 'n':
                return

if __name__ == '__main__':
    print('''
Hello, this is J-Meom, this software is to help you create change script for SRX firewall.
you can input the policy parameters you want to integrate with into the box, please have a try NOW!
    ''')
    while(1):
        host = input('Where do you want J-Meow to search ? \n')
        if host == 'exit':
            exit(0)
        else:
            if ip_validate(host):
                login_tuple = login_inform(host)
                start_to_seek(login_tuple)
            else:
                print('\n\n Please input something like this "10.1.1.1"!! \n')
