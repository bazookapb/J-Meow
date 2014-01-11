'''
Created on Dec 17, 2013

@author: bazooka
'''
import inspect
import logging
import os
import re

from netaddr.ip.sets import IPSet

from jonus_parse.ConfigurationSoup import ConfigurationSoup, port_cal
from connection_libs.telnet_connection import telnet_connection


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

class PoliciesSeeker(object):
    """
    This class is for seeking specific policies.
    """
    

    def __init__(self, login_inform):
        '''
        Constructor
        '''
        self.loging_inform = login_inform
        with telnet_connection(host = self.loging_inform.host, 
                       port = self.loging_inform.port, 
                       username = self.loging_inform.username, 
                       password = self.loging_inform.password, 
                       finish = self.loging_inform.finish) as session:
            self.conf = ConfigurationSoup(session)
            self.conf.get_whole_conf()

    def export_conf(self):
        '''
            For debug
        '''
        with telnet_connection(host = self.loging_inform.host,
                   port = self.loging_inform.port,
                   username = self.loging_inform.username,
                   password = self.loging_inform.password,
                   finish = self.loging_inform.finish) as session:
            self.conf = ConfigurationSoup(session)
            return self.conf.get_whole_conf()

    def export_default_app(self):
        '''
        Return the Junos application setting, i.e.
        # File Transfer Protocol
        #</junos:comment>
                <application>
                    <name>junos-ftp</name>
                    <application-protocol>ftp</application-protocol>
                    <protocol>tcp</protocol>
                    <destination-port>21</destination-port>
                </application>
        <junos:comment>#

        '''
        with telnet_connection(host = self.loging_inform.host,
                   port = self.loging_inform.port,
                   username = self.loging_inform.username,
                   password = self.loging_inform.password,
                   finish = self.loging_inform.finish) as session:
            self.conf = ConfigurationSoup(session)
            return self.conf.get_default_app()


    def load_conf(self, host):
        # '''
        #     For debug
        # '''
        invoker_path = os.getcwd()
        this_file_path = os.path.abspath(os.path.dirname((inspect.getfile(inspect.currentframe()))))
        os.chdir(this_file_path)              # change the current path to this file.
        file_name = '../configurations/' + str(host)
        if os.path.isfile(file_name):
            with open(file_name, 'r') as file:
                try:
                    conf_text = file.read()
                    self.conf.get_whole_conf(conf_text)
                except IOError:
                    logging.error('An error occurs when opening the file ' + file_name)
        else:
            logging.error('The file: ' + file_name + 'does not exist')

        os.chdir(invoker_path)           # change the current path back

    def load_app_default(self):
        """
            For debug
        """
        invoker_path = os.getcwd()
        this_file_path = os.path.abspath(os.path.dirname((inspect.getfile(inspect.currentframe()))))
        os.chdir(this_file_path)              #change current path to this file.

        file_name = '../configurations/default_applications'
        if os.path.isfile(file_name):
            with open(file_name, 'r') as file:
                try:
                    app_text = file.read()
                    if self.conf.load_default_app(app_text) is not None:
                        logging.debug('This default applications have been loaded')
                    if self.conf.merge_conf_with_default_app():
                        logging.debug('The current configuration has merged with default applications')
                except IOError:
                    logging.error('An error occurs when opening the file ' + file_name)
        else:
            logging.error('The file: ' + file_name + 'does not exist')

        os.chdir(invoker_path)           # change the current path back

    def seek_with_two_equal(self, parameters_tuple):
        """
        The input parameters should be like this.
         parameters_tuple = dict(src_ip = '', src_port = '', src_zone = 'trust', dst_ip = '10.1.3.28/32', dst_port = 'TCP-8765', dst_zone = 'untrust',
                 protocol = 'tcp')
        First: search whether the application existed.
        Second: if the application exists, checks whether source-address or destination-address fulfill the parameters_tuple's requirement,
        if so, return all the hit policies, otherwise, return None.
        Third: if the application doesn't exist, checks whether both the source-address and destionation-address fit the requirement,
        if so, return all the hit policies, otherwise, return None.
        """
        policies_to_add_list =[]
        
        if parameters_tuple.valid():
            policies_list = self.conf.analyse_policies(parameters_tuple.src_zone, parameters_tuple.dst_zone)
            logging.debug('All policies are ' + str(policies_list))
            application_dict = self.conf.analyse_policies_applications(policies_list, parameters_tuple.src_zone, parameters_tuple.dst_zone)
            logging.debug('The policies map is' + str(application_dict))
            
            hit_policy = []
            for policy, policy_app in application_dict.items():
                # if policy_app == {}:  # application any
                #     continue
                if set(parameters_tuple.application.keys()) == set(policy_app.keys()):
                    for protocol, tunnel in parameters_tuple.application.items():
                        policy_tunnel = policy_app[protocol]
                        if set(policy_tunnel['src-port']) != set(tunnel['src-port']) or \
                        set(policy_tunnel['dst-port']) != set(tunnel['dst-port']):
                            continue
                        hit_policy.append(policy)
            logging.debug('The hit policies matched by application are ' + str(hit_policy))
            
            policy_address = self.conf.analyse_policies_address(hit_policy, parameters_tuple.src_zone, parameters_tuple.dst_zone)
            for policy in hit_policy:
                src_address = policy_address[policy]['src_address']
                dst_address = policy_address[policy]['dst_address']
                if src_address == parameters_tuple.src_ip or dst_address == parameters_tuple.dst_ip:
                    policies_to_add_list.append(policy)
            #App and one address is hit:
            logging.debug('The first-round hit policies to be modified are ' + str(policies_to_add_list))
            # unchosen policies
            for policy in hit_policy:
                policies_list.remove(policy)
            
            policy_address = self.conf.analyse_policies_address(policies_list, parameters_tuple.src_zone, parameters_tuple.dst_zone)
            for policy in policies_list:
                src_address = policy_address[policy]['src_address']
                dst_address = policy_address[policy]['dst_address']
                # both requirements are meet
                if src_address == parameters_tuple.src_ip and dst_address == parameters_tuple.dst_ip:
                    policies_to_add_list.append(policy)
            #App is not hit and both address is hit:
            logging.debug('The second-round hit policies to be modified are ' + str(policies_to_add_list))
            
                    
            return policies_to_add_list
                
                    
        else:
            logging.error("The input message has some thing wrong" + str(parameters_tuple.application))
        
    def seek(self, parameters_tuple):
        '''
        The input parameters should be like this.
         parameters_tuple = dict(src_ip = '', src_port = '', src_zone = 'trust', dst_ip = '10.1.3.28/32', dst_port = 'TCP-8765', dst_zone = 'untrust',
                 protocol = 'tcp')
        First: search whether the application existed.
        Second: if the application exists, checks whether source-address or destination-address fulfill the parameters_tuple's requirement,
        if so, return all the hit policies, otherwise, return None.
        Third: if the application doesn't exist, checks whether both the source-address and destionation-address fit the requirement, 
        if so, return all the hit policies, otherwise, return None. 
        '''
        policies_to_add_list =[]
        
        if parameters_tuple.valid():
            with telnet_connection(host = self.loging_inform.host, 
                                   port = self.loging_inform.port, 
                                   username = self.loging_inform.username, 
                                   password = self.loging_inform.password, 
                                   finish = self.loging_inform.finish) as session:
                conf = ConfigurationSoup(session)
                conf.get_whole_conf()
                policies_list = conf.analyse_policies(parameters_tuple.src_zone, parameters_tuple.dst_zone)
                logging.debug('All policies are' + str(policies_list))
                application_dict = conf.analyse_policies_applications(policies_list, parameters_tuple.src_zone, parameters_tuple.dst_zone)
                logging.debug('The policies map is' + str(application_dict))
                
                hit_policy = []
                for policy, policy_app in application_dict.items():
                    if policy_app == {}:  # application any
                        hit_policy.append(policy)
                    elif set(parameters_tuple.application.keys()) == set(policy_app.keys()):
                        for protocol, tunnel in parameters_tuple.application.items():
                            policy_tunnel = policy_app[protocol]
                            if set(policy_tunnel['src-port']) != set(tunnel['src-port']) or \
                            set(policy_tunnel['dst-port']) != set(tunnel['dst-port']):
                                continue
                            hit_policy.append(policy)
                logging.debug('The hit policies matched by application are ' + str(hit_policy))
                
                policy_address = conf.analyse_policies_address(hit_policy, parameters_tuple.src_zone, parameters_tuple.dst_zone)
                for policy in hit_policy:
                    src_address = policy_address[policy]['src_address']
                    dst_address = policy_address[policy]['dst_address']
                    if src_address == parameters_tuple.src_ip or dst_address == parameters_tuple.dst_ip:
                        policies_to_add_list.append(policy)
                logging.debug('The first-round hit policies to be modified are ' + str(policies_to_add_list))
                # unchosen policies
                for policy in hit_policy:
                    policies_list.remove(policy)
                
                policy_address = conf.analyse_policies_address(policies_list, parameters_tuple.src_zone, parameters_tuple.dst_zone)
                for policy in policies_list:
                    src_address = policy_address[policy]['src_address']
                    dst_address = policy_address[policy]['dst_address']
                    # both requirements are meet
                    if src_address == parameters_tuple.src_ip and dst_address == parameters_tuple.dst_ip:
                        policies_to_add_list.append(policy)
                logging.debug('The second-round hit policies to be modified are ' + str(policies_to_add_list))
                
                        
                return policies_to_add_list
                
                    
        else:
            logging.error("The input message has some thing wrong" + str(parameters_tuple.application))
        
    def fetch_policies(self, policies_list, from_zone, to_zone):
            print('The policies can be used to add the new policy are below:')
            for policy in policies_list:
                print(self.conf.get_policy(policy, from_zone, to_zone))
                print('------------------------------------------------')
            
class login_inform:
    '''
    A structure to store the login information
    '''
    def __init__(self, host = '100.100.100.254', port = 23, username = 'test', password = 'test123' , finish = 'SRX'):
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
                    


class parameters_tuple(object):
    '''
    A structure to store the searching information
    '''
    def __merge (self, dict1 = {}, dict2 = {}):
        '''
        In recursive dict, merge the leaf list by list.extend method.
        '''
        for key, val in dict2.items():
            if key in dict1.keys():
                if isinstance(val, list):
                    dict1[key].extend(val)
                else:
                    self.__merge(dict1[key], val)
            else:
                dict1[key] = val
        return dict1


    def __init__(self, src_ip = 'any', src_zone = 'trust', dst_ip = 'any', dst_zone = 'untrust',
                 application_set = []):

        self.src_ip = src_ip
        self.src_zone = src_zone
        self.dst_ip = dst_ip
        self.dst_zone = dst_zone
        applications = {}
        for application in application_set:
            applications = self.__merge(applications, application)
        self.application = applications
        
    def valid(self):
        '''
        Make sure the input parameters class stick to the form of below example
        parameters_tuple(src_zone = 'untrust', src_ip = ['100.1.4.2/32', '100.1.2.0/24'], 
                             dst_zone = 'trust', dst_ip = ['10.1.3.0/30'],  
                             application = {'tcp': {'dst-port': ['80', '20'], 'src-port': ['any', '5-20']}}
                             )
        '''
        def ip_validate(ip):
            ip_validator = re.compile('^((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)/(\d{1,2})$')
            if ip_validator.match(ip) != None and int(ip_validator.match(ip).groups()[3]) <= 32:
                return True

            return False
            
        def application_validate(application):
            '''
                Unfold the ports from 1-3 to [1,2,3], keep 'any' in it origin form
            '''
            try: 
                for tuple  in application.values():
                    if not isinstance(tuple, dict) or not isinstance(tuple['src-port'], list) or not isinstance(tuple['dst-port'], list):
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
                logging.warn(str(application) + ' is not a valid application input, and the error is "' + str(e) +'"')
                return False
            else:
                return True
        def port_validate(port):
            port_validator = re.compile(r'(\d+-\d+)|(\d*)|any')
            if port_validator.match(port) == None:
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

        
if __name__ == '__main__':
#     login_tuple = login_inform(host = '192.168.0.200')
#     login_tuple = login_inform(host = '100.100.100.254')
#     tuple = parameters_tuple(src_zone = 'untrust', src_ip = ['100.1.4.2/32', '100.1.2.0/24'],\
#                              dst_zone = 'trust', dst_ip = ['10.1.3.0/30'],\
#                              application_set = [{'tcp': {'dst-port': ['20'], 'src-port': ['5-20']}},\
#                                                 {'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]\
#                              )
    host = '10.1.66.22'
    login_tuple = login_inform(host = host)
    # tuple = parameters_tuple(src_zone = 'trust', src_ip = ['10.1.3.28/32', '10.1.3.26/32', '10.1.3.27/32'],
    #                      dst_zone = 'untrust', dst_ip = ['58.68.253.60/32'],
    #                      application_set = [{'tcp': {'dst-port': ['443'], 'src-port': ['any']}},
    #                                         {'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]
    #                      )
    # tuple = parameters_tuple(src_zone = 'trust', src_ip = ['10.1.3.42/32', '10.1.3.43/32'],
    #                      dst_zone = 'untrust', dst_ip = ['any'],
    #                      application_set = [{'tcp': {'dst-port': ['any'], 'src-port': ['any']}}]
    #                      )
    tuple = parameters_tuple(src_zone = 'untrust', src_ip = ['10.0.0.0/8', '12.0.0.0/8', '13.0.0.0/8'],
                     dst_zone = 'trust', dst_ip = ['10.1.48.190/32'],
                     application_set = [{'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]
                     )
    seeker = PoliciesSeeker(login_tuple)

    seeker.load_conf(host)
    seeker.load_app_default()

    policies = seeker.seek_with_two_equal(tuple)
    seeker.fetch_policies(policies, tuple.src_zone, tuple.dst_zone)
    
         
         
        