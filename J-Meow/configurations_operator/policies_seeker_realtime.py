'''
Created on Dec 17, 2013

@author: bazooka
'''
import inspect
import logging
import os

from netaddr.ip.sets import IPSet

from jonus_parse.configuration_soup import ConfigurationSoup
from connection_libs.telnet_connection import telnet_connection
from configurations_operator.policies_seeker_structure import LoginInform
from configurations_operator.policies_seeker_structure import ParametersTuple

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


class PoliciesSeeker(object):
    """
    This class is for seeking specific policies.
    """


    def __init__(self, login_inform, debug_flag):
        """
        Constructor
        """
        self.loging_inform = login_inform
        self.conf = ConfigurationSoup()
        if debug_flag is not True:
            with telnet_connection(host=self.loging_inform.host,
                                   port=self.loging_inform.port,
                                   username=self.loging_inform.username,
                                   password=self.loging_inform.password,
                                   finish=self.loging_inform.finish) as session:
                configuration = session.commit('show configuration')
                self.conf.get_whole_conf(configuration)

                default_app_text = session.commit('show configuration groups junos-defaults applications')
                self.conf.get_default_app(default_app_text)


    def get_zone(self, ip_list):
        """
        To get zone name of ip from the map initiated in the init function.
        @param ip:
        @return: The security zone name of the ip address belongs to
        """
        try:
            ip = IPSet(ip_list)
            for prefix, zone in self.prefix_zone_map_dict.items():
                if prefix == '0.0.0.0/0':            # prevent the ip trapped in the default route
                    last_hope = zone
                    continue
                if ip.issubset(IPSet([prefix])):
                    return zone
            return last_hope
        except Exception as e:
            logging.error('In get_zone function, the ip is '+str(ip))
            return None


    def load_conf(self, host):
        # '''
        #     For debug
        # '''
        self.host = host
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
            Read the application default information from file.
        """
        invoker_path = os.getcwd()
        this_file_path = os.path.abspath(os.path.dirname((inspect.getfile(inspect.currentframe()))))
        os.chdir(this_file_path)              #change current path to this file.

        file_name = '../configurations/default_applications'
        if os.path.isfile(file_name):
            with open(file_name, 'r') as file:
                try:
                    app_text = file.read()
                    if self.conf.get_default_app(app_text) is not None:
                        logging.debug('This default applications have been loaded')
                    if self.conf.merge_conf_with_default_app():
                        logging.debug('The current configuration has merged with default applications')
                except IOError:
                    logging.error('An error occurs when opening the file ' + file_name)
        else:
            logging.error('The file: ' + file_name + 'does not exist')

        os.chdir(invoker_path)           # change the current path back

    def init_prefix_zone_map(self):
        """
            Populate the prefix_zone_map_dict object
        """
        static_route_map_dict = self.conf.analyse_route_IP()
        interfaces_IP_dict = self.conf.analyse_interfaces_IP()
        interfaces_zone_map_dict = self.conf.analyse_interfaces_security_zone()
        #  Merge the connected route items into route table.
        route_map_dict = static_route_map_dict.copy()
        for interface_ip in interfaces_IP_dict.values():
            route_map_dict[interface_ip] = IPSet([interface_ip])
        logging.debug('The route prefix and next-hop map is' + str(route_map_dict))

        self.prefix_zone_map_dict = {}
        for prefix, next_hop in route_map_dict.items():
            for interface_name, ip in interfaces_IP_dict.items():
                ip = IPSet([ip])
                if next_hop.issubset(ip) and interfaces_zone_map_dict[interface_name]:
                    zone = interfaces_zone_map_dict[interface_name]
                    self.prefix_zone_map_dict[prefix] = zone
        logging.debug('The prefix_zone_map_dict is initiated: ' + str(self.prefix_zone_map_dict))


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

        src_zone = self.get_zone(
            parameters_tuple.src_ip) if not parameters_tuple.src_zone else parameters_tuple.src_zone
        dst_zone = self.get_zone(
            parameters_tuple.dst_ip) if not parameters_tuple.dst_zone else parameters_tuple.dst_zone

        policies_to_add_list = []

        if parameters_tuple.valid():
            policies_list = self.conf.analyse_policies(src_zone, dst_zone)
            logging.debug('All policies are ' + str(policies_list))
            application_dict = self.conf.analyse_policies_applications(policies_list, src_zone, dst_zone)
            logging.debug('The policies map is' + str(application_dict))

            hit_policy = []
            for policy, policy_app in application_dict.items():
                # if policy_app == {}:  # application any
                #     continue
                if set(parameters_tuple.application.keys()) == set(policy_app.keys()):
                    for protocol, tunnel in parameters_tuple.application.items():
                        policy_tunnel = policy_app[protocol]
                        policy_tunnel['src-port'].sort(key=lambda x:0 if x=='any' else x)
                        policy_tunnel['dst-port'].sort(key=lambda x:0 if x=='any' else x)
                        if policy_tunnel['src-port'] != tunnel['src-port'] or policy_tunnel['dst-port'] != tunnel['dst-port']:
                            continue
                        hit_policy.append(policy)
            logging.debug('The hit policies matched by application are ' + str(hit_policy))

            policy_address = self.conf.analyse_policies_address(hit_policy, src_zone, dst_zone)
            for policy in hit_policy:
                src_address = policy_address[policy]['src_address']
                dst_address = policy_address[policy]['dst_address']
                if src_address == parameters_tuple.src_ip or dst_address == parameters_tuple.dst_ip:
                    policies_to_add_list.append(policy)
                    #App and one address is hit:
            logging.debug('The first-round hit policies to be modified are ' + str(policies_to_add_list))

            #   unchosen policies
            for policy in hit_policy:
                policies_list.remove(policy)

            policy_address = self.conf.analyse_policies_address(policies_list, src_zone, dst_zone)
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

    def fetch_policies(self, policies_list, from_zone, to_zone):
        print('The policies can be used to add the new policy are below:')
        for policy in policies_list:
            print(self.conf.get_policy(policy, from_zone, to_zone))
            print('------------------------------------------------')


if __name__ == '__main__':
#     login_tuple = login_inform(host = '192.168.0.200')
#     login_tuple = login_inform(host = '100.100.100.254')
#     tuple = parameters_tuple(src_zone = 'untrust', src_ip = ['100.1.4.2/32', '100.1.2.0/24'],\
#                              dst_zone = 'trust', dst_ip = ['10.1.3.0/30'],\
#                              application_set = [{'tcp': {'dst-port': ['20'], 'src-port': ['5-20']}},\
#                                                 {'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]\
#                              )
    host = '10.1.66.22'
    login_tuple = LoginInform(host=host)
    # tuple = parameters_tuple(src_zone = 'trust', src_ip = ['10.1.3.28/32', '10.1.3.26/32', '10.1.3.27/32'],
    #                      dst_zone = 'untrust', dst_ip = ['58.68.253.60/32'],
    #                      application_set = [{'tcp': {'dst-port': ['443'], 'src-port': ['any']}},
    #                                         {'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]
    #                      )
    # tuple = parameters_tuple(src_zone = 'trust', src_ip = ['10.1.3.42/32', '10.1.3.43/32'],
    #                      dst_zone = 'untrust', dst_ip = ['any'],
    #                      application_set = [{'tcp': {'dst-port': ['any'], 'src-port': ['any']}}]
    #                      )
    tuple = ParametersTuple(src_zone='untrust', src_ip=['10.0.0.0/8', '12.0.0.0/8', '13.0.0.0/8'],
                            dst_zone='trust', dst_ip=['10.1.48.190/32'],
                            application_set=[{'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]
    )
    seeker = PoliciesSeeker(login_tuple, debug_flag=True)

    seeker.load_conf(host)
    seeker.load_app_default()
    seeker.init_prefix_zone_map()
    # policies = seeker.seek_with_two_equal(tuple)
    # seeker.fetch_policies(policies, seeker.get_zone(tuple.src_ip), seeker.get_zone(tuple.dst_ip))
    
         
         
        