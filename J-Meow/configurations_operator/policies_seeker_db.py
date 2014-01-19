import logging
import netaddr
from configurations_operator.policies_seeker_structure import LoginInform, db_login_info
from configurations_operator.policies_seeker_structure import ParametersTuple
from configurations_operator.policies_seeker_realtime import PoliciesSeeker
import data_sources.mysql_operator
import jonus_parse.configuration_soup

__author__ = 'bazooka'

class PoliciesSeekerWithDB(PoliciesSeeker):
    prefix_zone_map_dict = {}
    def __init__(self, login_tuple, debug_flag):
        self.conf = jonus_parse.configuration_soup.ConfigurationSoup()
        self.host = login_tuple.host
        self.load_conf(self.host)
        self.load_app_default()
        self.init_prefix_zone_map()
        logging.debug('The configuration | default app | prefix_zone_map are all ready!!!')

    def seek_with_equal(self, parameters_tuple):
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
            parameters_tuple.src_ip) if parameters_tuple.src_zone is None else parameters_tuple.src_zone
        dst_zone = self.get_zone(
            parameters_tuple.dst_ip) if parameters_tuple.dst_zone is None else parameters_tuple.dst_zone

        policies_to_insert_list = []
        policies_exists_list = []

        if parameters_tuple.valid():

            src_hit_policy = {}
            dst_hit_policy = {}
            application_hit_policy = {}

            sql_insertor = data_sources.mysql_operator.MysqlOperator(db_login_info.host, db_login_info.username, db_login_info.password, db_login_info.scheme)

            src_hit_policy = set(sql_insertor.search_policy_by_ip(host, src_ip= parameters_tuple.src_ip, from_zone=src_zone, to_zone=dst_zone))
            logging.debug('The hit policies matched by source address are ' + str(src_hit_policy))

            dst_hit_policy = set(sql_insertor.search_policy_by_ip(host, dst_ip= parameters_tuple.dst_ip, from_zone=src_zone, to_zone=dst_zone))
            logging.debug('The hit policies matched by destination address are ' + str(dst_hit_policy))

            for protocol, content in parameters_tuple.application.items():
                content['src-port'].sort(key=lambda x:0 if x=='any' else x)
                content['dst-port'].sort(key=lambda x:0 if x=='any' else x)

            application_hit_policy = set(sql_insertor.search_policy_by_app(host, application=parameters_tuple.application, from_zone=src_zone, to_zone=dst_zone))
            logging.debug('The hit policies matched by application are ' + str(application_hit_policy))

            three_equal_set = application_hit_policy & dst_hit_policy & src_hit_policy

            two_equal_set = (application_hit_policy & dst_hit_policy) | (application_hit_policy & src_hit_policy) | (dst_hit_policy & src_hit_policy)
            two_equal_set = two_equal_set - three_equal_set

            for (id, policy_name) in three_equal_set:
                policies_exists_list.append(policy_name)
            for (id, policy_name) in two_equal_set:
                policies_to_insert_list.append(policy_name)

            logging.debug('The existed match policies are ' + str(policies_exists_list))
            logging.debug('The policies to be inserted into are' + str(policies_to_insert_list))

            return policies_to_insert_list, policies_exists_list


        else:
            logging.error("The input message has some thing wrong" + str(parameters_tuple.application))
            return None



if __name__ == '__main__':
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
    # tuple = ParametersTuple(src_zone='untrust', src_ip=['10.0.0.0/8', '12.0.0.0/8', '13.0.0.0/8'],
    #                         dst_zone='trust', dst_ip=['10.1.48.190/32'],
    #                         application_set=[{'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]
    # )
    tuple = ParametersTuple(src_ip=['10.0.0.0/8', '12.0.0.0/8', '13.0.0.0/8'], dst_ip=['10.1.48.190/32'],
                        application_set=[{'tcp': {'dst-port': ['80'], 'src-port': ['any']}}]
    )
    seeker = PoliciesSeekerWithDB(login_tuple, debug_flag=True)
    seeker.seek_with_equal(tuple)
    # policies = seeker.seek_with_two_equal(tuple)
    # seeker.fetch_policies(policies, seeker.get_zone(tuple.src_ip), seeker.get_zone(tuple.dst_ip))