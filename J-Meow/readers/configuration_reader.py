import inspect
import logging
import configurations_operator.policies_seeker_realtime
from configurations_operator.policies_seeker_structure import LoginInform, db_login_info
import data_sources.mysql_operator
import jonus_parse.configuration_soup

__author__ = 'root'
import os


def conf_file_writer(host='10.1.35.98', username='pbro', password=''):
    """
    Get configuration from targeted device
    @param host:
    @param username:
    @param password:
    @return:
    """
    os.mkdir('./configurations') if not os.path.exists('./configurations') else None
    login_info = LoginInform(host, username=username, password=password)
    seeker = configurations_operator.policies_seeker_realtime.PoliciesSeeker(login_info)
    with open('./configurations/' + str(host), 'w+') as file:
        print(seeker.export_conf())
        file.write(seeker.export_conf())


def default_app_read(host='10.1.35.98', username='test', password='test123'):
    """
    Get default application from targeted device.
    @param host: the device to get configuration from.
    @param username:
    @param password:
    @return:
    """
    os.mkdir('./configurations') if not os.path.exists('./configurations') else None
    login_info = LoginInform(host, username=username, password=password)
    seeker = configurations_operator.policies_seeker_realtime.PoliciesSeeker(login_info)
    with open('./configurations/default_applications', 'w+') as file:
        print(seeker.export_default_app())
        file.write(seeker.export_default_app())

def conf_load_db(host):
    # '''
    #     Load configuration into DB
    # '''
    conf_soup = jonus_parse.configuration_soup.ConfigurationSoup()

    sql_insertor = data_sources.mysql_operator.MysqlOperator(db_login_info.host, db_login_info.username, db_login_info.password, db_login_info.scheme)

    invoker_path = os.getcwd()
    this_file_path = os.path.abspath(os.path.dirname((inspect.getfile(inspect.currentframe()))))
    os.chdir(this_file_path)              # change the current path to this file.
    file_name = '../configurations/' + str(host)
    if os.path.isfile(file_name):
        with open(file_name, 'r') as file:
            try:
                conf_text = file.read()
                conf_soup.get_whole_conf(conf_text)
            except IOError:
                logging.error('An error occurs when opening the file ' + file_name)
    else:
        logging.error('The file: ' + file_name + 'does not exist')

    file_name = '../configurations/default_applications'
    if os.path.isfile(file_name):
        with open(file_name, 'r') as file:
            try:
                app_text = file.read()
                if conf_soup.get_default_app(app_text) is not None:
                    logging.debug('This default applications have been loaded')
                if conf_soup.merge_conf_with_default_app():
                    logging.debug('The current configuration has merged with default applications')
            except IOError:
                logging.error('An error occurs when opening the file ' + file_name)
    else:
        logging.error('The file: ' + file_name + 'does not exist')

    os.chdir(invoker_path)           # change the current path back

    #start to process content of the configuration.

    relationship_list = conf_soup.get_security_zone_relationship()
    for relationship in relationship_list:
        (src_zone, dst_zone) = relationship
        policies_list = conf_soup.analyse_policies(src_zone, dst_zone)
        logging.debug('All policies from '+ src_zone +' to '+ dst_zone +' are ' + str(policies_list))
        policy_content = conf_soup.analyse_policies_info(policies_list, src_zone, dst_zone, ['address_getter', 'application_getter'])
        logging.debug('The policies content map is' + str(policy_content))
        # start to insert the record into database


        for policy in policies_list:

            sql_insertor.add_policy(host, policy, policy_content[policy]['src_address'],
                                    policy_content[policy]['dst_address'], src_zone, dst_zone, 'permit')
            application = policy_content[policy]['application']
            sql_insertor.add_application(host, policy, src_zone, dst_zone, application)
    logging.info('The device '+ host +'database loading has finished')
    
if __name__ == '__main__':
    # host = '10.1.66.22'
    # login_tuple = configurations_operator.policies_seeker.login_inform(host = host, username = 'pbro', password = 'Page3of5')
    # tuple = configurations_operator.policies_seeker.parameters_tuple(src_zone = 'untrust',
    # src_ip = ['124.193.138.58/32', '221.192.235.85/32', '114.242.222.114/32'], \
    #                          dst_zone = 'trust', dst_ip = ['10.1.3.28/32'],  \
    #                          application_set = [{'tcp': {'dst-port': ['808'], 'src-port': ['any']}}]
    #                          )
    # seeker = configurations_operator.policies_seeker.policies_seeker(login_tuple)
    # conf_file_writer(host)

    # seeker.load_conf(host)




    # policies = seeker.seek_with_two_equal(tuple)
    # seeker.fetch_policies(policies, tuple.src_zone, tuple.dst_zone)


    conf_load_db(host='10.1.35.98')
    conf_load_db(host='10.1.66.22')
