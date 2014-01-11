import inspect
import logging
import configurations_operator.policies_seeker_realtime

__author__ = 'root'
import os


def conf_file_writer(host='10.1.35.98', username='pbro', password=''):
    os.mkdir('./configurations') if not os.path.exists('./configurations') else None
    login_info = configurations_operator.policies_seeker_realtime.login_inform(host, username=username, password=password)
    seeker = configurations_operator.policies_seeker_realtime.PoliciesSeeker(login_info)
    with open('./configurations/' + str(host), 'w+') as file:
        print(seeker.export_conf())
        file.write(seeker.export_conf())


def default_app_read(host='10.1.35.98', username='test', password='test123'):
    os.mkdir('./configurations') if not os.path.exists('./configurations') else None
    login_info = configurations_operator.policies_seeker_realtime.login_inform(host, username=username, password=password)
    seeker = configurations_operator.policies_seeker_realtime.PoliciesSeeker(login_info)
    with open('./configurations/default_applications', 'w+') as file:
        print(seeker.export_default_app())
        file.write(seeker.export_default_app())

def conf_load_db(self, host):
    # '''
    #     Load configuration into DB
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




    default_app_read(host='100.100.100.254')