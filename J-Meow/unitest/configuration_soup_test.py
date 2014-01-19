'''
Created on Dec 16, 2013

@author: bazooka
'''
import logging
import os
import unittest

from netaddr.ip.sets import IPSet

from jonus_parse.configuration_soup import ConfigurationSoup


class Test(unittest.TestCase):


    def setUp(self):
        if not hasattr(self, 'soup'):
            self.soup = ConfigurationSoup()
            file_name = '../configurations/10.1.35.98'
            if os.path.isfile(file_name):
                with open(file_name, 'r') as file:
                    try:
                        conf_text = file.read()
                        self.soup.get_whole_conf(conf_text)
                    except IOError:
                        logging.error('An error occurs when opening the file ' + file_name)
            else:
                logging.error('The file: ' + file_name + 'does not exist')

            file_name = '../configurations/default_applications'
            if os.path.isfile(file_name):
                with open(file_name, 'r') as file:
                    try:
                        app_text = file.read()
                        if self.soup.get_default_app(app_text) is not None:
                            logging.debug('This default applications have been loaded')
                        if self.soup.merge_conf_with_default_app():
                            logging.debug('The current configuration has merged with default applications')
                    except IOError:
                        logging.error('An error occurs when opening the file ' + file_name)
            else:
                logging.error('The file: ' + file_name + 'does not exist')


    
    def tearDown(self):
        pass

    #----------------------------------------------------------------- def test_


    def test_analysis_policies_applications(self):
        policies = ['WangYin','10017']
        app = self.soup.analyse_policies_applications(policies, from_zone = 'trust', to_zone = 'untrust')
        target_app = {'1000': {'tcp':{'src-port':['any'], 'dst-port':[8200]}}, '20005': {'tcp':{'src-port':['any'], 'dst-port':[8767]}}}
        self.assertDictEqual(target_app, app, ''.join(app))

    def test_analyse_policies(self):
        policies = ['10001','10011', '9']
        output = self.soup.analyse_policies('trust', 'untrust')
        for policy in policies:
            self.assertIn(policy, output, 'The output are ' + str(output)+ 'and target is ' + policy)

    def test_analyse_policies_address(self):
        policies = ['WangYin','10017']
        output = self.soup.analyse_policies_address(policies, 'trust', 'untrust')
        target = {'WangYin': {'src_address': IPSet(['192.168.13.0/24', '10.0.0.0/8']), 'dst_address': IPSet(['202.99.20.128/25'])},
                  '10017': {'src_address': IPSet(['10.1.3.42/32', '10.1.3.43/32']), 'dst_address': IPSet(['0.0.0.0/0'])}}
        self.assertDictEqual(output, target, 'some thing wrong when compare policies address:' + str(policies))

    def test_analyse_policies_info(self):
        policies = ['WangYin','10017']
        output = self.soup.analyse_policies_info(policies, 'trust', 'untrust', ['address_getter', 'application_getter'])
        # print(output)
        target = {'10017': {'application': {'0': {'dst-port': ['any'], 'src-port': ['any']}}, 'src_address': IPSet(['10.1.3.42/31']), 'dst_address': IPSet(['0.0.0.0/0'])}, 'WangYin': {'application': {'tcp': {'dst-port': [80, 8443, 443], 'src-port': ['any']}}, 'src_address': IPSet(['10.0.0.0/8', '192.168.13.0/24']), 'dst_address': IPSet(['202.99.20.128/25'])}}

        for policy, content in output.items():
            self.assertEqual(target[policy]['dst_address'], output[policy]['dst_address'])
            self.assertEqual(target[policy]['src_address'], output[policy]['src_address'])
            self.assertDictEqual(target[policy]['application'], output[policy]['application'])
        # self.assertDictEqual(output, target, 'some thing wrong when compare policies address:' + str(policies))

    def test_analyse_interfaces_IP(self):
        target = {'ae0.0': '192.168.13.2/24', 'ge-0/0/1.0': '202.99.20.134/25', 'ge-2/0/0.0': '192.168.99.173/24'}
        output = self.soup.analyse_interfaces_IP()
        # print(output)
        self.assertDictEqual(output, target, 'The interface list is not right'+str(output))

    def test_analyse_interfaces_security_zone(self):
        target = {'ge-0/0/1.0': 'untrust', 'ae0.0': 'trust', 'st0.0': 'vpn'}
        output = self.soup.analyse_interfaces_security_zone()
        self.assertDictEqual(output, target, 'The interface and security zone list is not right'+str(output))

    def test_analyse_route_IP(self):

        target = {'10.0.0.0/8': IPSet(['192.168.13.229/32']), '0.0.0.0/0': IPSet(['202.99.20.129/32']), '192.168.3.0/24': IPSet(['192.168.13.229/32'])}
        output = self.soup.analyse_route_IP()
        self.assertDictEqual(output, target, 'The interface and security zone list is not right'+str(output))
#------------------------------------------------------------------------------
    #---------------------------- def test__analysis_analysis_application(self):
        # result_dict = self.soup.analysis_analysis_application(self.__application)
        # self.assertDictEqual(result_dict, {'protocol':'tcp', 'src_port':None, 'dst_port':[8765, 8766]}, ''.join(result_dict))
#------------------------------------------------------------------------------ 
    #---------------------------------- def test_analysis_application_set(self):
        #--- result= self.soup.analysis_application_set(self.__application_set1)
        #--------------------------------------- self.assertTrue(result is None)
        #-- result = self.soup.analysis_application_set(self.__application_set2)
        #--------------- self.assertTrue(['junos-ftp', 'TCP-7301_7302'], result)
#------------------------------------------------------------------------------ 
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()