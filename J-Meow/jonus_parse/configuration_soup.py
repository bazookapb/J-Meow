"""
Created on Dec 16, 2013

@author: bazooka
"""
import logging
import re

from bs4 import BeautifulSoup
from netaddr.ip.sets import IPSet


def port_cal(ports):
    """
    Change the ports from XX/XX-XX/'any' into list form
    """
    if re.match('^\d+-\d+$', ports):
        if ports == '0-65535':
            return ['any']
        start_num, end_num = ports.split(sep='-', maxsplit=1)

        start_num = int(start_num)
        end_num = int(end_num)

        min_num = min(start_num, end_num)
        max_num = max(start_num, end_num)
        if min_num != max_num:
            result = []
            for port in range(int(min_num), int(max_num) + 1):
                result.append(port)
            return result
        else:
            return [int(min_num)]
    elif re.match('^\d+$', ports):
        return [int(ports)]
    else:
        return [ports]


class ConfigurationSoup(object):
    """
    class docs
    """


    def __init__(self, session=None):
        """
        session is a connection to get configuration
        @param session:
        """
        self.__session = session

    def __extract_deny_policy(self, xml):
        """
            To delete all deny policies from the configuration xml.
        """
        deny_tag = xml.find_all(name='deny')
        for tag in deny_tag:
            tag.parent.parent.extract()


    def __extract_inactive_policy(self, xml):
        """
            To delete all inactive policies from the configuration xml.
        """
        inactive_tag = xml.find_all(inactive='inactive')
        for tag in inactive_tag:
            tag.extract()

    def __check_config(fun):
        def new(self, *arg, **kwargs):
            if self.__default_app_xml is None or self.__configuration_xml is None:
                logging.critical('configuration file is not loaded correctly into this object')
                return None
            else:
                return fun(self, *arg, **kwargs)

        return new

    def get_whole_conf(self, configuration=None):
        """
            To get the configuration from end-point via connection, you can use the 'configuration' input parameter for debug purpose.
        """
        if configuration == None:
            configuration = self.__session.commit('show configuration')
            # did not want a incompleted configuration
        if re.search(r'</rpc-reply>\s*$', configuration) == None:
            self.__configuration_xml = None
            return None
        self.__configuration_xml = BeautifulSoup(configuration)
        return configuration

    def get_default_app(self):
        """
            To get the Junos application configuration from end-point via connection, you can use the 'configuration' input parameter for debug purpose.
        """
        default_app_text = self.__session.commit('show configuration groups junos-defaults applications')

        # did not want a completed configuration
        if re.search(r'</rpc-reply>\s*$', default_apps) == None:
            self.__default_app_xml = None
            return None
        self.__default_app_xml = BeautifulSoup(default_app_text)
        return default_app_text

    def load_default_app(self, default_app_text):
        # did not want an incompleted configuration
        if re.search(r'</rpc-reply>\s*$', default_app_text) == None:
            self.__default_app_xml = None
            return None
        self.__default_app_xml = BeautifulSoup(default_app_text)
        return default_app_text


    def merge_conf_with_default_app(self):
        """
        insert the __default_app_xml into __configuration_xml
        @return: the merge result flag
        """
        if self.__default_app_xml is not None and self.__configuration_xml is not None:
            application_set_list = self.__default_app_xml.applications.find_all(name='application-set')

            for application_set in application_set_list:
                self.__configuration_xml.applications.find(name='application-set').insert_before(
                    application_set) # Merge application-set into current conf

            def find_applications_not_under_application_set(tag):
                if tag.name == 'application' and tag.parent.name != 'application-set':
                    return True
                return False

            application_list = self.__default_app_xml.applications.find_all(find_applications_not_under_application_set)
            for application in application_list:
                self.__configuration_xml.applications.find(name='application').insert_before(
                    application) # Merge application into current conf
                # print(self.__configuration_xml.prettify())
            return True
        else:
            return False

    @__check_config
    def analyse_policies(self, from_zone='untrust', to_zone='trust'):
        """
            To get all policy names from the configuration xml
            output: policies' name list
        """

        def child_has_correct_zone_direction(tag):
            if len(tag.contents) > 3 and tag.contents[1].name == 'from-zone-name' and tag.contents[
                3].name == 'to-zone-name':
                return tag.contents[1].text == from_zone and tag.contents[3].text == to_zone
            else:
                return False

        policies = []
        policies_set_xml = self.__configuration_xml.policies.find(child_has_correct_zone_direction)
        self.__extract_deny_policy(policies_set_xml)
        self.__extract_inactive_policy(policies_set_xml)
        names = policies_set_xml.find_all(name='name')
        for name in names:
            policies.append(name.string)
        return policies

    @__check_config
    def analyse_applications(self):
        """
            To get all applications'/application-sets' names from the configuration xml
            output: applications' name list
        """

        def applications_not_under_application_set(tag):
            if tag.name == 'application-set':
                return True
            elif tag.name == 'application' and tag.parent.name != 'application-set': # clear the application which is under the application set
                return True
            else:
                return False

        applications_list = []
        application_set_xml = self.__configuration_xml.applications.find_all(applications_not_under_application_set)
        names = application_set_xml.find(name='name')
        for name in names:
            applications_list.append(name.string)
        return applications_list

    @__check_config
    def get_policy(self, policy, from_zone='untrust', to_zone='trust', ):
        '''
        Return all the policy xml arch.
        '''
        return self.__configuration_xml.policies.find(name = 'name', text = policy).parent

    @__check_config
    def analyse_policies_address(self, policies=[], from_zone='untrust', to_zome='trust'):
        """
        Input: policy name list
            Get the source and destination addresses related to a policy
        Output: list(policy: {src_address:IPSet([]), dst_address:IPSet([]) })
        """

        def get_addr_info(addrs=[], zone_name='untrust'):
            """
            Input: Address names list
            A recursive method to get address from address-set
            Output: A generator which return addresses belong to a policy
            """
            for addr in addrs:
                ip = addr.text
                if ip == 'any':
                    ip = '0.0.0.0/0'
                    yield ip
                else:
                    try:
                        security_zone = self.__configuration_xml.zones.find(name='name', text=zone_name).parent
                        address_xml = security_zone.find(name='name', text=ip).parent
                    except AttributeError as e:
                        logging.warn("cannot find the address :" + ip)
                        return None
                    else:
                        if address_xml.name == 'address':
                            yield address_xml.find('ip-prefix').text
                        elif address_xml.name == 'address-set':
                            address_members = address_xml.find_all(name='address')
                            member_list = []
                            for member in address_members:
                                member_list.append(member.find(name='name'))
                            for address in get_addr_info(member_list, zone_name):
                                yield address
                        else:
                            logging.warn(address_xml.name + 'is not an address/address set')

        def summarize_addr_info(addr_tuple):
            """
            Use the netaddr.IPSet lib to do the clear dupilcated work.
            """
            result_list = IPSet([])
            if addr_tuple is not None:
                for addr in addr_tuple:
                    result_list.add(addr)
            return result_list

        result_dict = {}
        for policy in policies:
            policy_temp = self.__configuration_xml.policies.find(text=policy)
            if policy_temp is None:
                logging.warn('No such a policy: ' + policy + 'from ' + from_zone + ' to ' + to_zome)
                continue
            policy_xml = policy_temp.parent.parent  # Get the policy xml.
            if policy_xml.parent.find('from-zone-name').text == from_zone and policy_xml.parent.find(
                    'to-zone-name').text == to_zome:
                src_addr = policy_xml.find_all(name='source-address')
                dst_addr = policy_xml.find_all(name='destination-address')

                addr_tuple = []
                addr_tuple = get_addr_info(src_addr, from_zone)
                result_dict[policy] = {'src_address': summarize_addr_info(addr_tuple)}

                addr_tuple = []
                addr_tuple = get_addr_info(dst_addr, to_zome)
                result_dict[policy].update({'dst_address': summarize_addr_info(addr_tuple)})

        logging.debug('The addresses summary result is ' + str(result_dict))
        return result_dict

    @__check_config
    def analyse_policies_applications(self, policies=[], from_zone='untrust', to_zone='trust'):
        """
        Input: policy name list
            Get the application structure related to a policy, grouped by policy name.
        Output: dict(policy: {protocol:{dst-port:[], src-port:[]}})
        """

        result_dict = {}
        for policy in policies:
            policy_xml = self.__configuration_xml.policies.find(text=policy).parent.parent  # Get the policy xml.
            if policy_xml.parent.find('from-zone-name').text == from_zone and policy_xml.parent.find(
                    'to-zone-name').text == to_zone:
                applications = policy_xml.find_all(name='application')
                app_tuple = []   # tuple to store the application information.   
                app_tuple = self.__get_application_info(applications)
                result_dict[policy] = ConfigurationSoup.__summarize_application_info(app_tuple)
        return result_dict

    @__check_config
    def is_in_application(self, application=[]):
        pass

    @__check_config
    def is_in_address_book(self, from_zone='untrust', to_zone='trust', address='0.0.0.0/0'):
        pass

    @__check_config
    def __get_application_info(self, applications=[]):
        """
        Input: Application names list
        A recursive method to get applications from application-set
        NOT SUPPORT APPLICATION-SET IN DEFAULT APPLICATION CONFIGURATION
        Output: A generator which return applications belong to a policy
        """
        for app in applications:
            try:
                app_name_xml = self.__configuration_xml.applications.find(name='name', text=app.text)
                # if app_name_xml is None or app_name_xml.parent.parent.name == 'application-set':
                # search in the default configuration
                # if self.__default_app_xml is not None:
                #     app_name_xml = self.__default_app_xml.applications.find(name='name', text=app.text)
                # else:
                #     raise AttributeError

                app_xml = app_name_xml.parent

            except AttributeError as e:
                logging.warn("cannot find the app number :" + app.text)
            else:
                if app_xml.name == 'application':
                    yield app_xml
                elif app_xml.name == 'application-set':
                    app_member = app_xml.find_all(name='application')
                    member_list = []
                    for member in app_member:
                        member_list.append(member.find(name='name'))
                    for member_app in self.__get_application_info(member_list):
                        yield member_app
                else:
                    logging.info(app_xml.name + 'is not a application/application set')


    @classmethod
    def __summarize_application_info(cls, applications=[]):
        """
        [input: <application>
                <name>TCP-test</name>
                <protocol>tcp</protocol>
                <source-port>5</source-port>
                <destination-port>20</destination-port>
                </application>
        <application>
        <name>junos-dns-tcp</name>
            <term>
                <name>t1</name>
                <alg>dns</alg>
                <protocol>tcp</protocol>
                <destination-port>53</destination-port>
            </term>
        </application>
        process the application structure and delete duplicated port for outputing a dict structure which is grouped by protocol name, i.e. tcp
        output: {protocol:{src-port:[xx,xxx,'any']}, ...}
        """
        try:
            app_dict = {}
            for app in applications:
                protocol = app.protocol.text
                if protocol in ['tcp', 'udp', '0']:
                    src_port_xml = app.find("source-port")
                    src_port = port_cal(src_port_xml.text) if src_port_xml is not None else ['any']
                    dst_port_xml = app.find("destination-port")
                    dst_port = port_cal(dst_port_xml.text) if dst_port_xml is not None else ['any']

                    if protocol not in app_dict:
                        app_dict[protocol] = {'src-port': src_port, 'dst-port': dst_port}
                    else:
                        app_dict[protocol]['src-port'].extend(src_port) # kill the duplicated numbers
                        app_dict[protocol]['src-port'] = list(set(app_dict[protocol]['src-port']))
                        app_dict[protocol]['dst-port'].extend(dst_port)
                        app_dict[protocol]['dst-port'] = list(set(app_dict[protocol]['dst-port']))
            return app_dict
        except Exception as e:
            logging.warn('The problem app is \n' + str(app))
            return {}


if __name__ == '__main__':
    configuration = '''
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/12.1X44/junos">
    <configuration junos:commit-seconds="1387695751" junos:commit-localtime="2013-12-22 07:02:31 UTC" junos:commit-user="root">
            <version>12.1X44.4</version>
            <system>
                <host-name>Pang</host-name>
                <root-authentication>
                    <encrypted-password>$1$K.m1eKhb$VxY64FCv9iXANnkNgqtmv0</encrypted-password>
                </root-authentication>
                <login>
                    <user>
                        <name>admin</name>
                        <uid>2000</uid>
                        <class>super-user</class>
                        <authentication>
                            <encrypted-password>$1$5mF0WMZn$ixP7Dsmb/NwMsJ1E41CyX1</encrypted-password>
                        </authentication>
                    </user>
                    <user>
                        <name>test</name>
                        <uid>2001</uid>
                        <class>super-user</class>
                        <authentication>
                            <encrypted-password>$1$cpnkhQRW$0pgo239ncRep/rJCnvrsW.</encrypted-password>
                        </authentication>
                    </user>
                </login>
                <services>
                    <ssh>
                        <protocol-version>v2</protocol-version>
                    </ssh>
                    <telnet>
                    </telnet>
                    <web-management>
                        <http>
                            <interface>ge-0/0/0.0</interface>
                        </http>
                        <https>
                            <system-generated-certificate/>
                        </https>
                    </web-management>
                </services>
                <syslog>
                    <user>
                        <name>*</name>
                        <contents>
                            <name>any</name>
                            <emergency/>
                        </contents>
                    </user>
                    <file>
                        <name>messages</name>
                        <contents>
                            <name>any</name>
                            <any/>
                        </contents>
                        <contents>
                            <name>authorization</name>
                            <info/>
                        </contents>
                    </file>
                    <file>
                        <name>interactive-commands</name>
                        <contents>
                            <name>interactive-commands</name>
                            <any/>
                        </contents>
                    </file>
                </syslog>
                <license>
                    <autoupdate>
                        <url>
                            <name>https://ae1.juniper.net/junos/key_retrieval</name>
                        </url>
                    </autoupdate>
                </license>
            </system>
            <interfaces>
                <interface>
                    <name>ge-0/0/0</name>
                    <unit>
                        <name>0</name>
                        <family>
                            <inet>
                                <address>
                                    <name>192.168.0.200/24</name>
                                </address>
                            </inet>
                        </family>
                    </unit>
                </interface>
                <interface>
                    <name>ge-0/0/1</name>
                    <unit>
                        <name>0</name>
                        <family>
                            <inet>
                                <address>
                                    <name>20.1.1.1/24</name>
                                </address>
                            </inet>
                        </family>
                    </unit>
                </interface>
                <interface>
                    <name>ge-0/0/2</name>
                    <unit>
                        <name>0</name>
                        <family>
                            <inet>
                                <address>
                                    <name>30.1.1.1/24</name>
                                </address>
                            </inet>
                        </family>
                    </unit>
                </interface>
                <interface>
                    <name>ge-0/0/3</name>
                    <unit>
                        <name>0</name>
                        <family>
                            <inet>
                                <address>
                                    <name>40.1.1.1/24</name>
                                </address>
                            </inet>
                        </family>
                    </unit>
                </interface>
            </interfaces>
            <routing-options>
                <static>
                    <route>
                        <name>1.1.1.1/32</name>
                        <next-hop>10.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>2.2.2.2/32</name>
                        <next-hop>20.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>3.3.3.3/32</name>
                        <next-hop>30.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>4.4.4.4/32</name>
                        <next-hop>40.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>1.0.0.0/8</name>
                        <next-hop>10.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>2.0.0.0/8</name>
                        <next-hop>20.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>3.0.0.0/8</name>
                        <next-hop>30.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>4.0.0.0/8</name>
                        <next-hop>40.1.1.2</next-hop>
                    </route>
                    <route>
                        <name>1.1.5.0/24</name>
                        <next-hop>10.1.1.8</next-hop>
                    </route>
                    <route>
                        <name>0.0.0.0/0</name>
                        <next-hop>192.168.0.1</next-hop>
                    </route>
                </static>
            </routing-options>
            <security>
                <flow>
                    <aging>
                        <low-watermark>10</low-watermark>
                    </aging>
                </flow>
                <screen>
                    <ids-option>
                        <name>untrust-screen</name>
                        <icmp>
                            <ping-death/>
                        </icmp>
                        <ip>
                            <source-route-option/>
                            <tear-drop/>
                        </ip>
                        <tcp>
                            <syn-flood>
                                <alarm-threshold>1024</alarm-threshold>
                                <attack-threshold>200</attack-threshold>
                                <source-threshold>1024</source-threshold>
                                <destination-threshold>2048</destination-threshold>
                                <undocumented><queue-size>2000</queue-size></undocumented>
                                <timeout>20</timeout>
                            </syn-flood>
                            <land/>
                        </tcp>
                    </ids-option>
                </screen>
                <policies>
                    <policy>
                        <from-zone-name>trust</from-zone-name>
                        <to-zone-name>trust</to-zone-name>
                        <policy>
                            <name>default-permit</name>
                            <match>
                                <source-address>any</source-address>
                                <destination-address>any</destination-address>
                                <application>any</application>
                            </match>
                            <then>
                                <permit>
                                </permit>
                            </then>
                        </policy>
                    </policy>
                    <policy>
                        <from-zone-name>trust</from-zone-name>
                        <to-zone-name>untrust</to-zone-name>
                        <policy>
                            <name>default-permit</name>
                            <match>
                                <source-address>any</source-address>
                                <destination-address>any</destination-address>
                                <application>any</application>
                            </match>
                            <then>
                                <permit>
                                </permit>
                            </then>
                        </policy>
                    </policy>
                    <policy>
                        <from-zone-name>untrust</from-zone-name>
                        <to-zone-name>trust</to-zone-name>
                        <policy>
                            <name>Policy2</name>
                            <match>
                                <source-address>100.1.3.0/30</source-address>
                                <destination-address>10.1.2.0/24</destination-address>
                                <application>TCP-test</application>
                            </match>
                            <then>
                                <permit>
                                </permit>
                            </then>
                        </policy>
                        <policy>
                            <name>default-deny</name>
                            <match>
                                <source-address>any</source-address>
                                <destination-address>any</destination-address>
                                <application>any</application>
                            </match>
                            <then>
                                <deny/>
                            </then>
                        </policy>
                        <policy>
                            <name>Policy1</name>
                            <match>
                                <source-address>OUT1</source-address>
                                <source-address>100.1.4.2/32</source-address>
                                <destination-address>10.1.3.2/32</destination-address>
                                <destination-address>10.1.3.1/32</destination-address>
                                <destination-address>10.1.3.3/32</destination-address>
                                <destination-address>IN1</destination-address>
                                <application>APP1</application>
                                <application>UDP-test2</application>
                            </match>
                            <then>
                                <permit>
                                </permit>
                            </then>
                        </policy>
                    </policy>
                </policies>
                <zones>
                    <security-zone>
                        <name>trust</name>
                        <tcp-rst/>
                        <address-book>
                            <address>
                                <name>10.1.3.0/32</name>
                                <ip-prefix>10.1.3.0/32</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.3.1/32</name>
                                <ip-prefix>10.1.3.1/32</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.3.2/32</name>
                                <ip-prefix>10.1.3.2/32</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.3.3/32</name>
                                <ip-prefix>10.1.3.3/32</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.3.0/30</name>
                                <ip-prefix>10.1.3.0/30</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.2.0/24</name>
                                <ip-prefix>10.1.2.0/24</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.4.0/28</name>
                                <ip-prefix>10.1.4.0/28</ip-prefix>
                            </address>
                            <address>
                                <name>10.1.4.2/31</name>
                                <ip-prefix>10.1.4.2/31</ip-prefix>
                            </address>
                            <address-set>
                                <name>IN1</name>
                                <address>
                                    <name>10.1.3.2/32</name>
                                </address>
                                <address>
                                    <name>10.1.3.0/30</name>
                                </address>
                            </address-set>
                        </address-book>
                        <host-inbound-traffic>
                            <system-services>
                                <name>all</name>
                            </system-services>
                        </host-inbound-traffic>
                        <interfaces>
                            <name>ge-0/0/0.0</name>
                            <host-inbound-traffic>
                                <system-services>
                                    <name>http</name>
                                </system-services>
                                <system-services>
                                    <name>https</name>
                                </system-services>
                                <system-services>
                                    <name>ssh</name>
                                </system-services>
                                <system-services>
                                    <name>telnet</name>
                                </system-services>
                                <system-services>
                                    <name>dhcp</name>
                                </system-services>
                                <system-services>
                                    <name>all</name>
                                </system-services>
                            </host-inbound-traffic>
                        </interfaces>
                    </security-zone>
                    <security-zone>
                        <name>untrust</name>
                        <address-book>
                            <address>
                                <name>100.1.3.1/32</name>
                                <ip-prefix>100.1.3.1/32</ip-prefix>
                            </address>
                            <address>
                                <name>100.1.3.2/32</name>
                                <ip-prefix>100.1.3.2/32</ip-prefix>
                            </address>                            <address>
                                <name>100.1.3.3/32</name>
                                <ip-prefix>100.1.3.3/32</ip-prefix>
                            </address>
                            <address>
                                <name>100.1.3.0/30</name>
                                <ip-prefix>100.1.3.0/30</ip-prefix>
                            </address>
                            <address>
                                <name>100.1.3.0/24</name>
                                <ip-prefix>100.1.3.0/24</ip-prefix>
                            </address>
                            <address>
                                <name>100.1.4.2/32</name>
                                <ip-prefix>100.1.4.2/32</ip-prefix>
                            </address>
                            <address>
                                <name>100.1.2.0/24</name>
                                <ip-prefix>100.1.2.0/24</ip-prefix>
                            </address>
                            <address-set>
                                <name>OUT1</name>
                                <address>
                                    <name>100.1.3.2/32</name>
                                </address>
                                <address>
                                    <name>100.1.3.3/32</name>
                                </address>
                                <address>
                                    <name>100.1.4.2/32</name>
                                </address>
                                <address>
                                    <name>100.1.2.0/24</name>
                                </address>
                            </address-set>
                        </address-book>
                        <screen>untrust-screen</screen>
                        <interfaces>
                            <name>ge-0/0/1.0</name>
                        </interfaces>
                        <interfaces>
                            <name>ge-0/0/2.0</name>
                        </interfaces>
                        <interfaces>
                            <name>ge-0/0/3.0</name>
                        </interfaces>
                    </security-zone>
                    <security-zone>
                        <name>cisco</name>
                    </security-zone>
                </zones>
            </security>
            <applications>
                <application>
                    <name>TCP-test</name>
                    <protocol>tcp</protocol>
                    <source-port>5</source-port>
                    <destination-port>20</destination-port>
                </application>
                <application>
                    <name>UDP-test</name>
                    <protocol>udp</protocol>
                    <source-port>1-2</source-port>
                    <destination-port>3-3</destination-port>
                </application>
                <application>
                    <name>UDP-test2</name>
                    <protocol>udp</protocol>
                    <source-port>6-7</source-port>
                    <destination-port>4-8</destination-port>
                </application>
                <application-set>
                    <name>APP1</name>
                    <application>
                        <name>TCP-test</name>
                    </application>
                    <application>
                        <name>UDP-test</name>
                    </application>
                </application-set>
                <application-set>
                    <name>APP2</name>
                    <application>
                        <name>UDP-test</name>
                    </application>
                    <application>
                        <name>UDP-test2</name>
                    </application>
                </application-set>
            </applications>
    </configuration>
    <cli>
        <banner></banner>
    </cli>
</rpc-reply>
    '''
    policies = ['Policy1', 'Policy2', 'default-deny']
    soup = ConfigurationSoup()
    soup.get_whole_conf(configuration)
    print(soup.analyse_policies_applications(soup.analyse_policies()))
    print(soup.analyse_policies_address(soup.analyse_policies()))
    

        