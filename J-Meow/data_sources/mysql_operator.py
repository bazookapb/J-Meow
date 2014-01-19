import logging
import netaddr

__author__ = 'bazooka'
import mysql.connector

class MysqlOperator(object):
    """
    This class insert the information into database
    """
    def __init__(self, host, user, pwd, database):
        self.cnx = mysql.connector.connect(user=user, password=pwd, host=host, database=database)
    def close(self):
        if self.cnx is not None:
            self.cnx.close()

    def __enter__(self):
        return self
    def __exit__(self, e_t, e_v, t_b):
        if self.cnx is not None:
            self.cnx.close()

    def add_policy(self, device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone, action):
        try:
            cursor = self.cnx.cursor()
            insert_sql = 'INSERT INTO POLICIES (DEVICE_IP, POLICY_NAME, FROM_ZONE, TO_ZONE, SRC_IP, \
            DST_IP, ACTION) VALUES ("{}", "{}", "{}", "{}", "{}", "{}", "{}")'\
            .format(device_ip, policy_name, from_zone, to_zone, str(src_ip), str(dst_ip), action)
            # print(insert_sql)
            cursor.execute(insert_sql)
            self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.error("Cann't insert policy name : {}".format(policy_name)+" Error: {}".format(err.msg))
            return False

    def search_policy_by_ip(self, device_ip, policy_name=None, src_ip=None, dst_ip=None, from_zone=None, to_zone=None, action=None):
        '''

        @param device_ip:
        @param policy_name:
        @param src_ip:
        @param dst_ip:
        @param from_zone:
        @param to_zone:
        @param action:
        @return:

        '''
        if src_ip is not None and dst_ip is not None:
            search_sql_by_device_sql = 'SELECT POLICY_ID, POLICY_NAME FROM POLICIES WHERE DEVICE_IP="{}" AND\
                FROM_ZONE="{}" AND TO_ZONE="{}" AND SRC_IP="{}" AND DST_IP="{}"'.format(device_ip, from_zone, to_zone, str(src_ip), str(dst_ip))
        elif src_ip is not None:
            search_sql_by_device_sql = 'SELECT POLICY_ID, POLICY_NAME FROM POLICIES WHERE DEVICE_IP="{}" AND\
                FROM_ZONE="{}" AND TO_ZONE="{}" AND SRC_IP="{}"'.format(device_ip, from_zone, to_zone, str(src_ip))
        elif dst_ip is not None:
            search_sql_by_device_sql = 'SELECT POLICY_ID, POLICY_NAME FROM POLICIES WHERE DEVICE_IP="{}" AND\
                FROM_ZONE="{}" AND TO_ZONE="{}" AND DST_IP="{}"'.format(device_ip, from_zone, to_zone, str(dst_ip))
        try:
            cursor = self.cnx.cursor()
            cursor.execute(search_sql_by_device_sql)
            result_dict = cursor.fetchall()
            # logging.debug("The policies hit are "+ str(result_dict))
            return result_dict
        except mysql.connector.Error as err:
            logging.error("Cann't find policies in device: {}".format(str(device_ip))+" Error: {}".format(err.msg))
            return None

    def search_policy_by_app(self, device_ip, policy_name=None, application={}, from_zone=None, to_zone=None, action=None):
        protocols = list(application.keys())
        if len(application)==2:
            search_sql_by_device_sql = 'SELECT POLICY_ID, POLICY_NAME FROM POLICIES WHERE DEVICE_IP="{}" AND FROM_ZONE="{}" AND TO_ZONE="{}" AND POLICY_ID in (SELECT b.POLICY_ID FROM APPLICATION_SUMMARY as a JOIN APPLICATION_SUMMARY as b  ON a.POLICY_ID = b.POLICY_ID WHERE b.PROTOCOL="{}" AND b.SRC_PORT="{}" AND b.DST_PORT="{}" AND a.PROTOCOL="{}" AND a.SRC_PORT="{}" AND a.DST_PORT="{}" GROUP BY POLICY_ID HAVING COUNT(POLICY_ID)=2);'\
                .format(device_ip, from_zone, to_zone, protocols[0], application[protocols[0]]['src-port'], application[protocols[0]]['dst-port'], protocols[1], application[protocols[1]]['src-port'], application[protocols[1]]['dst-port'])
        elif len(application)==1:
            search_sql_by_device_sql = 'SELECT POLICY_ID, POLICY_NAME FROM POLICIES WHERE DEVICE_IP="{}" AND FROM_ZONE="{}" AND TO_ZONE="{}" AND POLICY_ID in (SELECT b.POLICY_ID FROM APPLICATION_SUMMARY as b  WHERE b.PROTOCOL="{}" AND b.SRC_PORT="{}" AND b.DST_PORT="{}" GROUP BY POLICY_ID HAVING COUNT(POLICY_ID)=1);'\
                .format(device_ip, from_zone, to_zone, protocols[0], application[protocols[0]]['src-port'], application[protocols[0]]['dst-port'])
        elif len(application)==3:
            search_sql_by_device_sql = 'SELECT POLICY_ID, POLICY_NAME FROM POLICIES WHERE DEVICE_IP="{}" AND FROM_ZONE="{}" AND TO_ZONE="{}" AND POLICY_ID in (SELECT b.POLICY_ID FROM APPLICATION_SUMMARY as a JOIN APPLICATION_SUMMARY as b  ON a.POLICY_ID = b.POLICY_ID JOIN APPLICATION_SUMMARY as c  ON c.POLICY_ID = b.POLICY_ID WHERE b.PROTOCOL="{}" AND b.SRC_PORT="{}" AND b.DST_PORT="{}" AND a.PROTOCOL="{}" AND a.SRC_PORT="{}" AND a.DST_PORT="{}" AND c.PROTOCOL="{}" AND c.SRC_PORT="{}" AND c.DST_PORT="{}" GROUP BY POLICY_ID HAVING COUNT(POLICY_ID)=3);'\
                .format(device_ip, from_zone, to_zone, protocols[0], application[protocols[0]]['src-port'], application[protocols[0]]['dst-port'], protocols[1], application[protocols[1]]['src-port'], application[protocols[1]]['dst-port'], protocols[2], application[protocols[2]]['src-port'], application[protocols[2]]['dst-port'])
        else: # None or empty.
            return []
        try:
            cursor = self.cnx.cursor()
            cursor.execute(search_sql_by_device_sql)
            result_dict = cursor.fetchall()
            return result_dict
        except mysql.connector.Error as err:
            logging.error("Cann't find policies in device: {}".format(str(device_ip))+" Error: {}".format(err.msg))
            return None

    def remove_policy(self, device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone):
        try:
            cursor = self.cnx.cursor()
            delete_by_name_sql = 'DELETE FROM POLICIES WHERE DEVICE_IP="%s", POLICY_NAME="%s", FROM_ZONE="%s", TO_ZONE="%s"'
            data = (device_ip, policy_name, from_zone, to_zone)
            cursor.execute(delete_by_name_sql, data)
            # self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.ERROR("Cann't delete policy name : {}".format(policy_name)+" Error: {}".format(err.msg))
            return False

    def remove_all_policy(self):
        try:
            cursor = self.cnx.cursor()
            delete_sql = 'DELETE from APPLICATION_SUMMARY;"'
            cursor.execute(delete_sql)
            delete_sql = 'DELETE from POLICIES;'
            cursor.execute(delete_sql)
            self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.ERROR("Cann't delete all policies Error: {}".format(err.msg))
            return False


    def add_application(self, device_ip, policy_name, from_zone, to_zone, application):
        try:
            cursor = self.cnx.cursor(buffered=True)
            # query_sql = 'SELECT POLICY_ID FROM POLICIES WHERE DEVICE_IP="{}" AND POLICY_NAME="{}" AND FROM_ZONE="{}" AND TO_ZONE="{}"'\
            # .format(device_ip, str(policy_name), str(from_zone), str(to_zone))
            # cursor.execute(query_sql)
            # result_set = cursor.fetchone()
            # id = result_set[0]  #get policy id
            for protocol, content in application.items():
                src_port = content['src-port']
                dst_port = content['dst-port']
                insert_sql = 'INSERT INTO APPLICATION_SUMMARY (POLICY_ID, SRC_PORT, DST_PORT, PROTOCOL) SELECT POLICY_ID, "{}", "{}", "{}" FROM POLICIES WHERE DEVICE_IP="{}" AND POLICY_NAME="{}" AND FROM_ZONE="{}" AND TO_ZONE="{}"'\
                    .format(src_port, dst_port, protocol, device_ip, str(policy_name), str(from_zone), str(to_zone))
                cursor.execute(insert_sql)
            self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.error("Cann't insert application for policy name : " + str(policy_name) + " Error: {}".format(err.msg))
            return False


if __name__ == '__main__':
        user = 'J-MEOW'
        pwd = ''
        host = 'localhost'
        database = 'test'
        insertor = MysqlOperator(host, user, pwd, database)
        # insertor.add_policy(device_ip='10.1.2.3', policy_name='test1', src_ip='10.2', dst_ip='1212', from_zone='untrust', to_zone='trust', action='permit')
        result = insertor.search_policy_by_ip(device_ip='10.1.66.22', src_ip=netaddr.IPSet(['10.0.0.0/8', '12.0.0.0/8', '13.0.0.0/8']), dst_ip=None, from_zone='untrust', to_zone='trust')
        print(result)

        application = {'tcp':{'src-port':['any'], 'dst-port':[5666, 12489]}}
        # application = {'tcp':{'src-port':['any'], 'dst-port':[5666, 12489]}, 'udp':{'src-port':['any'], 'dst-port':[16102, 16103, 16104, 16105]}}
        # application = {'tcp':{'src-port':['any'], 'dst-port':[5666, 12489]}, 'udp':{'src-port':['any'], 'dst-port':[16102, 16103, 16104, 16105]}, 'icmp':{'src-port':['any'], 'dst-port':['any']}}
        result = insertor.search_policy_by_app(device_ip='10.1.66.22', application=application, from_zone='untrust', to_zone='training')
        print(result)