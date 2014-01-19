import logging

__author__ = 'bazooka'
import mysql.connector

class MysqlOperator(object):
    """
    This class insert the information into database
    """
    def __init__(self, host, user, pwd, database):

        self.cnx = mysql.connector.connect(user=user, password=pwd, host=host, database=database)

    def __enter__(self):
        return self
    def __exit__(self, e_t, e_v, t_b):
        if self.cnx is not None:
            self.cnx.close()

    def add_policy(self, device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone, action):
        try:
            cursor = self.cnx.cursor()
            insert_sql = "INSERT INTO POLICIES (DEVICE_IP, POLICY_NAME, FROM_ZONE, TO_ZONE, SRC_IP,"" \
            "" DST_IP, ACTION) VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}')"\
                .format(device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone, action)
            cursor.execute(insert_sql)
            self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.ERROR("Cann't insert policy name : {}".format(policy_name))
            print("Error: {}".format(err.msg))
            return False

    def search_policy(self, device_ip, policy_name=None, src_ip=None, dst_ip=None, from_zone=None, to_zone=None, action=None):
        if device_ip and not (policy_name or src_ip or dst_ip or from_zone or to_zone or action):
            try:
                cursor = self.cnx.cursor()

                search_sql_by_device_sql = "SELECT * FROM POLICIES WHERE DEVICE_IP='{}'".format(device_ip)
                cursor.execute(search_sql_by_device_sql)
                result_dict = {}
                for (id, result_device_ip, result_policy_name, result_src_ip, result_dst_ip, result_from_zone, result_to_zone, result_action) in cursor:
                    print(result_policy_name)
                return {result_dict}
            except mysql.connector.Error as err:
                logging.ERROR("Cann't find policies in device: {}".format(str(device_ip)))
                print("Error: {}".format(err.msg))
                return None
        elif device_ip and policy_name and from_zone and to_zone:
            try:
                cursor = self.cnx.cursor()

                search_sql_by_device_sql = "SELECT * FROM POLICIES WHERE DEVICE_IP='{}'".format(device_ip)
                cursor.execute(search_sql_by_device_sql)
                result_dict = {}
                for (id, result_device_ip, result_policy_name, result_src_ip, result_dst_ip, result_from_zone, result_to_zone, result_action) in cursor:
                    print(result_policy_name)
                return {result_dict}
            except mysql.connector.Error as err:
                logging.ERROR("Cann't find policies in device: {}".format(str(device_ip)))
                print("Error: {}".format(err.msg))
                return None
    def remove_policy(self, device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone):
        try:
            cursor = self.cnx.cursor()
            delete_by_name_sql = "DELETE FROM POLICIES WHERE DEVICE_IP='{}', POLICY_NAME='{}', FROM_ZONE='{}', TO_ZONE='{}'"\
                .format(device_ip, policy_name, from_zone, to_zone)
            cursor.execute(delete_by_name_sql)
            self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.ERROR("Cann't delete policy name : {}".format(policy_name))
            print("Error: {}".format(err.msg))
            return False

    def add_policy(self, device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone, action):
        try:
            cursor = self.cnx.cursor()
            insert_sql = "INSERT INTO POLICIES (DEVICE_IP, POLICY_NAME, FROM_ZONE, TO_ZONE, SRC_IP,"" \
            "" DST_IP, ACTION) VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}')"\
                .format(device_ip, policy_name, src_ip, dst_ip, from_zone, to_zone, action)
            cursor.execute(insert_sql)
            self.cnx.commit()
            return True
        except mysql.connector.Error as err:
            logging.ERROR("Cann't insert policy name : {}".format(policy_name))
            print("Error: {}".format(err.msg))
            return False


if __name__ == '__main__':
        user = 'J-MEOW'
        pwd = ''
        host = 'localhost'
        database = 'test'
        insertor = MysqlOperator(host, user, pwd, database)
        # insertor.add_policy(device_ip='10.1.2.3', policy_name='test1', src_ip='10.2', dst_ip='1212', from_zone='untrust', to_zone='trust', action='permit')
        insertor.search_policy(device_ip='10.1.2.3')

