'''
Created on Dec 14, 2013

@author: bazooka
'''
import logging
import re
import socket
import telnetlib

from strategies import stratigy_srx


class telnet_connection(object):
    '''
    classdocs
    '''
    def __enter__(self):
        return self
    def __exit__(self, e_t, e_v, t_b):
        if self.__con != None:
            self.__con.close()
            

    def __init__(self, username, password, finish, host = '192.168.1.2', port = '23', timeout = 999):
        '''
        Constructor
        '''
        self.host = host
        self.port = port
        self.timeout = timeout
        self.username = bytes(username, encoding = 'utf8')
        self.password = bytes(password, encoding = 'utf8')
        if finish.lower() == 'srx':
            finish = stratigy_srx.finish_symbol_normal
        else:
            finish = '~$'
        self.finish = bytes(finish, encoding = 'utf8')
        
        try:
            self.__con = None
            self.__con = telnetlib.Telnet(host, self.port, timeout)
        except socket.timeout:
            logging.warn("socket timeout")
        except OSError:
            logging.error('system error : OSError.errno' )
            return
        else:
            print(self.__con.read_until(b'login: ', timeout).decode("utf8"))
            self.__con.write((self.username + b"\n"))
            print(self.__con.read_until(b'Password:', timeout).decode("utf8"))
            self.__con.write((self.password + b"\n"))
            self.__con.read_some().decode("utf8")
            login_result = self.__con.read_some().decode("utf8")
            if 'incorrect' in login_result:
                logging.warn(login_result)
                self.__con.close()
                self.__con = None
                return 
            print(self.__con.read_until(self.finish).decode("utf8"))
            
            self.__con.write( bytes("\n", encoding = 'utf8'))
            prompt = self.__con.read_until(self.finish, timeout).decode("utf8")
            # prompt = re.sub(r'(\r\n)+', r'\r\n', prompt)
            # prompt = re.search(r'(?<=\r\n)\S*' + finish + '$', prompt).group(0)
            prompt = re.search(r'.*', prompt, re.S).group(0) # re.S make . represent \n
            print('prompt is ' + repr(prompt[1:]))
            self.prompt = prompt[1:]
            #===================================================================
            # m = re.search(r'(?<=' + self.username + r'@)\S*' + self.finish, output)
            # prompt = m.group(0)
            #===================================================================

    def commit(self, cmd):
        try:
            show_flag = False
            if self.__con is None:
                return ''
            cmd = re.sub(r'[\r\n]*', '', cmd)
            if cmd.startswith('show'):
                show_flag = True
                cmd += ' | display xml | no-more'
            self.__con.write( bytes("%s\r" %cmd, encoding = 'utf8'))
            while(1):
                output = str(self.__con.read_until(bytes(self.prompt[-5:], encoding = 'utf8'), self.timeout), "utf8")

                if show_flag and re.search(r'rpc', output):
                    break
            end_index = output.find(self.prompt)
            if show_flag:
                start_index = output.find('no-more')+ len('no-more \r\n')
            else:
                start_index = output.find(cmd)+len(cmd)
            logging.debug(output[start_index:end_index]) 
            return(output[start_index:end_index])
        except socket.timeout:
            logging.warn("socket timeout")  


if __name__ == '__main__':
    # '192.168.0.200'
    # with telnet_connection(username = 'test', password = 'test123', host = '100.100.100.254', finish = 'srx') as session:
    with telnet_connection(username = 'test', password = 'test123', host = '192.168.0.200', finish = 'srx') as session:
        # print(session.commit('show configuration security policies from-zone untrust to-zone trust'))
        print(session.commit('show configuration groups junos-defaults applications'))
        # session.commit('show configuration')
        # print(session.commit('show configuration applications application-set APP1'))
        #------------------------------------------ session.commit('show route')

                
