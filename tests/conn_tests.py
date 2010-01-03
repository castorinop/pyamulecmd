import socket
from threading import Thread
from ec.conn import conn, ConnectionFailedError

class send_response(Thread):
    def __init__ (self,responses):
        Thread.__init__(self)
        self.responses = responses
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('localhost', 4712))
        self.s.listen(1)
    def __del__(self):
        self.s.close()
    def run(self):
        conn, addr = self.s.accept()
        for i in range(len(self.responses)):
            response = self.responses[i]
            data = conn.recv(1024)
            conn.send(response)
            if (i == len(self.responses)):
                conn.close()

def test_connection_success():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00"])
    fake_host.start()
    test_conn = conn("aaa")

def test_connection_fail_1():
    fake_host = send_response([""])
    fake_host.start()
    try:
        conn("aaa")
    except ConnectionFailedError:
        pass

def test_connection_fail_2():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0Eabcd"])
    fake_host.start()
    try:
        conn("aaa")
    except ConnectionFailedError:
        pass

def test_connection_fail_3():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x03\x03\x00\x00"])
    fake_host.start()
    try:
        conn("aaa")
    except ConnectionFailedError:
        pass

def test_connstate_not_connected():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x0b\x07\x01\x0b\x02\t\x01\x14\x02\x01\x00\x08'])
    fake_host.start()
    test_conn = conn("aaa")
    status = test_conn.get_connstate()
    assert status['kad_firewall'] == '' and \
           status['ed2k'] == 'Not connected' and \
           status['server_name'] == '' and \
           status['kad'] == 'Not running' and \
           status['ed2k_id'] == 0 and \
           status['client_id'] == 0 and \
           status['id'] == "" and \
           status['server_addr'] == ''

def test_connstate_firewalled():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x008\x07\x01\x0b\x02?\x03\xe0\xa8\x81\x08\x1f\x01\xe0\xa8\x82\x06\x12eDonkeyServer No2\x00\xd4?\xce#\x10\x92\x0c\x04\x04\x00\x1c\xd7\xd6\x14\x04\x04\x00\x1c\xd7\xd6\x1d'])
    fake_host.start()
    test_conn = conn("aaa")
    status = test_conn.get_connstate()
    assert status['kad_firewall'] == 'firewalled' and \
           status['ed2k'] == 'connected' and \
           status['server_name'] == u'eDonkeyServer No2' and \
           status['kad'] == 'connected' and \
           status['ed2k_id'] == 1890262 and \
           status['client_id'] == 1890262 and \
           status['id'] == 'LowID' and \
           status['server_addr'] == '212.63.206.35:4242'

def test_connstate_connecting():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x0b\x07\x01\x0b\x02\t\x01\x14\x02\x01\x00\x1a'])
    fake_host.start()
    test_conn = conn("aaa")
    status = test_conn.get_connstate()
    assert status['kad_firewall'] == '' and \
           status['ed2k'] == 'connecting' and \
           status['server_name'] == '' and \
           status['kad'] == 'Not connected' and \
           status['ed2k_id'] == 0 and \
           status['client_id'] == 0 and \
           status['id'] == "" and \
           status['server_addr'] == ''

def test_connstate_kad_ok():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x0e\x07\x01\x0b\x02\x0c\x01\x14\x04\x04*J\xb5T\x14'])
    fake_host.start()
    test_conn = conn("aaa")
    status = test_conn.get_connstate()
    assert status['kad_firewall'] == 'ok' and \
           status['ed2k'] == 'Not connected' and \
           status['server_name'] == '' and \
           status['kad'] == 'connected' and \
           status['ed2k_id'] == 0 and \
           status['client_id'] == 709539156 and \
           status['id'] == "" and \
           status['server_addr'] == ''

