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
        for response in self.responses:
            data = conn.recv(2048)
            conn.send(response)
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

def test_connstate_kad_ok():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00H\x0c\x0b\xd0\x80\x02\x01o\xd0\x82\x02\x01\x00\xd0\x84\x02\x01\x00\xd0\x86\x02\x01\x00\xd0\x90\x02\x01\x00\xd0\x8c\x02\x01\x00\xd0\x92\x04\x04\x001\xe8\x18\xd0\x94\x03\x02\x018\xd0\x96\x04\x04\x10\xa8\x91\xaa\xd0\x98\x03\x02\x92@\x0b\x02\x0c\x01\x14\x04\x04\xe8L\xb5T\x14'])
    fake_host.start()
    test_conn = conn("aaa")
    status = test_conn.get_status()
    assert status['ul_limit'] == 0 and \
           status['queue_len'] == 0 and \
           status['connstate']['kad_firewall'] == 'ok' and \
           status['connstate']['ed2k'] == 'Not connected' and \
           status['connstate']['server_name'] == '' and \
           status['connstate']['kad'] == 'connected' and \
           status['connstate']['ed2k_id'] ==  0 and \
           status['connstate']['client_id'] == 3897341268L and \
           status['connstate']['id'] == '' and \
           status['connstate']['server_addr'] == '' and \
           status['kad_users'] == 312 and \
           status['ed2k_files'] == 279482794 and \
           status['ed2k_users'] == 3270680 and \
           status['dl_limit'] == 0 and \
           status['dl_speed'] == 0 and \
           status['kad_files'] == 37440 and \
           status['src_count'] == 0 and \
           status['ul_speed'] == 111

def test_connstate_shared_files_compressed():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00!\x00\x00\x02ux\xda\x9d\xd3Mk\x13A\x18\x07\xf0M\x8cK,\xa9\x82(z\x10\xa4\xad\x07A\xb2\xd9\x9d\x99\x9d\x99\xb5x\x98\xdd\xc9\xb81\xd9&m6\xe9\xfavh\xd3\x15\xda\xa6IM\xb7(uAPP\xd1O\xe0\xc1\x83\xe0\xc9\x17\x04\xcf^D1w\x05\xc1\x93_\xa0x\xeaEA\xb1\xe9\xa6mTJIO\xcf<\xec\xee\x7fx~<;,%\x92\xb1\x03\x92\x14S\xa5TR\x8eK\xeb\')\x99\xdc\xa8\xf1\xe4@\xb7Ou\xfbx\xb7O$\xd6kB\x1a\x99_M\x1e\x94\xd7\x8fCE^\xd1\xf51\xab \xcaU\xdd\x06%1\xc9=\x9c\xf3\\\x97\xdbE\xb3X\x9a(K\xf2\xe1\x8dOSr\xbc\xf3>\x98r\x96\xeb~\x1a(@\xc1\xe9\x85\xa5\x1b\xca\xe5Z\xb3\x11\xf8\x8d`fZ\xf1\x17:\x8f\x16[\xcd9\xbf\x16(\r?\xb8\xaa\xf87}I\x96\xa3;\xaf\xbc_\x95Ot2\xe6\xfc\x190\x7f6\x93\t\xaf\xcd\xd6\xfd\xb0\xef\xc0\x10\xab\xc4@\x98\x86\xaa\xce\x98\x8a\x01\xa5\xa6E,"\x0c\x81\x88 \x88B\x00t\x04\x011\xc3\x8c$\x9f\x8am\xcc\xbd\xff\xb9|\xfaQ\xbb\xfdc\xedvpw\xd8\x05\xb7"\xb8\x91\xff\xe0\xa4\x7f\xe0\xa4m\xb8n\x8d\xd4\xca\xe3\xa4Pq/V\xca\x0e7K\xc0\xadf\x81C\\\\\xad\x98\x85\n\x04(/6\xd5b\x91Z\xda\xef\x0c\xa9*\xc8\xa8\xed2\xdf\xca\xec\xe2\x16\xd8\x99\x8f\xf7#0\xff/\xb0~\xb2B@1\xa5D\x0bUAi6+\x98\xc1)\xe3P \xc8\x99\xc9,\xc3\xa0\x80\x03\xa4\xabV\x8f\xd5\xa1\x07\xdf\x7f>y\xf8y\xed\xdc\x8b\x97\x8f\xef|\xca\xa6"\xab\xd1=[\x8dsR\x80\x17\x9cKU\x90/\x9e/\x99\x1e\xd6s\xd0v=\x91\xf5\xc6\xaa\x9e]d\x9bV\xfb"+\xa3w!\x96\x9a\xcb\xad\x9a\xaf\x04S\xad]f\x9d^\x01[n\xf6\xe0\xb7\xc8\xed\xfa\x8e\x8b\xd6On\x88\x08\x00\x1a\x82!D\x0cAhi\xd0\xc4\xa6i\x01M#\x98i\xd4BL\x03Bd1\xea1D\xcf\xe0\xbb\xd1\xf9\xb7C\xc7\xe6\x8e\x7fx\x9a\xf9=\x13\x19\x92=\x1b\xe6\xdc\x9c\xc3pa\xc2\xb4\xc7\xf2\x8eG\xdc\xbc\x9ew\x889^\x1098\xc9X\xd5\xde4LD\x86d{G\xd2\xb9\xc6R0U\xaf\xfb\xad>~U\x18\xfb\x1a\t6w\xd8\xbc~RC\x08\x11\xa0\xaa\x11\xea\xaa\xca(f\x02!\x0c,\x824\x8e\x19\xd7t\x95kHpM\x98\xa0\xc7\xaf4p\xef5\x9fn\xb3/\xaf\x8e\x0e\x1e\xf9u\xf2\xcd\x1f\x86\xa2"!'])
    fake_host.start()
    test_conn = conn("aaa")
    shared = test_conn.get_shared()
    assert  len(shared) == 4 and \
            len(shared[0]) == 13 and \
            shared[3]['link'] == 'ed2k://|file|eMule0.49c-Installer.[contentdb.emule-project.net].exe|3342809|500A86AF4462C741D6AD150D14FD1FB2|/'

def test_conn_socket_error():
    try:
        conn("aaa")
    except ConnectionFailedError as error:
        print error
        pass

def test_conn_shutdown():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00"])
    fake_host.start()
    test_conn = conn("aaa")
    test_conn.shutdown()

def test_conn_connect():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x003\x06\x02\x00\x06\x16Connecting to eD2k...\x00\x00\x06\x15Connecting to Kad...\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect = test_conn.connect()
    assert  connect[0] == True and \
            len(connect[1]) == 2

def test_conn_connect_server():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x02\x01\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect_server = test_conn.connect_server()
    assert connect_server == True

def test_conn_connect_kad():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x02\x01\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect_kad = test_conn.connect_kad()
    assert connect_kad == True

def test_conn_disconnect():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x007\x06\x02\x00\x06\x18Disconnected from eD2k.\x00\x00\x06\x17Disconnected from Kad.\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    disconnect = test_conn.disconnect()
    assert  disconnect[0] == True and \
            len(disconnect[1]) == 2

def test_conn_disconnect_server():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x02\x01\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect_server = test_conn.disconnect_server()


def test_conn_disconnect_kad():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x02\x01\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect_server = test_conn.disconnect_kad()

def test_conn_reload_shared():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x02\x01\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect_server = test_conn.reload_shared()

def test_conn_reload_ipfilter():
    fake_host = send_response(["\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00",'\x00\x00\x00"\x00\x00\x00\x02\x01\x00'])
    fake_host.start()
    test_conn = conn("aaa")
    connect_server = test_conn.reload_ipfilter()
