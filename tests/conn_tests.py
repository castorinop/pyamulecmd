import socket, time
from threading import Thread
from ec.conn import conn, ConnectionFailedError

class send_response(Thread):
    def __init__ (self,response):
        Thread.__init__(self)
        self.response = response
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('localhost', 4712))
        self.s.listen(1)
    def __del__(self):
        self.s.close()
    def run(self):
        conn, addr = self.s.accept()
        data = conn.recv(1024)
        conn.send(self.response)
        conn.close()

def test_connection_success():
    fake_host = send_response("\x00\x00\x00\x22\x00\x00\x00\x0E\x04\x00\x01\xe0\xa8\x96\x06\x06\x32\x2e\x32\x2e\x33\x00")
    fake_host.start()
    test_conn = conn("aaa")

def test_connection_fail_1():
    fake_host = send_response("")
    fake_host.start()
    try:
        conn("aaa")
    except ConnectionFailedError:
        pass

def test_connection_fail_2():
    fake_host = send_response("\x00\x00\x00\x22\x00\x00\x00\x0Eabcd")
    fake_host.start()
    try:
        conn("aaa")
    except ConnectionFailedError:
        pass

def test_connection_fail_3():
    fake_host = send_response("\x00\x00\x00\x22\x00\x00\x00\x03\x03\x00\x00")
    fake_host.start()
    try:
        conn("aaa")
    except ConnectionFailedError:
        pass