from packet import ECLoginPacket, ReadPacketData
from struct import unpack
import socket, asynchat
import codes

class ConnectionFailedError(Exception):
    def __init__(self):
        pass

class conn:
    def __init__(self, password, host="localhost", port=4712, app="pyEC", ver="0.5"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.sock.connect((host,port)) 
        packet_req = ECLoginPacket(app, ver, password)

        type, tags = self.send_and_receive_packet(packet_req)
        if type != codes.op['auth_ok']:
            raise ConnectionFailedError
    def __del__(self):
        self.sock.close()

    def send_packet(self, data):
        self.sock.send(data)
    def receive_packet(self):
        header_data = self.sock.recv(8)
        if (not header_data) or (len(header_data) != 8):
            raise ConnectionFailedError
        flags, data_len = unpack("!II", "".join(header_data))
        packet_data = self.sock.recv(data_len)
        if (not packet_data) or (len(packet_data) != data_len):
            print len(packet_data), data_len
            raise ConnectionFailedError
        return ReadPacketData("".join(packet_data))
    def send_and_receive_packet(self, data):
        self.send_packet(data)
        return self.receive_packet()

