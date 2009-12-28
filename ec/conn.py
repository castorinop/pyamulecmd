from packet import ECLoginPacket, ECPacket, ReadPacketData
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
            raise ConnectionFailedError
        return ReadPacketData("".join(packet_data))

    def send_and_receive_packet(self, data):
        self.send_packet(data)
        return self.receive_packet()

    def get_status(self):
        data = ECPacket((codes.op['stat_req'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        response = self.send_and_receive_packet(data)
        print repr(response)
    
    def get_connstate(self):
        data = ECPacket((codes.op['get_connstate'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        response = self.send_and_receive_packet(data)
        # structure: (op['misc_data'], [(tag['connstate'], (connstate, [subtags]))])
        # (7, [(5, (29, [(1280, ('212.63.206.35:4242', [(1281, u'eDonkeyServer No2')])), (6, 8955376), (10, 8955376)]))])
        connstate = response[1][0][1][0]
        subtags = response[1][0][1][1]
        server_name, server_addr, ed2k_id, client_id = "", "", "", ""
        for tag in subtags:
            if tag[0] == codes.tag['server']:
                server_addr = tag[1][0]
                server_name = tag[1][1][0][1]
            if tag[0] == codes.tag['ed2k_id']:
                ed2k_id = tag[1]
            if tag[0] == codes.tag['client_id']:
                client_id = tag[1]
        
        status = "eD2k: "
        if (connstate & 0x01): # ed2k connected
            highest_lowid_ed2k_kad = 16777216
            id = "with HighID" if (client_id > highest_lowid_ed2k_kad) else "with LowID"
            status += "Connected to %s [%s] %s" % (server_name, server_addr, id)
        elif (connstate & 0x02): # ed2k connecting
            status += "Now connecting"
        else:
            status += "Not connected"
        status += "\nKad: "
        if (connstate & 0x10): # kad running
            if (connstate & 0x04): # kad connected
                status += "Connected ("
                if (connstate & 0x08): # kad firewalled
                    status += "firewalled"
                else:
                    status += "ok"
                status += ")"
            else:
                status += "Not connected"
        else:
            status += "Not running"
        print status
