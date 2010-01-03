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
        # structure: (op['stats'], [(tag['stats_ul_speed'], 0), (tag['stats_dl_speed'], 0), (tag['stats_ul_speed_limit'], 0), (tag['stats_dl_speed_limit'], 0), (tag['stats_ul_queue_len'], 0), (tag['stats_total_src_count'], 0), (tag['stats_ed2k_users'], 3270680), (tag['stats_kad_users'], 0), (tag['stats_ed2k_files'], 279482794), (tag['stats_kad_files'], 0), (tag['connstate'], ((connstate, [subtags])))])
        status = { "ul_speed"  : 0, \
                   "dl_speed"  : 0, \
                   "ul_limit"  : 0, \
                   "dl_limit"  : 0, \
                   "queue_len" : 0, \
                   "src_count" : 0, \
                   "ed2k_users": 0, \
                   "kad_users" : 0, \
                   "ed2k_files": 0, \
                   "kad_files" : 0, \
                   "connstate" : { "server_name" : "", \
                        "server_addr" : "", \
                        "ed2k_id"     : 0, \
                        "client_id"   : 0, \
                        "id"          : "", \
                        "kad_firewall": ""  \
                    } \
                 }
        for tag in response[1]:
            tag_type = tag[0]
            value = tag[1]
            if (tag_type == codes.tag['stats_ul_speed']):
                status['ul_speed'] = value
            if (tag_type == codes.tag['stats_dl_speed']):
                status['dl_speed'] = value
            if (tag_type == codes.tag['stats_ul_speed_limit']):
                status['ul_limit'] = value
            if (tag_type == codes.tag['stats_dl_speed_limit']):
                status['dl_limit'] = value
            if (tag_type == codes.tag['stats_ul_queue_len']):
                status['queue_len'] = value
            if (tag_type == codes.tag['stats_total_src_count']):
                status['src_count'] = value
            if (tag_type == codes.tag['stats_ed2k_users']):
                status['ed2k_users'] = value
            if (tag_type == codes.tag['stats_kad_users']):
                status['kad_users'] = value
            if (tag_type == codes.tag['stats_ed2k_files']):
                status['ed2k_files'] = value
            if (tag_type == codes.tag['stats_kad_files']):
                status['kad_files'] = value
            if (tag_type == codes.tag['connstate']):
                status['connstate'] = self.__decode_connstate__(*value)
        return status
    
    def get_connstate(self):
        data = ECPacket((codes.op['get_connstate'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        response = self.send_and_receive_packet(data)
        # structure: (op['misc_data'], [(tag['connstate'], (connstate, [subtags]))])
        # (7, [(5, (29, [(1280, ('212.63.206.35:4242', [(1281, u'eDonkeyServer No2')])), (6, 8955376), (10, 8955376)]))])
        connstate = response[1][0][1][0]
        subtags = response[1][0][1][1]
        return self.__decode_connstate__(connstate, subtags)

    def __decode_connstate__(self, connstate, subtags):
        status = { "server_name" : "", \
                   "server_addr" : "", \
                   "ed2k_id"     : 0, \
                   "client_id"   : 0, \
                   "id"          : "", \
                   "kad_firewall": ""  \
                 }
        for tag in subtags:
            if tag[0] == codes.tag['server']:
                status["server_addr"] = tag[1][0]
                status["server_name"] = tag[1][1][0][1]
            if tag[0] == codes.tag['ed2k_id']:
                status["ed2k_id"] = tag[1]
            if tag[0] == codes.tag['client_id']:
                status["client_id"] = tag[1]
        
        if (connstate & 0x01): # ed2k connected
            status["ed2k"] = "connected"
            highest_lowid_ed2k_kad = 16777216
            status["id"] = "HighID" if (status["client_id"] > highest_lowid_ed2k_kad) else "LowID"
        elif (connstate & 0x02): # ed2k connecting
            status["ed2k"] = "connecting"
        else:
            status["ed2k"] = "Not connected"
        if (connstate & 0x10): # kad running
            if (connstate & 0x04): # kad connected
                status["kad"] = "connected"
                if (connstate & 0x08): # kad firewalled
                    status["kad_firewall"] = "firewalled"
                else:
                    status["kad_firewall"] = "ok"
            else:
                status["kad"] = "Not connected"
        else:
            status["kad"] = "Not running"
        return status
