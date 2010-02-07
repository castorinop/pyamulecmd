from .packet import ECLoginPacket, ECPacket, ReadPacketData
from struct import unpack
import asynchat, socket, zlib
from . import codes, packet

class ConnectionFailedError(Exception):
    def __init__(self, error):
        self.error = error
    def __str__(self):
        return repr(self.error)

class conn:
    """Remote-control aMule(d) using "External connections."""
    def __init__(self, password, host="localhost", port=4712, app="pyEC", ver="0.5"):
        """Connect to a running aMule(d) core.
        
        Parameters:
        - password (required): Password for the connection
        - host (default: "localhost"): Host where core is running
        - port (default: 4712): Port where core is running
        - app (default "pyEC"): application name transmitted on login
        - ver (default: "0.5"): application version
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        try:
            self.sock.connect((host,port))
        except (socket.error):
            raise ConnectionFailedError("Couldn't connect to socket")
        packet_req = ECLoginPacket(app, ver, password)

        type, tags = self.send_and_receive_packet(packet_req)
        if type != codes.op['auth_ok']:
            raise ConnectionFailedError("Authentication failed")
    def __del__(self):
        self.sock.close()

    def send_packet(self, data):
        self.sock.send(data)

    def receive_packet(self):
        header_data = self.sock.recv(8)
        if (not header_data) or (len(header_data) != 8):
            raise ConnectionFailedError("Invalid packet header: received %d of 8 expected bytes" % len(header_data))
        flags, data_len = unpack("!II", header_data)
        packet_data = self.sock.recv(data_len)
        if (not packet_data) or (len(packet_data) != data_len):
            raise ConnectionFailedError("Invalid packet body: received %d of %d expected bytes" % (len(packet_data), data_len))
        if (flags & codes.flag['zlib']):
            packet_data = zlib.decompress(packet_data)
        utf8_nums = (flags & codes.flag['utf8_numbers'] != 0)
        return ReadPacketData(packet_data, utf8_nums)

    def send_and_receive_packet(self, data):
        self.send_packet(data)
        return self.receive_packet()

    def get_status(self):
        """Get status information from remote core.
        
        Returns a dictionary with the following keys:
        - "ul_speed": upload speed in Bytes/s
        - "dl_speed": download speed in Bytes/s
        - "ul_limit": upload limit, 0 is unlimited
        - "dl_limit": download limit, 0 is unlimited
        - "queue_len": number of clients waiting in the upload queue
        - "src_count": number of download sources
        - "ed2k_users": users in the eD2k network
        - "kad_users": users in the kademlia network
        - "ed2k_files": files in the eD2k network
        - "kad_files": files in the kademlia network
        - "connstate": connection status, dictionary with the following keys:
            - "ed2k": ed2k network status. possible values: "connected", "connecting", "Not connected"
            - "kad": kademlia network status. possible values: "connected", "Not connected", "Not running"
            - "server_addr": server address in ip:port format
            - "ed2k_id": identification number for the ed2k network
            - "client_id": identification number for the kademlia network
            - "id": connection status. possible values: "LowID", "HighID", ""
            - "kad_firewall": kademlia status. possible values: "ok", "firewalled", ""

        """
        data = ECPacket((codes.op['stat_req'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        response = self.send_and_receive_packet(data)
        # structure: (op['stats'], [(tag['stats_ul_speed'], 0), (tag['stats_dl_speed'], 0), (tag['stats_ul_speed_limit'], 0), (tag['stats_dl_speed_limit'], 0), (tag['stats_ul_queue_len'], 0), (tag['stats_total_src_count'], 0), (tag['stats_ed2k_users'], 3270680), (tag['stats_kad_users'], 0), (tag['stats_ed2k_files'], 279482794), (tag['stats_kad_files'], 0), (tag['connstate'], ((connstate, [subtags])))])
        return packet.decode_status(response[1])
        
    
    def get_connstate(self):
        """Get connection status information from remore core.
        
        Returns a dictionary with the following keys:
        - "ed2k": ed2k network status. possible values: "connected", "connecting", "Not connected"
        - "kad": kademlia network status. possible values: "connected", "Not connected", "Not running"
        - "server_addr": server address in ip:port format
        - "ed2k_id": identification number for the ed2k network
        - "client_id": identification number for the kademlia network
        - "id": connection status. possible values: "LowID", "HighID", ""
        - "kad_firewall": kademlia status. possible values: "ok", "firewalled", ""
        """
        data = ECPacket((codes.op['get_connstate'], [(codes.tag['detail_level'], codes.detail['cmd'])]))
        response = self.send_and_receive_packet(data)
        # structure: (op['misc_data'], [(tag['connstate'], (connstate, [subtags]))])
        connstate = response[1][0][1][0]
        subtags = response[1][0][1][1]
        return packet.decode_connstate(connstate, subtags)

    def shutdown(self):
        """Shutdown remote core"""
        data = ECPacket((codes.op['shutdown'],[]))
        self.send_packet(data)

    def connect(self):
        """Connect remote core to activated networks.
        
        Returns a tuple with a boolean indicating success and a list of strings with status messages."""
        data = ECPacket((codes.op['connect'],[]))
        response = self.send_and_receive_packet(data)
        # (op['failed'], [(tag['string'], u'All networks are disabled.')])
        # (op['strings'], [(tag['string'], u'Connecting to eD2k...'), (tag['string'], u'Connecting to Kad...')])
        return (response[0] != codes.op['failed'], map(lambda s:s[1],response[1]))

    def connect_server(self):
        """Connect remote core to eD2k network.
        
        Returns a boolean indicating success."""
        data = ECPacket((codes.op['server_connect'],[]))
        response = self.send_and_receive_packet(data)
        return response[0] != codes.op['failed']

    def connect_kad(self):
        """Connect remote core to kademlia network.
        
        Returns a boolean indicating success."""
        data = ECPacket((codes.op['kad_start'],[]))
        response = self.send_and_receive_packet(data)
        return response[0] != codes.op['failed']

    def disconnect(self):
        """Disconnect remote core from networks.
        
        Returns a tuple with a boolean indicating success and a list of strings with status messages."""
        # (op['noop'], [])
        # (op['strings'], [(tag['string'], u'Disconnected from eD2k.'), (tag['string'], u'Disconnected from Kad.')])
        data = ECPacket((codes.op['disconnect'],[]))
        response = self.send_and_receive_packet(data)
        return (response[0] == codes.op['strings'], map(lambda s:s[1],response[1]))

    def disconnect_server(self):
        """Disconnect remote core from eD2k network."""
        data = ECPacket((codes.op['server_disconnect'],[]))
        response = self.send_and_receive_packet(data)

    def disconnect_kad(self):
        """Disconnect remote core from kademlia network."""
        data = ECPacket((codes.op['kad_stop'],[]))
        response = self.send_and_receive_packet(data)

    def reload_shared(self):
        """Reload shared files on remote core."""
        data = ECPacket((codes.op['sharedfiles_reload'],[]))
        response = self.send_and_receive_packet(data)

    def reload_ipfilter(self):
        """Reload ipfilter on remote core."""
        data = ECPacket((codes.op['ipfilter_reload'],[]))
        response = self.send_and_receive_packet(data)

    def get_shared(self):
        """Get list of shared files.
        
        Returns a list of shared files. The data for a file is stored in a dictionary with the following keys:
        - "name": file name
        - "size": size in Bytes
        - "link": eD2k link to the file
        - "hash": file hash stored in 16 Byte
        - "prio": upload priority, Auto is prefixed by 1, e.g. 12 is Auto (High)
            - 4: Very Low
            - 0: Low
            - 1: Normal
            - 2: High
            - 3: Very High
            - 6: Release
        - "aich": file's AICH hash (see: http://wiki.amule.org/index.php/AICH)
        - "part_status": unknown
        - "uploaded": Bytes uploaded during the current session
        - "uploaded_total": total Bytes uploaded
        - "requests": number of requests for this file during the current session
        - "requests_total": total number of requests for this file
        - "accepted": number of accepted requests for this file during the current session
        - "accepted_total": total number of accepted requests for this file
        """
        data = ECPacket((codes.op['get_shared_files'],[]))
        response = self.send_and_receive_packet(data)
        return packet.decode_shared(response[1])

    def search_local(self, keywords):
        self.search(codes.search['local'],keywords)

    def search_global(self, keywords):
        self.search(codes.search['global'],keywords)

    def search_kad(self, keywords):
        self.search(codes.search['kad'],keywords)


    def search(self, type, keywords):
        packet = (codes.op['search_start'], \
            [(codes.tag['search_type'],(type, \
                [(codes.tag['search_name'],unicode(keywords))] \
            ))] \
        )
        data = ECPacket(packet)
        response = self.send_and_receive_packet(data)
        print repr(response)

    def search_progress(self):
        data = ECPacket((codes.op['search_progress'],[]))
        response = self.send_and_receive_packet(data)
        print repr(response)
    
    def search_results(self):
        data = ECPacket((codes.op['search_results'],[]))
        response = self.send_and_receive_packet(data)
        print repr(response)
