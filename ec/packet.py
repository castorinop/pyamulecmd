import zlib
from struct import pack, unpack
from hashlib import md5
from .tag import ECTag, ReadTag
from . import codes

def ECPacket(data_tuple):
    data = ECPacketData(data_tuple)
    flags = codes.flag['base'] | codes.flag['utf8_numbers']
    if (len(data) > 1024):
        flags |= codes.flag['zlib']
        data = zlib.compress(data)
    return pack('!II',
        flags,
        len(data)) + data

def ECPacketData(data_tuple):
    type, tags = data_tuple
    return pack('!BB',
        type,
        len(tags)) + ''.join([ECTag(name, data) for name,data in tags])

def ReadPacketData(data, utf8_nums = True):
    type, = unpack('!B', data[:1])
    if utf8_nums:
        offset = 2
        num_tags, = unpack('!B', data[1:2])
    else:
        num_tags, = unpack('!H', data[1:3])
        offset = 3
    tags = []
    for i in range(num_tags):
        tag_len, tag_name, tag_data = ReadTag(data[offset:], utf8_nums)
        offset += tag_len
        tags.append((tag_name, tag_data))
    return type, tags

def ECLoginPacket(app, version, password):
    return ECPacket((codes.op['auth_req'],
            [(codes.tag['client_name'],      unicode(app)),
             (codes.tag['client_version'],   unicode(version)),
             (codes.tag['protocol_version'], codes.protocol_version),
             (codes.tag['passwd_hash'],      md5(password).digest())
            ]))

def ECAuthPacket(password):
    return ECPacket((codes.op['auth_passwd'],
            [
             (codes.tag['passwd_hash'],      md5(password).digest())
            ]))

def decode_connstate(connstate, subtags):
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

def decode_status(tags):
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
    for tag in tags:
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
            status['connstate'] = decode_connstate(*value)
    return status

def decode_shared(tags):
    files = []
    for shared_file in tags:
        file = {}
        file['hash'] = shared_file[1][0]
        for (key, value) in shared_file[1][1]:
            if (key == codes.tag['knownfile_xferred']):
                file['uploaded'] = value
            if (key == codes.tag['knownfile_xferred_all']):
                file['uploaded_total'] = value
            if (key == codes.tag['knownfile_req_count']):
                file['requests'] = value
            if (key == codes.tag['knownfile_req_count_all']):
                file['requests_total'] = value
            if (key == codes.tag['knownfile_accept_count']):
                file['accepted_requests'] = value
            if (key == codes.tag['knownfile_accept_count_all']):
                file['accepted_requests_total'] = value
            if (key == codes.tag['knownfile_aich_masterhash']):
                file['aich'] = value
            if (key == codes.tag['partfile_prio']):
                file['prio'] = value
            if (key == codes.tag['partfile_part_status']):
                file['part_status'] = value
            if (key == codes.tag['partfile_name']):
                file['name'] = value
            if (key == codes.tag['partfile_size_full']):
                file['size'] = value
            if (key == codes.tag['partfile_ed2k_link']):
                file['link'] = value
        files.append(file)
    return files

def decode_search(tags):
    files = []
    for search_file in tags:
        file = {}
        file['hash'] = search_file[1][0]
        for (key, value) in search_file[1][1]:
            if (key == codes.tag['partfile_source_count']):
                file['sources'] = value
            if (key == codes.tag['partfile_source_count_xfer']):
                file['sources_complete'] = value
            if (key == codes.tag['partfile_name']):
                file['name'] = value
            if (key == codes.tag['partfile_size_full']):
                file['size'] = value
        files.append(file)
    return files
