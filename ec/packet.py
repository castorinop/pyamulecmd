from struct import pack, unpack
from hashlib import md5
from tag import ECTag, ReadTag
import codes

def ECPacket(data_tuple):
    data = ECPacketData(data_tuple)
    return pack('!II',
        codes.flag['base'] | codes.flag['utf8_numbers'],
        len(data)) + data

def ECPacketData(data_tuple):
    type, tags = data_tuple
    return pack('BB',
        type,
        len(tags)) + ''.join([ECTag(name, data) for name,data in tags])

class NotEnoughDataError(Exception):
    def __str__(self):
        return 'Not enough data provided'

def ReadPacket(data):
    if len(data) < 8:
        raise NotEnoughDataError
    flags, data_len = unpack("!II", data[:8])
    if len(data) < (8 + data_len):
        raise NotEnoughDataError
    return ReadPacketData(data[8:8+data_len])

def ReadPacketData(data):
    type, num_tags = unpack('BB', data[:2]) 
    offset = 2
    tags = []
    for i in range(num_tags):
        tag_len, tag_name, tag_data = ReadTag(data[offset:])
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
