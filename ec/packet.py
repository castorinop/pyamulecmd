from struct import pack
from hashlib import md5
from tag import ECTag
import codes

def ECPacket(data):
    return pack('!II',
        codes.flag['base'] | codes.flag['utf8_numbers'],
        len(data)) + data

def ECPacketData(type, tags):
    return pack('BB',
        type,
        len(tags)) + ''.join(tags)

def ECLoginPacket(app, version, password):
    return ECPacket(
        ECPacketData(codes.op['auth_req'],
            [ECTag(codes.tag['client_name'],      unicode(app)),
             ECTag(codes.tag['client_version'],   unicode(version)),
             ECTag(codes.tag['protocol_version'], codes.protocol_version),
             ECTag(codes.tag['passwd_hash'],      md5(password).digest())
            ]))
