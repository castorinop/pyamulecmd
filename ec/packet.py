from struct import pack
from hashlib import md5
from tag import ECTag

def ECPacket(data):
    return pack('!II', 0x22, len(data)) + data

def ECPacketData(type, tags):
    return pack('BB', type, len(tags)) + ''.join(tags)

def ECLoginPacket(app, version, password):
    return ECPacket(ECPacketData(0x02,
            [ECTag(0x100, unicode(app)),
             ECTag(0x101, unicode(version)),
             ECTag(0x02, 0x0200),
             ECTag(0x01, md5(password).digest())
            ]))
