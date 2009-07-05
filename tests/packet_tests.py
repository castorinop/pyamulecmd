from ec.packet import *
import types

def test_ECPacketData():
    assert ECPacketData(0x02,['tag1','tag2']) == '\x02\x02tag1tag2'

def test_ECPacket():
    test_data = 'packet data'
    assert ECPacket(test_data) == '\x00\x00\x00\x22\x00\x00\x00\x0B'+test_data

def test_ECLoginPacket():
    assert ECLoginPacket("amule-remote", "0x0001", "aaa") == '\x00\x00\x00\x22\x00\x00\x00\x36\x02\x04\xc8\x80\x06\x0d\x61\x6d\x75\x6c\x65\x2d\x72\x65\x6d\x6f\x74\x65\x00\xc8\x82\x06\x07\x30\x78\x30\x30\x30\x31\x00\x04\x03\x02\x02\x00\x02\x09\x10\x47\xbc\xe5\xc7\x4f\x58\x9f\x48\x67\xdb\xd5\x7e\x9c\xa9\xf8\x08'

def test_ReadPacket_short_1():
    try:
        ReadPacket('')
    except NotEnoughDataError:
        pass

def test_ReadPacket_short_2():
    try:
        ReadPacket('\x00\x00\x00\x01\x00\x00\x00\x0Fabcdef')
    except NotEnoughDataError:
        pass

def test_NotEnoughDataError_str():
    try:
        raise NotEnoughDataError
    except NotEnoughDataError as e:
        assert isinstance(NotEnoughDataError.__str__(e), types.StringTypes)

def test_ReadPacket():
    app = "test-app"
    version = "132.0"
    password = "passwd"
    assert ReadPacket(ECLoginPacket(app,version,password)) == (codes.op['auth_req'],
        [(codes.tag['client_name'],      unicode(app)),
         (codes.tag['client_version'],   unicode(version)),
         (codes.tag['protocol_version'], codes.protocol_version),
         (codes.tag['passwd_hash'],      md5(password).digest())
        ])