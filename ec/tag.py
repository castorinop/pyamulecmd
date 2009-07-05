from struct import pack, unpack
import types
from tagtypes import tagtype

def ECTag(name, data):
	return unicode.encode(unichr(2*name), "utf-8") + ECTagData(data)

def ECTagData(data):
    if type(data) == types.UnicodeType:
        return ECTagDataStr(data)
    elif type(data) in [types.IntType, types.LongType] :
        return ECTagDataInt(data)
    elif type(data) == types.StringType:
        return ECTagDataHash(data)
    else:
        raise TypeError('Argument of invalid type specified')

def ECTagDataStr(data):
    data += '\0'
    fmtStr = '!BB'+str(len(data))+'s'
    return pack(fmtStr, tagtype['string'], len(data), unicode.encode(data, "utf-8"))

def ECTagDataHash(data):
    if len(data) != 16:
        raise ValueError('length of hash not 16')
    return pack('!BB16s', tagtype['hash16'], 16, data)

def ECTagDataInt(data):
    if data <= pow(2,8):
        fmtStr = '!BBB'
        tagType = tagtype['uint8']
        len = 1
    elif data <= pow(2,16):
        fmtStr = '!BBH'
        tagType = tagtype['uint16']
        len = 2
    elif data <= pow(2,32):
        fmtStr = '!BBI'
        tagType = tagtype['uint32']
        len = 4
    else:
        fmtStr = '!BBQ'
        tagType = tagtype['uint64']
        len = 8
    return pack(fmtStr, tagType, len, data)

def ReadTag(data):
    if ord(data[0]) in range(0x7F):
        name_len = 1
    elif ord(data[0]) in range(0xc3,0xdf):
        name_len = 2
    elif ord(data[0]) in range(0xe0,0xef):
        name_len = 3
    else:
        raise ValueError
    tag_name = ord(data[:name_len].decode("utf-8"))/2
    data_len, data = ReadTagData(data[name_len:])
    return name_len + data_len , tag_name, data

def ReadTagData(data):
    type = ord(data[0])
    if type in [tagtype['uint8'], tagtype['uint16'], tagtype['uint32'], tagtype['uint64']]:
        len, value = ReadInt(data[1:])
    elif type == tagtype['hash16']:
        len, value = ReadHash(data[1:])
    elif type == tagtype['string']:
        len, value = ReadString(data[1:])
    else:
        raise TypeError
    return len + 1, value

def ReadInt(data):
    len = unpack('!B', data[0])[0]
    if len == 1:
        fmtStr = '!B'
    elif len == 2:
        fmtStr = '!H'
    elif len == 4:
        fmtStr = '!I'
    else:
        fmtStr = '!Q'
    return len +1 , unpack(fmtStr, data[1:])[0]

def ReadString(data):
    len = ord(data[0])
    return len+1, unicode(data[1:len])

def ReadHash(data):
    len = ord(data[0])
    if len != 16:
        raise ValueError
    return len+1, data[1:len+1]