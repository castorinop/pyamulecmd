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
    tag_value = ord(data[:name_len].decode("utf-8"))
    tag_name = tag_value/2
    tag_has_subtags = (tag_value%2 == 1)
    if tag_has_subtags:
        pass
    data_len, data = ReadTagData(data[name_len:])
    return name_len + data_len , tag_name, data

#\x07\x01
#\x0b\x02 \x09\x01
#\x14\x02\x01\x00\x08

def ReadTagData(data):
    type = ord(data[0])
    length = ord(data[1])
    tag_data = data[2:2+length]
    if type in [tagtype['uint8'], tagtype['uint16'], tagtype['uint32'], tagtype['uint64']]:
        value = ReadInt(tag_data)
    elif type == tagtype['hash16']:
        value = ReadHash(tag_data)
    elif type == tagtype['string']:
        value = ReadString(tag_data)
    else:
        raise TypeError
    return length+2, value

def ReadInt(data):
    fmtStr = { 1: "!B",
               2: "!H",
               4: "!I",
               8: "!Q"}.get(len(data), "")
    if fmtStr == "":
        print "Warning: Wrong length for integer"
        return 0
    return unpack(fmtStr, data)[0]

def ReadString(data):
    return unicode(data[:-1])

def ReadHash(data):
    if len(data) != 16:
        raise ValueError
    return data