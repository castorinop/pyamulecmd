from struct import pack
import types

def ECTag(name, data):
	return unicode.encode(unichr(2*name), "utf-8") + ECTagData(data)

def ECTagData(data):
    if type(data) == types.UnicodeType:
        return ECTagDataStr(data)
    elif type(data) == types.IntType:
        return ECTagDataInt(data)
    elif type(data) == types.StringType:
        return ECTagDataHash(data)
    else:
        raise TypeError('Argument of invalid type specified')

def ECTagDataStr(data):
    data += '\0'
    fmtStr = '!BB'+str(len(data))+'s'
    return pack(fmtStr, 0x06, len(data), unicode.encode(data, "utf-8"))

def ECTagDataHash(data):
    if len(data) != 16:
        raise ValueError('length of hash not 16')
    return pack('!BB16s', 0x09, 0x10, data)

def ECTagDataInt(data):
    if data <= 0xFF:
        fmtStr = '!BBB'
        tagType = 0x02
        len = 1
    elif data <= 0xFFFF:
        fmtStr = '!BBH'
        tagType = 0x03
        len = 2
    elif data <= 0xFFFFFF:
        fmtStr = '!BBI'
        tagType = 0x04
        len = 4
    else:
        fmtStr = '!BBL'
        tagType = 0x05
        len = 8
    return pack(fmtStr, tagType, len, data)