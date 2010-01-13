from struct import pack, unpack
import types
from .tagtypes import tagtype

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

def ReadTag(data, utf8_nums = True):
    if utf8_nums:
        if ord(data[0]) in range(0x7F):
            name_len = 1
        elif ord(data[0]) in range(0xc3,0xdf):
            name_len = 2
        elif ord(data[0]) in range(0xe0,0xef):
            name_len = 3
        else:
            raise ValueError("%s not a valid unicode range" % ord(data[0]))
        tag_value = ord(data[:name_len].decode("utf-8"))
    else:
        name_len = 2
        tag_value, = unpack("!H",data[:2])
    tag_name = tag_value/2
    tag_has_subtags = (tag_value%2 == 1)
    data_len, data = ReadTagData(data[name_len:], tag_has_subtags, utf8_nums)
    return name_len + data_len , tag_name, data

def ReadTagData(data, tag_has_subtags=False, utf8_nums = True):
    type = ord(data[0])
    if utf8_nums:
        length = ord(data[1])
        if ord(data[1]) in range(0x7F):
            utf_len = 1
        elif ord(data[1]) in range(0xc3,0xdf):
            utf_len = 2
        elif ord(data[1]) in range(0xe0,0xef):
            utf_len = 3
        else:
            raise ValueError("%s not a valid unicode range" % hex(ord(data[1])))
        length = ord(data[1:1+utf_len].decode("utf-8"))
        tag_data = data[1+utf_len:]
    else:
        length, = unpack('!I', data[1:5])
        utf_len = 4
        tag_data = data[5:]
    if tag_has_subtags:
        if utf8_nums:
            num_subtags = ord(tag_data[0])
            offset=1
        else:
            num_subtags, = unpack('!H', tag_data[:2])
            offset=2
        subtags = []
        subtag_data = tag_data
        length = 1+utf_len+offset
        for i in range(num_subtags):
            subtag_len, subtag_name, subtag_data = ReadTag(tag_data[offset:],utf8_nums)
            offset += subtag_len
            length += subtag_len
            subtags.append((subtag_name, subtag_data))
        tag_data = tag_data[offset:]
    if type in [tagtype['uint8'], tagtype['uint16'], tagtype['uint32'], tagtype['uint64']]:
        intlen = 1
        if type == tagtype['uint16']:
            intlen = 2
        if type == tagtype['uint32']:
            intlen = 4
        if type == tagtype['uint64']:
            intlen = 8
        if tag_has_subtags:
            length += intlen
        value = ReadInt(tag_data[:intlen])
    elif type == tagtype['hash16']:
        if tag_has_subtags:
            length += 16
        value = ReadHash(tag_data[:16])
    elif type == tagtype['string']:
        value = ReadString(tag_data)
        if tag_has_subtags:
            length += len(value)+1
    elif type == tagtype['ipv4']:
        if tag_has_subtags:
            length += 6
        value = ReadIPv4(tag_data)
    elif type == tagtype['custom']:
        value = tag_data[:length]
    else:
        raise TypeError("Invalid tag type 0x%x"%type)
    if tag_has_subtags:
        return length, (value, subtags)
    return length+utf_len+1, value

def ReadInt(data):
    fmtStr = { 1: "!B",
               2: "!H",
               4: "!I",
               8: "!Q"}.get(len(data), "")
    if fmtStr == "":
        raise ValueError("ReadInt: Wrong length for number: %d [%s]" %(len(data),repr(data)))
    return unpack(fmtStr, data)[0]

def ReadIPv4(data):
    ipv4, port = unpack("!IH",data[:6])
    a = (ipv4 & 0xff000000) >> 24
    b = (ipv4 & 0xff0000) >> 16
    c = (ipv4 & 0xff00) >> 8
    d = ipv4 & 0xff
    return "%d.%d.%d.%d:%d"% (a,b,c,d,port)

def ReadString(data):
    return unicode(data[:data.find('\x00')])

def ReadHash(data):
    if len(data) != 16:
        raise ValueError("Expected length 16, got length %d"%(len(data)))
    return data