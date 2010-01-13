from ec.tag import *
from ec import codes

def test_ECTagDataStr_success():
    print ECTagDataStr(u'test')
    assert ECTagDataStr(u'test') == '\x06\x05test\x00'

def test_ECTagDataStr_fail():
    try:
        ECTagDataStr('test')
    except TypeError:
        pass

def test_ECTagDataHash_success():
    print ECTagDataHash('0123456789abcdef')
    assert ECTagDataHash('0123456789abcdef') == '\x09\x100123456789abcdef'

def test_ECTagDataHash_fail():
    try:
        ECTagDataHash('too short')
    except ValueError:
        pass

def test_ECTagDataInt_uint8():
    print ECTagDataInt(127)
    assert ECTagDataInt(127) == '\x02\x01\x7F'

def test_ECTagDataInt_uint16():
    print ECTagDataInt(31000)
    assert ECTagDataInt(31000) == '\x03\x02\x79\x18'

def test_ECTagDataInt_uint32():
    print ECTagDataInt(4000000)
    assert ECTagDataInt(4000000) == '\x04\x04\x00\x3d\x09\x00'

def test_ECTagDataInt_uint64():
    print ECTagDataInt(80000000000000000L)
    assert ECTagDataInt(80000000000000000L) == '\x05\x08\x01\x1c\x37\x93\x7e\x08\x00\x00'

def test_ECTagData_Unicode_String():
    test_string = u'String'
    assert ECTagData(test_string) == ECTagDataStr(test_string)

def test_ECTagData_Int():
    test_int = 923578123217
    assert ECTagData(test_int) == ECTagDataInt(test_int)

def test_ECTagData_String():
    test_hash = '0123456789abcdef'
    assert ECTagData(test_hash) == ECTagDataHash(test_hash)

def test_ECTagData_fail():
    try:
        ECTagData(1.0)
    except TypeError:
        pass

def test_ECTag():
    test_data = 123
    assert ECTag(0x101,test_data) == '\xc8\x82' + ECTagData(test_data)

def test_ReadInt_uint8():
    test_int = 73
    test_data = ECTagDataInt(test_int)
    assert ReadInt(test_data[2:]) == test_int

def test_ReadInt_uint16():
    test_int = 14092
    test_data = ECTagDataInt(test_int)
    assert ReadInt(test_data[2:]) == test_int

def test_ReadInt_uint32():
    test_int = 312353512
    test_data = ECTagDataInt(test_int)
    assert ReadInt(test_data[2:]) == test_int

def test_ReadInt_uint64():
    test_int = 8414561238214513L
    test_data = ECTagDataInt(test_int)
    assert ReadInt(test_data[2:]) == test_int

def test_ReadInt_invalid():
    test_data = "\xFF\xFF\xFF"
    try:
        ReadInt(test_data)
    except ValueError:
        pass


def test_ReadString():
    test_string = u'Die Welt ist rund.'
    test_data = ECTagDataStr(test_string)
    print repr(ReadString(test_data[2:]))
    assert ReadString(test_data[2:]) == test_string

def test_ReadHash():
    test_hash = 'abcdef0123456789'
    test_data = ECTagDataHash(test_hash)
    assert ReadHash(test_data[2:]) == test_hash

def test_ReadHash_fail():
    try:
        ReadHash('too short')
    except ValueError:
        pass

def test_ReadTagData_uint8():
    test_int = 73
    test_data = ECTagDataInt(test_int)
    print repr(test_data)
    print ReadTagData(test_data)
    assert ReadTagData(test_data) == (3, test_int)

def test_ReadTagData_uint16():
    test_int = 14092
    test_data = ECTagDataInt(test_int)
    print ReadTagData(test_data)
    assert ReadTagData(test_data) == (4, test_int)

def test_ReadTagData_uint32():
    test_int = 312353512
    test_data = ECTagDataInt(test_int)
    assert ReadTagData(test_data) == (6, test_int)

def test_ReadTagData_uint64():
    test_int = 8414561238214513L
    test_data = ECTagDataInt(test_int)
    assert ReadTagData(test_data) == (10, test_int)

def test_ReadTagData_String():
    test_string = u'Die Welt ist rund.'
    test_data = ECTagDataStr(test_string)
    assert ReadTagData(test_data) == (21, test_string)

def test_ReadTagData_Hash():
    test_hash = 'abcdef0123456789'
    test_data = ECTagDataHash(test_hash)
    assert ReadTagData(test_data) == (18, test_hash)

def test_ReadTagData_fail():
    try:
        ReadTagData('abc')
    except TypeError:
        pass

def test_ReadTag_mode_1char():
    test_name = codes.tag['passwd_hash'] # 0x02
    test_data = '1234567890abcdef'
    assert ReadTag(ECTag(test_name,test_data)) == (19, test_name, test_data)

def test_ReadTag_mode_2char():
    test_name = codes.tag['client_version'] # 0x101
    test_data = u'123'
    assert ReadTag(ECTag(test_name,test_data)) == (8, test_name, test_data)

def test_ReadTag_mode_3char():
    test_name = 0xFFF
    test_data = 123
    assert ReadTag(ECTag(test_name,test_data)) == (6, test_name, test_data)

def test_ReadTag_fail_1():
    try:
        ReadTag('\x80')
    except ValueError:
        pass

def test_ReadTag_fail_2():
    try:
        ReadTag('\xc2')
    except ValueError:
        pass

def test_ReadTag_fail_3():
    try:
        ReadTag('\xf0')
    except ValueError:
        pass