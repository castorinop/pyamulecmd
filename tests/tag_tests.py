from ec.tag import *

def test_ECTagDataStr_success():
    assert ECTagDataStr(u'test') == '\x06\x05test\x00'

def test_ECTagDataStr_fail():
    try:
        ECTagDataStr('test')
    except TypeError:
        pass

def test_ECTagDataHash_success():
    assert ECTagDataHash('0123456789abcdef') == '\t\x100123456789abcdef'

def test_ECTagDataHash_fail():
    try:
        ECTagDataHash('too short')
    except ValueError:
        pass

def test_ECTagDataInt_uint8():
    assert ECTagDataInt(127) == '\x02\x01\x7F'

def test_ECTagDataInt_uint16():
    assert ECTagDataInt(31000) == '\x03\x02\x79\x18'

def test_ECTagDataInt_uint32():
    assert ECTagDataInt(4000000) == '\x04\x04\x00\x3d\x09\x00'

def test_ECTagDataInt_uint64():
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
