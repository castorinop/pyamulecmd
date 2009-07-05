#!/usr/bin/python

import re

print 'flag = {}'
print 'opcode = {}'
print 'tagcode = {}'
print 'detail = {}'
print 'search = {}'
print 'value = {}'
print 'prefs = {}'
with open("ECCodes.abstract") as f:
    for line in f:
        m = re.match(r"EC_FLAG_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'flag[\''+m.group('type').lower() + '\'] = ' + m.group('code')
        m = re.match(r"EC_OP_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'opcode[\''+m.group('type').lower() + '\'] = ' + m.group('code')
        m = re.match(r"[\t ]*EC_TAG_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'tag[\''+m.group('type').lower() + '\'] = ' + m.group('code')
        m = re.match(r"EC_DETAIL_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'detail[\''+m.group('type').lower() + '\'] = ' + m.group('code')
        m = re.match(r"EC_SEARCH_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'search[\''+m.group('type').lower() + '\'] = ' + m.group('code')
        m = re.match(r"EC_VALUE_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'value[\''+m.group('type').lower() + '\'] = ' + m.group('code')
        m = re.match(r"EC_PREFS_(?P<type>[A-Z0-9_]*)[\t ]*(?P<code>0x[0-9a-fA-F]+)", line)
        if m != None:
            print 'prefs[\''+m.group('type').lower() + '\'] = ' + m.group('code')