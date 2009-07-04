protocol_version       = 0x0200

flag.base              = 0x00000020
flag.zlib              = 0x00000001
flag.utf8_numbers      = 0x00000002
flag.has_id            = 0x00000004
flag.accepts           = 0x00000010
flag.unknown_mask      = 0xff7f7f08

opcode.noop            = 0x01

opcode.auth_req        = 0x02
opcode.auth_fail       = 0x03
opcode.auth_ok         = 0x04

opcode.failed          = 0x05
opcode.strings         = 0x06
opcode.misc_data       = 0x07
opcode.shutdown        = 0x08
opcode.add_link        = 0x09
opcode.stat_req        = 0x0A
opcode.get_conn_state  = 0x0B
opcode.stats           = 0x0C

tag.passwd_hash        = 0x01
tag.protocol_version   = 0x02
tag.client_name        = 0x100
tag.client_version     = 0x101
tag.client_mod         = 0x102