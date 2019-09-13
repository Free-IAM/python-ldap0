# -*- coding: utf-8 -*-
"""
ldap0.msad - proprietary stuff for MS Actiev Directory
"""

import struct

__all__ = [
    'sid2sddl',
    'sddl2sid',
]


def sddl2sid(sddl: str) -> bytes:
    """
    convert SDDL str representation of a SID to bytes

    implements the inverse of function sid2sddl()
    """
    sid_components = sddl.split('-')
    srl_byte = int(sid_components[1])
    number_sub_id_byte = len(sid_components)-3
    result_list = [bytes([srl_byte, number_sub_id_byte])]
    iav_buf = struct.pack('!Q', int(sid_components[2]))[2:]
    result_list.append(iav_buf)
    result_list.extend([
        struct.pack('<I', int(s))
        for s in sid_components[3:]
    ])
    return b''.join(result_list)


def sid2sddl(sid: bytes) -> str:
    """
    convert SID bytes to SDDL str representation

    implements the inverse of sddl2sid()
    """
    srl = sid[0]
    number_sub_id = sid[1]
    iav = struct.unpack('!Q', b'\x00\x00'+sid[2:8])[0]
    sub_ids = [
        struct.unpack('<I', sid[8+4*i:12+4*i])[0]
        for i in range(number_sub_id)
    ]
    return 'S-%d-%d-%s' % (
        srl,
        iav,
        '-'.join([str(s) for s in sub_ids]),
    )
