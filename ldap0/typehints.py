# -*- coding: utf-8 -*-
"""
ldap0.typing - specific type hints
"""

from typing import Dict, List, Tuple

BytesList = List[bytes]
StrList = List[str]

AttrList = StrList

EntryBytes = Dict[bytes, BytesList]
EntryMixed = Dict[str, BytesList]
EntryStr = Dict[str, StrList]

ModList = List[Tuple[int, bytes, BytesList]]
