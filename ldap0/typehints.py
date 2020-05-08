# -*- coding: utf-8 -*-
"""
ldap0.typing - specific type hints
"""

from typing import Dict, List, Sequence, Tuple

from .controls import RequestControl


BytesList = List[bytes]
StrList = List[str]

AttrList = Sequence[str]

EntryBytes = Dict[bytes, BytesList]
EntryMixed = Dict[str, BytesList]
EntryStr = Dict[str, StrList]

ModList = List[Tuple[int, bytes, BytesList]]

RequestControls = Sequence[RequestControl]
