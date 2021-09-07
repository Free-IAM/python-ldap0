# -*- coding: utf-8 -*-
"""
ldap0.controls.syncrepl - classes for Content Synchronization Controls
(see RFC 4533)
"""

from typing import Optional, Sequence

from uuid import UUID

# Imports from pyasn1
from pyasn1.type import namedtype, namedval, univ, tag, constraint
from pyasn1.codec.ber import encoder, decoder
from pyasn1_modules.rfc2251 import LDAPString

from . import RequestControl, ResponseControl, KNOWN_RESPONSE_CONTROLS
from ..extop import IntermediateResponse, INTERMEDIATE_RESPONSE_REGISTRY


__all__ = [
    'SyncRequestControl',
    'SyncStateControl',
    'SyncDoneControl',
    'SyncInfoMessage',
    'SyncInfoNewCookie',
    'SyncInfoRefreshDelete',
    'SyncInfoRefreshPresent',
    'SyncInfoIDSet',
]


class SyncUUID(univ.OctetString):
    """
    syncUUID ::= OCTET STRING (SIZE(16))
    """
    subtypeSpec = constraint.ValueSizeConstraint(16, 16)


class SyncCookie(univ.OctetString):
    """
    syncCookie ::= OCTET STRING
    """


class SyncRequestMode(univ.Enumerated):
    """
    mode ENUMERATED {
        -- 0 unused
        refreshOnly       (1),
        -- 2 reserved
        refreshAndPersist (3)
    }
    """
    namedValues = namedval.NamedValues(
        ('refreshOnly', 1),
        ('refreshAndPersist', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(1, 3)


class SyncRequestValue(univ.Sequence):
    """
    syncRequestValue ::= SEQUENCE {
        mode ENUMERATED {
            -- 0 unused
            refreshOnly       (1),
            -- 2 reserved
            refreshAndPersist (3)
        }
        cookie     syncCookie OPTIONAL,
        reloadHint BOOLEAN DEFAULT FALSE
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mode', SyncRequestMode()),
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('reloadHint', univ.Boolean(False))
    )


class SyncRequestControl(RequestControl):
    """
    The Sync Request Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.1 and the
    controlValue, an OCTET STRING, contains a BER-encoded
    syncRequestValue.  The criticality field is either TRUE or FALSE.
    [...]
    The Sync Request Control is only applicable to the SearchRequest
    Message.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.1'

    def __init__(self, criticality=1, cookie=None, mode='refreshOnly', reloadHint=False):
        self.criticality = criticality
        self.cookie = cookie
        self.mode = mode
        self.reloadHint = reloadHint

    def encode(self):
        rcv = SyncRequestValue()
        rcv.setComponentByName('mode', SyncRequestMode(self.mode))
        if self.cookie is not None:
            rcv.setComponentByName('cookie', SyncCookie(self.cookie))
        if self.reloadHint is not None:
            rcv.setComponentByName('reloadHint', univ.Boolean(self.reloadHint))
        return encoder.encode(rcv)


class SyncStateOp(univ.Enumerated):
    """
    state ENUMERATED {
        present (0),
        add (1),
        modify (2),
        delete (3)
    }
    """
    namedValues = namedval.NamedValues(
        ('present', 0),
        ('add', 1),
        ('modify', 2),
        ('delete', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(0, 1, 2, 3)


class SyncStateValue(univ.Sequence):
    """
    syncStateValue ::= SEQUENCE {
        state ENUMERATED {
            present (0),
            add (1),
            modify (2),
            delete (3)
        },
        entryUUID syncUUID,
        cookie    syncCookie OPTIONAL
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('state', SyncStateOp()),
        namedtype.NamedType('entryUUID', SyncUUID()),
        namedtype.OptionalNamedType('cookie', SyncCookie())
    )


class SyncStateControl(ResponseControl):
    """
    The Sync State Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.2 and the
    controlValue, an OCTET STRING, contains a BER-encoded SyncStateValue.
    The criticality is FALSE.
    [...]
    The Sync State Control is only applicable to SearchResultEntry and
    SearchResultReference Messages.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.2'
    opnames = ('present', 'add', 'modify', 'delete')

    def decode(self, encodedControlValue: bytes):
        d, _ = decoder.decode(encodedControlValue, asn1Spec=SyncStateValue())
        self.state = self.__class__.opnames[int(d['state'])]
        uuid = UUID(bytes=bytes(d['entryUUID']))
        self.entryUUID = str(uuid)
        cookie = d['cookie']
        if cookie.hasValue():
            self.cookie = bytes(cookie)
        else:
            self.cookie = None

    def __repr__(self):
        return '{}(state={}, entryUUID={!r}{})'.format(
            self.__class__.__name__,
            self.state,
            self.entryUUID,
            '' if self.cookie is None else ', cookie={!r}'.format(self.cookie),
        )


KNOWN_RESPONSE_CONTROLS.reg(SyncStateControl)


class SyncDoneValue(univ.Sequence):
    """
    syncDoneValue ::= SEQUENCE {
        cookie          syncCookie OPTIONAL,
        refreshDeletes  BOOLEAN DEFAULT FALSE
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDeletes', univ.Boolean(False))
    )


class SyncDoneControl(ResponseControl):
    """
    The Sync Done Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.3 and the
    controlValue contains a BER-encoded syncDoneValue.  The criticality
    is FALSE (and hence absent).
    [...]
    The Sync Done Control is only applicable to the SearchResultDone
    Message.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.3'

    def decode(self, encodedControlValue: bytes):
        d, _ = decoder.decode(encodedControlValue, asn1Spec=SyncDoneValue())
        cookie = d['cookie']
        if cookie.hasValue():
            self.cookie = bytes(cookie)
        else:
            self.cookie = None
        self.refreshDeletes = bool(d['refreshDeletes'])

    def __repr__(self):
        return '{}({}refreshDeletes={})'.format(
            self.__class__.__name__,
            '' if self.cookie is None else 'cookie={!r}, '.format(self.cookie),
            self.refreshDeletes,
        )


KNOWN_RESPONSE_CONTROLS.reg(SyncDoneControl)


class RefreshDelete(univ.Sequence):
    """
    refreshDelete  [1] SEQUENCE {
        cookie         syncCookie OPTIONAL,
        refreshDone    BOOLEAN DEFAULT TRUE
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDone', univ.Boolean(True))
    )


class RefreshPresent(univ.Sequence):
    """
    refreshPresent [2] SEQUENCE {
        cookie         syncCookie OPTIONAL,
        refreshDone    BOOLEAN DEFAULT TRUE
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDone', univ.Boolean(True))
    )


class SyncUUIDs(univ.SetOf):
    """
    syncUUIDs      SET OF syncUUID
    """
    componentType = SyncUUID()


class SyncIdSet(univ.Sequence):
    """
    syncIdSet      [3] SEQUENCE {
        cookie         syncCookie OPTIONAL,
        refreshDeletes BOOLEAN DEFAULT FALSE,
        syncUUIDs      SET OF syncUUID
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDeletes', univ.Boolean(False)),
        namedtype.NamedType('syncUUIDs', SyncUUIDs())
    )


class SyncInfoValue(univ.Choice):
    """
    syncInfoValue ::= CHOICE {
        newcookie      [0] syncCookie,
        refreshDelete  [1] SEQUENCE {
            cookie         syncCookie OPTIONAL,
            refreshDone    BOOLEAN DEFAULT TRUE
        },
        refreshPresent [2] SEQUENCE {
            cookie         syncCookie OPTIONAL,
            refreshDone    BOOLEAN DEFAULT TRUE
        },
        syncIdSet      [3] SEQUENCE {
            cookie         syncCookie OPTIONAL,
            refreshDeletes BOOLEAN DEFAULT FALSE,
            syncUUIDs      SET OF syncUUID
        }
    }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'newcookie',
            SyncCookie().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            )
        ),
        namedtype.NamedType(
            'refreshDelete',
            RefreshDelete().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
            )
        ),
        namedtype.NamedType(
            'refreshPresent',
            RefreshPresent().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
            )
        ),
        namedtype.NamedType(
            'syncIdSet',
            SyncIdSet().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
            )
        )
    )


class SyncInfoMessage(IntermediateResponse):
    """
    The Sync Info Message is an LDAP Intermediate Response Message
    [RFC4511] where responseName is the object identifier
    1.3.6.1.4.1.4203.1.9.1.4 and responseValue contains a BER-encoded
    syncInfoValue.  The criticality is FALSE (and hence absent).
    """
    responseName = '1.3.6.1.4.1.4203.1.9.1.4'

    def __new__(cls, responseName, encodedResponseValue, ctrls):
        if cls is not __class__:
            return super().__new__(cls)
        syncinfo, _ = decoder.decode(encodedResponseValue, asn1Spec=SyncInfoValue())
        choice = syncinfo.getName()
        if choice == 'newcookie':
            child = SyncInfoNewCookie
        elif choice == 'refreshDelete':
            child = SyncInfoRefreshDelete
        elif choice == 'refreshPresent':
            child = SyncInfoRefreshPresent
        elif choice == 'syncIdSet':
            child = SyncInfoIDSet
        else:
            raise ValueError
        return child.__new__(child, responseName, encodedResponseValue, ctrls)

    def decode(self, value: bytes):
        self.syncinfo, _ = decoder.decode(
            value,
            asn1Spec=SyncInfoValue(),
        )

class SyncInfoNewCookie(SyncInfoMessage):
    cookie: bytes

    def decode(self, value: bytes):
        super().decode(value)
        self.cookie = bytes(self.syncinfo.getComponent())

    def __repr__(self):
        return '{}(cookie={!r})'.format(
            self.__class__.__name__,
            self.cookie,
        )


class SyncInfoRefreshDelete(SyncInfoMessage):
    cookie: Optional[bytes]
    refreshDone: bool

    def decode(self, value: bytes):
        super().decode(value)
        component = self.syncinfo.getComponent()
        self.cookie = None
        cookie = component['cookie']
        if cookie.isValue:
            self.cookie = bytes(cookie)
        self.refreshDone = bool(component['refreshDone'])

    def __repr__(self):
        return '{}(cookie={!r}, refreshDone={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.refreshDone,
        )


class SyncInfoRefreshPresent(SyncInfoMessage):
    cookie: Optional[bytes]
    refreshDone: bool

    def decode(self, value: bytes):
        super().decode(value)
        component = self.syncinfo.getComponent()
        self.cookie = None
        cookie = component['cookie']
        if cookie.isValue:
            self.cookie = bytes(cookie)
        self.refreshDone = bool(component['refreshDone'])

    def __repr__(self):
        return '{}(cookie={!r}, refreshDone={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.refreshDone,
        )


class SyncInfoIDSet(SyncInfoMessage):
    cookie: Optional[bytes]
    refreshDeletes: bool
    syncUUIDs: Sequence[str]

    def decode(self, value: bytes):
        super().decode(value)
        component = self.syncinfo.getComponent()
        self.cookie = None
        cookie = component['cookie']
        if cookie.isValue:
            self.cookie = bytes(cookie)
        self.refreshDeletes = bool(component['refreshDeletes'])

        uuids = []
        for syncuuid in component['syncUUIDs']:
            uuid = UUID(bytes=bytes(syncuuid))
            uuids.append(str(uuid))
        self.syncUUIDs = uuids

    def __repr__(self):
        return '{}(cookie={!r}, refreshDeletes={!r}, syncUUIDs={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.refreshDeletes,
            self.uuids,
        )


INTERMEDIATE_RESPONSE_REGISTRY.register(SyncInfoMessage)
