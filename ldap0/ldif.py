# -*- coding: utf-8 -*-
"""
ldap0.ldif - generate and parse LDIF data (see RFC 2849)
"""

import re
from binascii import a2b_base64, b2a_base64
from binascii import Error as binascii_Error
from urllib.request import urlopen
from urllib.parse import urlparse
from io import BytesIO
from collections import defaultdict
from typing import BinaryIO, Dict, Optional, Sequence, Set, Tuple, Union

import _libldap0
from _libldap0 import MOD_ADD, MOD_DELETE, MOD_REPLACE, MOD_INCREMENT

from .__about__ import __version__, __author__, __license__
from .functions import _libldap0_function_call
from .typehints import EntryBytes

__all__ = [
    'LDIFWriter',
    'LDIFParser',
]

MOD_OP_INTEGER = {
    b'add': MOD_ADD,
    b'delete': MOD_DELETE,
    b'replace': MOD_REPLACE,
    b'increment': MOD_INCREMENT,
}

MOD_OP_STR = {
    MOD_ADD: b'add',
    MOD_DELETE: b'delete',
    MOD_REPLACE: b'replace',
    MOD_INCREMENT: b'increment',
}

CHANGE_TYPES = {b'add', b'delete', b'modify', b'modrdn'}

SAFE_STRING_PATTERN = b'(^(\000|\n|\r| |:|<)|[\000\n\r\200-\377]+|[ ]+$)'
SAFE_STRING_RE = re.compile(SAFE_STRING_PATTERN)


class LDIFWriter:
    """
    Write LDIF entry or change records to file object
    Copy LDIF input to a file output object containing all data retrieved
    via URLs
    """
    _output_file: BinaryIO
    _base64_attrs: Set
    _cols: int
    _last_line_sep: bytes
    records_written: int

    def __init__(
            self,
            output_file: BinaryIO,
            base64_attrs: Optional[Sequence[bytes]] = None,
            cols: int = 76,
            line_sep=b'\n',
        ):
        """
        output_file
            file object for output
        base64_attrs
            list of attribute types to be base64-encoded in any case
        cols
            Specifies how many columns a line may have before it's
            folded into many lines.
        line_sep
            String used as line separator
        """
        self._output_file = output_file
        base64_attrs = base64_attrs or []
        self._base64_attrs = {a.lower() for a in base64_attrs}
        self._cols = cols
        self._last_line_sep = line_sep
        self.records_written = 0

    def _unfold_lines(self, line: bytes):
        """
        Write string line as one or more folded lines
        """
        # Check maximum line length
        line_len = len(line)
        if line_len <= self._cols:
            self._output_file.write(line)
            self._output_file.write(self._last_line_sep)
        else:
            # Fold line
            pos = self._cols
            self._output_file.write(line[0:min(line_len, self._cols)])
            self._output_file.write(self._last_line_sep)
            while pos < line_len:
                self._output_file.write(b' ')
                self._output_file.write(line[pos:min(line_len, pos+self._cols-1)])
                self._output_file.write(self._last_line_sep)
                pos = pos+self._cols-1
        # _unfold_lines()

    def _needs_base64_encoding(self, attr_type: bytes, attr_value: bytes) -> bool:
        """
        returns True if attr_value has to be base-64 encoded because
        of special chars or because attr_type is in self._base64_attrs
        """
        return (
            attr_type.lower() in self._base64_attrs or
            SAFE_STRING_RE.search(attr_value) is not None
        )

    def _unparse_attr_type_and_value(self, attr_type: bytes, attr_value: bytes):
        """
        Write a single attribute type/value pair

        attr_type
              attribute type
        attr_value
              attribute value
        """
        assert isinstance(attr_type, bytes), TypeError(
            'Expected bytes for attr_type, got %r' % (attr_type,)
        )
        assert isinstance(attr_value, bytes), TypeError(
            'Expected bytes for attr_value, got %r' % (attr_value,)
        )
        if self._needs_base64_encoding(attr_type, attr_value):
            # Encode with base64
            aval = b2a_base64(attr_value, newline=False)
            sep = b':: '
        else:
            aval = attr_value
            sep = b': '
        self._unfold_lines(sep.join((attr_type, aval)))
        # _unparseAttrTypeandValue()

    def _unparse_entry_record(self, entry: EntryBytes):
        """
        entry
            dictionary holding an entry
        """
        for attr_type in sorted(entry.keys()):
            for attr_value in entry[attr_type]:
                self._unparse_attr_type_and_value(attr_type, attr_value)

    def _unparse_change_record(self, modlist):
        """
        modlist
            list of additions (2-tuple) or modifications (3-tuple)
        """
        self._unparse_attr_type_and_value(b'changetype', b'modify')
        for mod in modlist:
            mod_op, mod_type, mod_vals = mod
            self._unparse_attr_type_and_value(MOD_OP_STR[mod_op], mod_type)
            if mod_vals:
                for mod_val in mod_vals:
                    self._unparse_attr_type_and_value(mod_type, mod_val)
            self._output_file.write(b'-'+self._last_line_sep)

    def unparse(self, dn, record):
        """
        dn
              string-representation of distinguished name
        record
              Either a dictionary holding the LDAP entry {attrtype:record}
              or a list with a modify list like for LDAPObject.modify().
        """
        # Start with line containing the distinguished name
        self._unparse_attr_type_and_value(b'dn', dn)
        # Dispatch to record type specific writers
        if isinstance(record, dict):
            self._unparse_entry_record(record)
        elif isinstance(record, list):
            self._unparse_change_record(record)
        else:
            raise ValueError('Argument record must be dictionary or list, was %r' % (record))
        # Write empty line separating the records
        self._output_file.write(self._last_line_sep)
        # Count records written
        self.records_written = self.records_written+1
        # unparse()


class LDIFParser:
    """
    Base class for a LDIF parser. Applications should sub-class this
    class and override method handle() to implement something meaningful.

    Public class attributes:

    records_read
          Counter for records processed so far
    """
    _input_file: BinaryIO
    _max_entries: Optional[int]
    _process_url_schemes: Set[bytes]
    _ignored_attr_types: Set[bytes]
    _last_line_sep: bytes
    version: Optional[int]
    line_counter: int
    byte_counter: int
    records_read: int
    changetype_counter: Dict[bytes, int]
    _last_line: Optional[bytes]

    def __init__(
            self,
            input_file: BinaryIO,
            ignored_attr_types: Optional[Sequence[bytes]] = None,
            max_entries: Optional[int] = None,
            process_url_schemes: Optional[Sequence[bytes]] = None,
            line_sep: bytes = b'\n'
        ):
        """
        Parameters:
        input_file
            File-object to read the LDIF input from
        ignored_attr_types
            Attributes with these attribute type names will be ignored.
        max_entries
            If non-zero specifies the maximum number of entries to be
            read from f.
        process_url_schemes
            List containing strings with URLs schemes to process with urllib.
            An empty list turns off all URL processing and the attribute
            is ignored completely.
        line_sep
            String used as line separator
        """
        self._input_file = input_file
        self._max_entries = max_entries
        self._process_url_schemes = {val.lower() for val in process_url_schemes or []}
        self._ignored_attr_types = {val.lower() for val in ignored_attr_types or []}
        self._last_line_sep = line_sep
        self.version = None
        # Initialize counters
        self.line_counter = 0
        self.byte_counter = 0
        self.records_read = 0
        self.changetype_counter = defaultdict(lambda: 0)
        # Read very first line
        try:
            self._last_line = self._readline()
        except EOFError:
            self._last_line = b''

    @classmethod
    def frombuf(cls, ldif_bytes: bytes, **kwargs):
        """
        initialize LDIFParser instance for parsing a byte sequence
        """
        assert isinstance(ldif_bytes, bytes), TypeError(
            'Expected bytes for ldif_bytes, got %r' % (ldif_bytes,)
        )
        return cls(BytesIO(ldif_bytes), **kwargs)

    def _readline(self) -> Union[bytes, None]:
        line = self._input_file.readline()
        self.line_counter = self.line_counter + 1
        self.byte_counter = self.byte_counter + len(line)
        if not line:
            return None
        elif line[-2:] == b'\r\n':
            return line[:-2]
        elif line[-1:] == b'\n':
            return line[:-1]
        return line

    def _unfold_lines(self) -> bytes:
        """
        Unfold several folded lines with trailing space into one line
        """
        if self._last_line is None:
            raise EOFError('EOF reached after %d lines (%d bytes)' % (
                self.line_counter,
                self.byte_counter,
            ))
        unfolded_lines = [self._last_line]
        next_line = self._readline()
        while next_line and next_line[0:1] == b' ':
            unfolded_lines.append(next_line[1:])
            next_line = self._readline()
        self._last_line = next_line
        return b''.join(unfolded_lines)

    def _next_key_and_value(self) -> Tuple[Union[bytes, None], Union[bytes, None]]:
        """
        Parse a single attribute type and value pair from one or
        more lines of LDIF data
        """
        attr_value: Union[bytes, None]
        # Reading new attribute line
        unfolded_line = self._unfold_lines()
        # Ignore comments which can also be folded
        while unfolded_line and unfolded_line[0:1] == b'#':
            unfolded_line = self._unfold_lines()
        if not unfolded_line:
            return None, None
        if unfolded_line == b'-':
            return b'-', None
        try:
            colon_pos = unfolded_line.index(b':')
        except ValueError:
            raise ValueError('no value-spec in %r' % (unfolded_line,))
        attr_type = unfolded_line[0:colon_pos]
        # if needed attribute value is BASE64 decoded
        value_spec = unfolded_line[colon_pos:colon_pos+2]
        if value_spec == b': ':
            attr_value = unfolded_line[colon_pos+2:].lstrip()
        elif value_spec == b'::':
            # attribute value needs base64-decoding
            try:
                attr_value = a2b_base64(unfolded_line[colon_pos+2:])
            except binascii_Error as err:
                raise ValueError('Error decoding base64 in %r: %s' % (unfolded_line, err))
        elif value_spec == b':<':
            # fetch attribute value from URL
            url = unfolded_line[colon_pos+2:].strip()
            attr_value = None
            if (
                    self._process_url_schemes and
                    urlparse(url)[0] in self._process_url_schemes
                ):
                attr_value = urlopen(url.decode('utf-8')).read()
        else:
            attr_value = unfolded_line[colon_pos+1:]
        return attr_type, attr_value

    def _consume_empty_lines(self) -> Tuple[Union[bytes, None], Union[bytes, None]]:
        """
        Consume empty lines until first non-empty line.
        Must only be used between full records!

        Returns non-empty key-value-tuple.
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        # Consume empty lines
        try:
            key, val = next_key_and_value()
            while key == val == None:
                key, val = next_key_and_value()
        except EOFError:
            key, val = None, None
        return key, val

    def parse_entry_records(self, max_entries=None):
        """
        parse LDIF entry records
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        if max_entries is None:
            max_entries = self._max_entries

        try:
            # Consume empty lines
            key, val = self._consume_empty_lines()
            # Consume version line
            if key == b'version':
                self.version = int(val)
                key, val = self._consume_empty_lines()
        except EOFError:
            return

        # Loop for processing whole records
        while key is not None and \
              (max_entries is None or self.records_read < max_entries):
            # Consume first line which must start with "dn: "
            if key != b'dn':
                raise ValueError(
                    'Line %d: First line of record does not start with "dn:": %r' % (
                        self.line_counter,
                        key,
                    )
                )
            try:
                _libldap0_function_call(_libldap0.str2dn, val, 1)
            except Exception:
                raise ValueError(
                    'Line %d: Not a valid string-representation for dn: %r' % (
                        self.line_counter,
                        val,
                    )
                )
            dn = val
            entry = {}
            # Consume second line of record
            key, val = next_key_and_value()

            # Loop for reading the attributes
            while key is not None:
                # Add the attribute to the entry if not ignored attribute
                if not key.lower() in self._ignored_attr_types:
                    try:
                        entry[key].append(val)
                    except KeyError:
                        entry[key] = [val]
                # Read the next line within the record
                try:
                    key, val = next_key_and_value()
                except EOFError:
                    key, val = None, None

            # handle record
            yield (dn, entry)
            self.records_read = self.records_read + 1
            # Consume empty separator line(s)
            key, val = self._consume_empty_lines()
        # parse_entry_records()

    def parse(self, max_entries=None):
        """
        Invokes LDIFParser.parse_entry_records() for backward compability
        """
        return self.parse_entry_records(max_entries=max_entries)

    def parse_change_records(self, max_entries=None):
        """
        parse LDIF change records
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        if max_entries is None:
            max_entries = self._max_entries

        # Consume empty lines
        key, val = self._consume_empty_lines()
        # Consume version line
        if key == b'version':
            self.version = int(val)
            key, val = self._consume_empty_lines()

        # Loop for processing whole records
        while key is not None and \
              (max_entries is None or self.records_read < max_entries):
            # Consume first line which must start with "dn: "
            if key != b'dn':
                raise ValueError(
                    'Line %d: First line of record does not start with "dn:": %r' % (
                        self.line_counter,
                        key,
                    )
                )
            try:
                _libldap0_function_call(_libldap0.str2dn, val, 0)
            except Exception:
                raise ValueError(
                    'Line %d: Not a valid string-representation for dn: %r' % (
                        self.line_counter,
                        val,
                    )
                )
            dn = val
            # Consume second line of record
            key, val = next_key_and_value()
            # Read "control:" lines
            controls = []
            while key is not None and key == b'control':
                try:
                    control_type, criticality, control_value = val.split(' ', 2)
                except ValueError:
                    control_value = None
                    control_type, criticality = val.split(' ', 1)
                controls.append((control_type, criticality, control_value))
                key, val = next_key_and_value()

            # Determine changetype first
            changetype = None
            # Consume changetype line of record
            if key == b'changetype':
                if val not in CHANGE_TYPES:
                    raise ValueError('Invalid changetype: %r' % val)
                changetype = val
                key, val = next_key_and_value()

            if changetype == b'modify':
                # From here we assume a change record is read with changetype: modify
                modops = []
                try:
                    # Loop for reading the list of modifications
                    while key is not None:
                        # Extract attribute mod-operation (add, delete, replace)
                        try:
                            modop = MOD_OP_INTEGER[key]
                        except KeyError:
                            raise ValueError(
                                'Line %d: Invalid mod-op string: %r' % (self.line_counter, key)
                            )
                        # we now have the attribute name to be modified
                        modattr = val
                        modvalues = []
                        try:
                            key, val = next_key_and_value()
                        except EOFError:
                            key, val = None, None
                        while key == modattr:
                            modvalues.append(val)
                            try:
                                key, val = next_key_and_value()
                            except EOFError:
                                key, val = None, None
                        modops.append((modop, modattr, modvalues or None))
                        key, val = next_key_and_value()
                        if key == b'-':
                            # Consume next line
                            key, val = next_key_and_value()
                except EOFError:
                    key, val = None, None
                if modops:
                    # append entry to result list
                    yield (dn, modops, controls)
            else:
                # Consume the unhandled change record
                while key is not None:
                    key, val = next_key_and_value()

            # Consume empty separator line(s)
            key, val = self._consume_empty_lines()

            # Increment record counters
            try:
                self.changetype_counter[changetype] = self.changetype_counter[changetype] + 1
            except KeyError:
                self.changetype_counter[changetype] = 1
            self.records_read = self.records_read + 1

        # parse_change_records()

    def list_entry_records(self):
        """
        return list of parsed entry records
        """
        return list(self.parse_entry_records())

    def list_change_records(self):
        """
        return list of parsed change records
        """
        return list(self.parse_change_records())
