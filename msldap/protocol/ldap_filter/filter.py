import re
import platform

from msldap.protocol.ldap_filter import parser
from msldap.protocol.ldap_filter.soundex import soundex_compare


class LDAPBase:
    indent = 4
    collapsed = False
    filters = None

    def simplify(self):
        if self.filters:
            if len(self.filters) == 1:
                return self.filters[0].simplify()
            else:
                self.filters = list(map(lambda x: x.simplify(), self.filters))

        return self

    def to_string(self, indent, indt_char, level):
        raise NotImplementedError

    def match(self, data):
        raise NotImplementedError

    @staticmethod
    def _indent(indent, indt_char=' ', level=0):
        if type(indent) == bool and indent:
            indent = LDAPBase.indent
        else:
            try:
                indent = int(indent)
            except ValueError:
                return ''

        try:
            indt_char = str(indt_char)
        except ValueError:
            raise InvalidIndentChar('Indent value must convertible to a string')

        return indt_char * (level * indent)

    @staticmethod
    def parse(filt):
        filt = _strip_whitespace(filt)
        return parser.parse(filt, actions=ParserActions())

    @staticmethod
    def escape(data):
        escaped = data.replace('\\', '\\5c')
        escaped = escaped.replace('*', '\\2a')
        escaped = escaped.replace('(', '\\28')
        escaped = escaped.replace(')', '\\29')
        escaped = escaped.replace('\x00', '\\00')

        return escaped

    @staticmethod
    def unescape(data):
        unescaped = data.replace('\\5c', '\\')
        unescaped = unescaped.replace('\\2a', '*')
        unescaped = unescaped.replace('\\28', '(')
        unescaped = unescaped.replace('\\29', ')')
        unescaped = unescaped.replace('\\00', '\x00')

        return unescaped

    @staticmethod
    def match_string(data, filt):
        match = _as_list(data)
        if '*' not in filt:
            return any(_ms_helper(m, filt) for m in match)

        return Filter.match_substring(data, filt)

    @staticmethod
    def match_substring(data, filt):
        match = _as_list(data)

        return any(_ss_helper(m, filt) for m in match)

    @staticmethod
    def match_approx(data, filt):
        match = _as_list(data)

        return any(_approx_helper(m, filt) for m in match)

    @staticmethod
    def match_lte(data, filt):
        match = _as_list(data)

        return any(_lte_helper(m, filt) for m in match)

    @staticmethod
    def match_gte(data, filt):
        match = _as_list(data)

        return any(_gte_helper(m, filt) for m in match)

    @staticmethod
    def AND(filt):
        return GroupAnd(filt)

    @staticmethod
    def OR(filt):
        return GroupOr(filt)

    @staticmethod
    def NOT(filt):
        filt = _as_list(filt)
        if not len(filt) == 1:  # TODO: Error code here.
            raise Exception

        return GroupNot(filt)


class Filter(LDAPBase):
    def __init__(self, attr, comp, val):
        self.type = 'filter'
        self.attr = attr
        self.comp = comp
        self.val = val

    def __repr__(self):
        return self.to_string()

    def __str__(self):
        return self.to_string()

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)

    def match(self, data):
        value = self.val

        try:
            attrval = data[self.attr]
        except KeyError:
            return False

        if self.comp == '=':
            if value == '*' and attrval:
                return True
            else:
                return Filter.match_string(attrval, value)
        elif self.comp == '<=':
            return Filter.match_lte(attrval, value)
        elif self.comp == '>=':
            return Filter.match_gte(attrval, value)
        elif self.comp == '~=':
            return Filter.match_approx(attrval, value)
        else:
            pass

    def to_string(self, indent=False, indt_char=' ', level=0):
        return ''.join([
            self._indent(indent, indt_char, level),
            '(',
            self.attr,
            self.comp,
            self.val,
            ')'
        ])

    @staticmethod
    def attribute(name):
        return Attribute(name)


class Group(LDAPBase):
    def __init__(self, comp, filters):
        self.type = 'group'
        self.comp = comp
        self.filters = filters

    def __repr__(self):
        return self.to_string()

    def __str__(self):
        return self.to_string()

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)

    def match(self, data):
        raise NotImplementedError

    def to_string(self, indent=False, indt_char=' ', level=0):
        id_str = self._indent(indent, indt_char, level)
        id_str2 = id_str
        nl = ''

        # If running on Windows use Windows style newlines,
        # if anything else default to POSIX style.
        if platform.system() == 'Windows' and indent:
            nl = '\r\n'
        elif indent:
            nl = '\n'

        if not Filter.collapsed and self.comp == '!':
            nl = ''
            id_str2 = ''
            indent = 0

        return ''.join([
            id_str,
            '(',
            self.comp,
            nl,
            nl.join(list(map(lambda x: x.to_string(indent, indt_char, level + 1), self.filters))),
            nl,
            id_str2,
            ')'
        ])


class GroupOr(Group):
    def __init__(self, filters):
        super().__init__(comp='|', filters=filters)

    def match(self, data):
        return any(f.match(data) for f in self.filters)


class GroupAnd(Group):
    def __init__(self, filters):
        super().__init__(comp='&', filters=filters)

    def match(self, data):
        return all(f.match(data) for f in self.filters)


class GroupNot(Group):
    def __init__(self, filters):
        super().__init__(comp='!', filters=filters)

    def match(self, data):
        return not any(_not_helper(f, data) for f in self.filters)

    def simplify(self):
        return self


class Attribute:
    def __init__(self, name):
        self.name = name

    def present(self):
        return Filter(self.name, '=', '*')

    def raw(self, value):
        return Filter(self.name, '=', _to_string(value))

    def equal_to(self, value):
        return Filter(self.name, '=', self.escape(_to_string(value)))

    def starts_with(self, value):
        return Filter(self.name, '=', self.escape(_to_string(value)) + '*')

    def ends_with(self, value):
        return Filter(self.name, '=', '*' + self.escape(_to_string(value)))

    def contains(self, value):
        return Filter(self.name, '=', '*' + self.escape(_to_string(value)) + '*')

    def approx(self, value):
        return Filter(self.name, '~=', self.escape(_to_string(value)))

    def lte(self, value):
        return Filter(self.name, '<=', self.escape(_to_string(value)))

    def gte(self, value):
        return Filter(self.name, '>=', self.escape(_to_string(value)))

    @staticmethod
    def escape(data):
        escaped = data.replace('\\', '\\5c')
        escaped = escaped.replace('*', '\\2a')
        escaped = escaped.replace('(', '\\28')
        escaped = escaped.replace(')', '\\29')
        escaped = escaped.replace('\x00', '\\00')

        return escaped


def _as_list(val):
    if not isinstance(val, (list, tuple)):
        return [val]

    return val


def _ss_regex(filt):
    pattern = re.sub(r'\*', '.*', filt)
    pattern = re.sub(r'(?<=\\)([0-9a-fA-F]{,2})', _ss_regex_escaped, pattern)
    return re.compile('^' + pattern + '$', re.I)


def _ss_regex_escaped(match):
    s = match.group(0) if match else None

    if s in ['28', '29', '5c', '2a']:
        s = 'x{}'.format(match.group(0).upper())

    return s


def _strip_whitespace(filt):
    if ' ' or '\n' or '\r\n' in filt:
        att_val = re.findall(r'(?<=[=])(?<=[~=]|[>=]|[<=])(.*?)(?=\))', filt)
        filt = filt.replace('\r\n', '')
        filt = filt.replace('\n', '')
        filt = filt.replace(' ', '')

        for s in att_val:
            key = s.replace('\r\n', '')
            key = key.replace('\n', '')
            key = key.replace(' ', '')
            filt = filt.replace(key, s)

        att = re.findall(r'(?<=[(])[a-zA-Z0-9 -.]*?(?=[~=]|[>=]|[<=]|[=])', filt)

        for s in att:
            if ' ' in s:
                regex = re.compile('(?<=[(])' + s + '?(?=[~=]|[>=]|[<=]|[=])', re.I)
                filt = re.sub(regex, s.replace(' ', ''), filt)

    return filt


def _ss_helper(cv, filt):
    regex = _ss_regex(filt)

    return regex.match(cv)


def _ms_helper(cv, filt):
    if cv:
        return cv.lower() == Filter.unescape(filt).lower()


def _approx_helper(cv, filt):
    return soundex_compare(cv, filt)


def _lte_helper(cv, filt):
    try:
        val = int(cv) <= int(filt)
    except ValueError:
        val = str(cv) <= str(filt)
    return val


def _gte_helper(cv, filt):
    try:
        val = int(cv) >= int(filt)
    except ValueError:
        val = str(cv) >= str(filt)
    return val


def _not_helper(filt, data):
    try:
        return filt.match(data)
    except AttributeError:
        pass


def _to_string(val):
    try:
        val = str(val)
    except ValueError:
        print('Could not convert data to a string.')
        raise
    return val


class ParserActions:

    @staticmethod
    def elements_to_string(elements=None):
        if elements:
            string = ''

            for e in elements:
                try:
                    string += e.text if e else ''
                except AttributeError:
                    string += str(e) if e else ''
            return string

    def return_string(self, input, start, end, elements=None):
        return self.elements_to_string(elements)

    def return_hex(self, input, start, end, elements=None):
        string = self.elements_to_string(elements)

        if string:
            return int(string, 16)

    def return_escaped_char(self, input, start, end, elements=None):
        string = self.elements_to_string(elements)

        if string:
            chr_code = int(string.replace('\\', ''))

            return chr(chr_code)

    @staticmethod
    def return_options(input, start, end, attr, opts=None, elements=None):
        if opts:
            opts.pop(0)
            opts = opts.pop(0)
            opts = opts.split(';')

        attr[0]['options'] = opts if opts else []
        return attr[0]

    def return_oid_type(self, input, start, end, elements=None):
        oid = self.elements_to_string(elements)

        if oid:
            return {
                'type': 'oid',
                'attribute': oid
            }

    def return_attr_type(self, input, start, end, elements=None):
        name = self.elements_to_string(elements)

        if name:
            return {
                'type': 'attribute',
                'attribute': name
            }

    @staticmethod
    def return_simple_filter(input, start, end, elements=None):
        attr = elements[0]['attribute']
        comp = getattr(elements[1], 'text')
        value = elements[2]

        return Filter(attr, comp, value)

    @staticmethod
    def return_present_filter(input, start, end, elements=None):
        attr = elements[0]['attribute']

        return Filter.attribute(attr).present()

    @staticmethod
    def return_wildcard(input, start, end, elements=None):
        attr = elements[0]['attribute']
        value = getattr(elements[2], 'text')

        return Filter(attr, '=', value)

    @staticmethod
    def return_filter(input, start, end, filt=None, elements=None):
        for f in filt:
            if isinstance(f, (Filter, GroupAnd, GroupOr, GroupNot)):
                return f

    @staticmethod
    def return_and_filter(input, start, end, filters=None, elements=None):
        for f in filters:
            if f.elements:
                return Filter.AND(f.elements)

    @staticmethod
    def return_or_filter(input, start, end, filters=None, elements=None):
        for f in filters:
            if f.elements:
                return Filter.OR(f.elements)

    @staticmethod
    def return_not_filter(input, start, end, filt=None, elements=None):
        for f in filt:
            if isinstance(f, Filter):
                return Filter.NOT(f)


class InvalidIndentChar(Exception):
    pass
