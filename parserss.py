#!/usr/bin/python
# Copyright (C) 2001-2005, Christof Meerwald
# http://jabrss.cmeerw.org

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 dated June, 1991.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

import codecs, httplib, md5, rfc822, os, random, re, socket, string, struct
import sys, time, threading, traceback, types, zlib
import apsw
import xmllib


SOCKET_CONNECTTIMEOUT = 200
SOCKET_TIMEOUT = 60

if hasattr(socket, 'setdefaulttimeout'):
    # Python >= 2.3 has native support for socket timeouts
    socket.setdefaulttimeout(SOCKET_CONNECTTIMEOUT)
    TimeoutException = socket.timeout
else:
    # try to use timeoutsocket if it is available
    try:
        import timeoutsocket
        timeoutsocket.setDefaultSocketTimeout(SOCKET_CONNECTTIMEOUT)
        TimeoutException = timeoutsocket.Timeout
    except ImportError:
        class TimeoutException(Exception):
            pass


re_validprotocol = re.compile('^(?P<protocol>[a-z]+):(?P<rest>.*)$')
re_supportedprotocol = re.compile('^(http)$')

re_validhost = re.compile('^(?P<host>[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)(:(?P<port>[0-9a-z]+))?(?P<path>(/.*)?)$')
re_blockhost = re.compile('^(10\.|127\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)')

re_blank = re.compile('([ \\t\\n][ \\t\\n]+|[\x00\x0c\\t\\n])')

re_spliturl = re.compile('^(?P<protocol>[a-z]+)://(?P<host>[^/]+)(?P<path>/?.*)$')

random.seed()


def RSS_Resource_db():
    db = apsw.Connection('jabrss_res.db')
    db.setbusytimeout(3000)

    return db


class UrlError(ValueError):
    pass

def split_url(url):
    mo = re_validprotocol.match(url)
    if not mo:
        raise UrlError('can\'t parse protocol of URL "%s"' % (url,))

    url_protocol, url_rest = mo.group('protocol', 'rest')
    if not re_supportedprotocol.match(url_protocol):
        raise UrlError('unsupported protocol "%s"' % (url_protocol))

    if url_rest[:2] != '//':
        raise UrlError('missing "//" after "%s:"' % (url_protocol,))

    url_rest = url_rest[2:]
    mo = re_validhost.match(url_rest)
    if not mo:
        raise UrlError('invalid host in URL "%s"' % (url,))

    url_host, url_port, url_path = mo.group('host', 'port', 'path')

    url_host = url_host.lower()
    if (url_port != '80') and (url_port != 'http') and (url_port != None):
        raise UrlError('ports != 80 not allowed')

    if url_path == '':
        url_path = '/'

    while url_path[:2] == '//':
        url_path = url_path[1:]

    if re_blockhost.match(url_host):
        raise UrlError('host "%s" not allowed' % (url_host,))

    return url_protocol, url_host, url_path


def normalize_text(s):
    r = re_blank.search(s)
    while r:
        s = s[:r.start()] + ' ' + s[r.end():]
        r = re_blank.search(s)

    return string.strip(s)

def normalize_obj(o):
    for attr in dir(o):
        if attr[0] != '_':
            value = getattr(o, attr)
            if type(value) in types.StringTypes:
                setattr(o, attr, normalize_text(value))

    return o

def normalize_item(item):
    normalize_obj(item)

    if item.descr == '':
        item.descr = None

    if not hasattr(item, 'descr_plain'):
        item.descr_plain = item.descr

    if not hasattr(item, 'descr_xhtml'):
        item.descr_xhtml = None

    del item.descr

    return item


def compare_items(l, r):
    ltitle, llink = l.title, l.link
    rtitle, rlink = r.title, r.link

    if ltitle == rtitle:
        lmo = re_spliturl.match(llink)
        rmo = re_spliturl.match(rlink)

        if lmo and rmo:
            lprotocol, lhost, lpath = lmo.group('protocol', 'host', 'path')
            rprotocol, rhost, rpath = rmo.group('protocol', 'host', 'path')

            if lprotocol == rprotocol and lpath == rpath:
                lhostparts = string.split(string.lower(lhost), '.')
                if lhostparts[-1] == '':
                    del lhostparts[-1]

                rhostparts = string.split(string.lower(rhost), '.')
                if rhostparts[-1] == '':
                    del rhostparts[-1]

                if len(lhostparts) >= 2:
                    del lhostparts[-1]
                if len(rhostparts) >= 2:
                    del rhostparts[-1]

                if len(lhostparts) > len(rhostparts):
                    tmp = lhostparts
                    lhostparts = rhostparts
                    rhostparts = tmp
                    del tmp

                if len(lhostparts) == len(rhostparts):
                    return lhostparts == rhostparts
                else:
                    return lhostparts == rhostparts[-len(lhostparts):]
            else:
                return 0
        else:
            return llink == rlink
    else:
        return 0


class Resource_Guard:
    def __init__(self, cleanup_handler):
        self._cleanup_handler = cleanup_handler

    def __del__(self):
        self._cleanup_handler()

class Data:
    def __init__(self, **kw):
        for key, value in kw.items():
            setattr(self, key, value)


class DecompressorError(ValueError):
    pass

class Null_Decompressor:
    def feed(self, s):
        return s

    def flush(self):
        return ''


class Deflate_Decompressor:
    def __init__(self):
        self._decompress = zlib.decompressobj()

    def feed(self, s):
        print repr(s)
        return self._decompress.decompress(s)

    def flush(self):
        return self._decompress.flush()


class Gzip_Decompressor:
    FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT = 1, 2, 4, 8, 16

    def __init__(self):
        self._crc = zlib.crc32("")
        self._size = 0

        self._decompress = zlib.decompressobj(-zlib.MAX_WBITS)
        self._header_flag = 0
        self._buffer = ''

        self._state_feed = Gzip_Decompressor._feed_header_static

    def _update_crc(self, data):
        self._crc = zlib.crc32(data, self._crc)
        self._size = self._size + len(data)

    def feed(self, s):
        self._buffer = self._buffer + s

        res = None
        while res == None:
            res = self._state_feed(self)

            if res:
                self._update_crc(res)

        return res

    def flush(self):
        data = ''
        while self._state_feed:
            res = self._state_feed(self)

            if res:
                self._update_crc(res)
                data += res
            elif res == '' and self._state_feed != None:
                raise IOError, 'premature EOF'

        return data

    def _feed_header_static(self):
        if len(self._buffer) >= 10:
            magic = self._buffer[:2]
            if magic != '\037\213':
                raise IOError, 'Not a gzipped file'
            method = ord(self._buffer[2])
            if method != 8:
                raise IOError, 'Unknown compression method'
            self._header_flag = ord(self._buffer[3])
            # modtime = self.fileobj.read(4)
            # extraflag = self.fileobj.read(1)
            # os = self.fileobj.read(1)
            self._buffer = self._buffer[10:]

            self._state_feed = Gzip_Decompressor._feed_header_flags
            return None

        # need more data
        return ''

    def _feed_header_flags(self):
        if self._header_flag & Gzip_Decompressor.FEXTRA:
            if len(self._buffer) >= 2:
                # Read & discard the extra field, if present
                xlen = struct.unpack('<H', self._buffer[:2])[0]
                if len(self._buffer) >= (2 + xlen):
                    self._buffer = self._buffer[2 + xlen:]
                    self._header_flag = self._header_flag & ~Gzip_Decompressor.FEXTRA
                    return None
        elif self._header_flag & Gzip_Decompressor.FNAME:
            # Read and discard a null-terminated string containing the filename
            pos = string.find(self._buffer, '\0')
            if pos != -1:
                self._buffer = self._buffer[pos + 1:]
                self._header_flag = self._header_flag & ~Gzip_Decompressor.FNAME
                return None
        elif self._header_flag & Gzip_Decompressor.FCOMMENT:
            # Read and discard a null-terminated string containing a comment
            pos = string.find(self._buffer, '\0')
            if pos != -1:
                self._buffer = self._buffer[pos + 1:]
                self._header_flag = self._header_flag & ~Gzip_Decompressor.FCOMMENT
                return None
        elif self._header_flag & Gzip_Decompressor.FHCRC:
            if len(self._buffer) >= 2:
                self._buffer = self._buffer[2:]
                self._header_flag = self._header_flag & ~Gzip_Decompressor.FHCRC
                return None
        else:
            self._state_feed = Gzip_Decompressor._feed_data
            return None

        # need more data
        return ''

    def _feed_data(self):
        if len(self._buffer) > 0:
            data = self._decompress.decompress(self._buffer)
            if self._decompress.unused_data:
                self._buffer = self._decompress.unused_data
                self._state_feed = Gzip_Decompressor._feed_eof
                if not data:
                    return None
            else:
                self._buffer = ''
            return data

        # need more data
        return ''

    def _feed_eof(self):
        if len(self._buffer) >= 8:
            crc32, isize = struct.unpack("<ll", self._buffer[:8])
            if crc32 % 0x100000000L != self._crc % 0x100000000L:
                raise DecompressorError('CRC check failed')
            elif isize != self._size:
                raise DecompressorError('Incorrect length of data produced')

            self._state_feed = None
        return ''


ENTITIES = {
    'nbsp' : u'\u00a0',
    'iexcl' : u'\u00a1',
    'cent' : u'\u00a2',
    'pound' : u'\u00a3',
    'curren' : u'\u00a4',
    'yen' : u'\u00a5',
    'brvbar' : u'\u00a6',
    'sect' : u'\u00a7',
    'uml' : u'\u00a8',
    'copy' : u'\u00a9',
    'ordf' : u'\u00aa',
    'laquo' : u'\u00ab',
    'not' : u'\u00ac',
    'shy' : u'\u00ad',
    'reg' : u'\u00ae',
    'macr' : u'\u00af',
    'deg' : u'\u00b0',
    'plusmn' : u'\u00b1',
    'sup2' : u'\u00b2',
    'sup3' : u'\u00b3',
    'acute' : u'\u00b4',
    'micro' : u'\u00b5',
    'para' : u'\u00b6',
    'middot' : u'\u00b7',
    'cedil' : u'\u00b8',
    'sup1' : u'\u00b9',
    'ordm' : u'\u00ba',
    'raquo' : u'\u00bb',
    'frac14' : u'\u00bc',
    'frac12' : u'\u00bd',
    'frac34' : u'\u00be',
    'iquest' : u'\u00bf',
    'Agrave' : u'\u00c0',
    'Aacute' : u'\u00c1',
    'Acirc' : u'\u00c2',
    'Atilde' : u'\u00c3',
    'Auml' : u'\u00c4',
    'Aring' : u'\u00c5',
    'AElig' : u'\u00c6',
    'Ccedil' : u'\u00c7',
    'Egrqave' : u'\u00c8',
    'Eacute' : u'\u00c9',
    'Ecirc' : u'\u00ca',
    'Euml' : u'\u00cb',
    'Igrave' : u'\u00cc',
    'Iacute' : u'\u00cd',
    'Icirc' : u'\u00ce',
    'Iuml' : u'\u00cf',
    'ETH' : u'\u00d0',
    'Ntilde' : u'\u00d1',
    'Ograve' : u'\u00d2',
    'Oacute' : u'\u00d3',
    'Ocirc' : u'\u00d4',
    'Otilde' : u'\u00d5',
    'Ouml' : u'\u00d6',
    'times' : u'\u00d7',
    'Oslash' : u'\u00d8',
    'Ugrave' : u'\u00d9',
    'Uacute' : u'\u00da',
    'Ucirc' : u'\u00db',
    'Uuml' : u'\u00dc',
    'Yacute' : u'\u00dd',
    'THORN' : u'\u00de',
    'szlig' : u'\u00df',
    'agrave' : u'\u00e0',
    'aacute' : u'\u00e1',
    'acirc' : u'\u00e2',
    'atilde' : u'\u00e3',
    'auml' : u'\u00e4',
    'aring' : u'\u00e5',
    'aelig' : u'\u00e6',
    'ccedil' : u'\u00e7',
    'egrave' : u'\u00e8',
    'eacute' : u'\u00e9',
    'ecirc' : u'\u00ea',
    'euml' : u'\u00eb',
    'igrave' : u'\u00ec',
    'iacute' : u'\u00ed',
    'icirc' : u'\u00ee',
    'iuml' : u'\u00ef',
    'eth' : u'\u00f0',
    'ntilde' : u'\u00f1',
    'ograve' : u'\u00f2',
    'oacute' : u'\u00f3',
    'ocirc' : u'\u00f4',
    'otilde' : u'\u00f5',
    'ouml' : u'\u00f6',
    'divide' : u'\u00f7',
    'oslash' : u'\u00f8',
    'ugrave' : u'\u00f9',
    'uacute' : u'\u00fa',
    'ucirc' : u'\u00fb',
    'uuml' : u'\u00fc',
    'yacute' : u'\u00fd',
    'thorn' : u'\u00fe',
    'yuml' : u'\u00ff',
    }


class Feed_Parser(xmllib.XMLParser):
    def __init__(self):
        xmllib.XMLParser.__init__(self, accept_utf8=1)

        self.elements = {
            'http://www.w3.org/1999/02/22-rdf-syntax-ns# RDF' :
            (self.rss_rdf_start, self.rss_rdf_end),
            'rss' :
            (self.rss_rss_start, self.rss_rss_end),
            'http://backend.userland.com/rss2 rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # RSS 0.90, see http://www.purplepages.ie/RSS/netscape/rss0.90.html
            # RSS 0.91, see http://my.netscape.com/publish/formats/rss-spec-0.91.html
            'http://my.netscape.com/rdf/simple/0.9/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # non-standard, but allow anyway
            'http://my.netscape.com/rdf/simple/0.91/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            # RSS 1.0, see http://web.resource.org/rss/1.0/spec
            'http://purl.org/rss/1.0/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            'http://purl.org/rss/2.0/ rss' :
            (self.rss_rss_start, self.rss_rss_end),
            'http://purl.org/atom/ns# feed' :
            (self.atom_feed_start, self.atom_feed_end)
            }

        self._format = ''
        self._encoding = 'utf-8'
        self._feed_encoding = None
        self._bytes = 0

        self._state = 0
        self._cdata = None
        self._content_mode = None
        self._summary = None

        self._channel = Data(title='', link='', descr='')
        self._items = []

    def handle_xml(self, encoding, standalone):
        if encoding and not self._feed_encoding:
            encoding = string.lower(encoding)
            if encoding[:8] == 'windows-':
                encoding = 'cp' + encoding[8:]

            self._encoding = encoding


    def feed(self, data):
        if self._bytes == 0:
            if data[:4] == codecs.BOM64_LE:
                # probably not supported
                self._feed_encoding = 'utf-32-le'
                data = data[4:]
            elif data[:4] == codecs.BOM64_BE:
                # probably not supported
                self._feed_encoding = 'utf-32-be'
                data = data[4:]
            elif data[:3] == '\xef\xbb\xbf':
                self._feed_encoding = 'utf-8'
                data = data[3:]
            elif data[:2] == codecs.BOM32_LE:
                self._feed_encoding = 'utf-16-le'
                data = data[2:]
            elif data[:2] == codecs.BOM32_BE:
                self._feed_encoding = 'utf-16-be'
                data = data[2:]

        self._bytes = self._bytes + len(data)
        if self._feed_encoding:
            data = data.decode(self._feed_encoding).encode('utf-8')

        return xmllib.XMLParser.feed(self, data)


    def rss_rdf_start(self, attrs):
        self._format = 'rdf'
        self.elements.update({
            'http://my.netscape.com/rdf/simple/0.9/ channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/1.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/2.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),

            'http://my.netscape.com/rdf/simple/0.9/ item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/1.0/ item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/2.0/ item' :
            (self.rss_item_start, self.rss_item_end),
            # not strictly conforming...
            'item' :
            (self.rss_item_start, self.rss_item_end),

            'http://my.netscape.com/rdf/simple/0.9/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/dc/elements/1.1/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/1.0/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/2.0/ title' :
            (self.rss_title_start, self.rss_title_end),
            # not strictly conforming...
            'title' :
            (self.rss_title_start, self.rss_title_end),

            'http://my.netscape.com/rdf/simple/0.9/ link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/1.0/ link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/2.0/ link' :
            (self.rss_link_start, self.rss_link_end),
            # not strictly conforming...
            'link' :
            (self.rss_link_start, self.rss_link_end),

            'http://my.netscape.com/rdf/simple/0.9/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/dc/elements/1.1/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/1.0/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/2.0/ description' :
            (self.rss_description_start, self.rss_description_end),
            # not strictly conforming...
            'description' :
            (self.rss_description_start, self.rss_description_end)
            })

    def rss_rdf_end(self):
        self.elements = {}


    def rss_rss_start(self, attrs):
        self._format = 'rss'
        self.elements.update({
            'channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://backend.userland.com/rss2 channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/1.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),
            'http://purl.org/rss/2.0/ channel' :
            (self.rss_channel_start, self.rss_channel_end),

            'item' :
            (self.rss_item_start, self.rss_item_end),
            'http://backend.userland.com/rss2 item' :
            (self.rss_item_start, self.rss_item_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/1.0/ item' :
            (self.rss_item_start, self.rss_item_end),
            'http://purl.org/rss/2.0/ item' :
            (self.rss_item_start, self.rss_item_end),

            'title' :
            (self.rss_title_start, self.rss_title_end),
            'http://backend.userland.com/rss2 title' :
            (self.rss_title_start, self.rss_title_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/dc/elements/1.1/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/1.0/ title' :
            (self.rss_title_start, self.rss_title_end),
            'http://purl.org/rss/2.0/ title' :
            (self.rss_title_start, self.rss_title_end),

            'link' :
            (self.rss_link_start, self.rss_link_end),
            'http://backend.userland.com/rss2 link' :
            (self.rss_link_start, self.rss_link_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/1.0/ link' :
            (self.rss_link_start, self.rss_link_end),
            'http://purl.org/rss/2.0/ link' :
            (self.rss_link_start, self.rss_link_end),

            'description' :
            (self.rss_description_start, self.rss_description_end),
            'http://backend.userland.com/rss2 description' :
            (self.rss_description_start, self.rss_description_end),
            'http://my.netscape.com/publish/formats/rss-0.91.dtd description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/dc/elements/1.1/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/1.0/ description' :
            (self.rss_description_start, self.rss_description_end),
            'http://purl.org/rss/2.0/ description' :
            (self.rss_description_start, self.rss_description_end)
            })

    def rss_rss_end(self):
        self.elements = {}


    def atom_feed_start(self, attrs):
        self._format = 'atom'
        self.elements.update({
            'http://purl.org/atom/ns# entry' :
            (self.atom_entry_start, self.atom_entry_end),

            'http://purl.org/atom/ns# title' :
            (self.atom_title_start, self.atom_title_end),

            'http://purl.org/atom/ns# link' :
            (self.atom_link_start, self.atom_link_end),

            'http://purl.org/atom/ns# tagline' :
            (self.atom_tagline_start, self.atom_tagline_end),

            'http://purl.org/atom/ns# summary' :
            (self.atom_summary_start, self.atom_summary_end),

            'http://purl.org/atom/ns# content' :
            (self.atom_content_start, self.atom_content_end)
            })

        self._state = self._state | 0x04

    def atom_feed_end(self):
        self._state = self._state & ~0x04
        self.elements = {}


    def rss_channel_start(self, attrs):
        self._state = self._state | 0x04

    def rss_channel_end(self):
        self._state = self._state & ~0x04


    def rss_item_start(self, attrs):
        self._state = self._state | 0x08
        self._items.append(Data(title='', link='', descr=''))

    def rss_item_end(self):
        self._state = self._state & ~0x08


    def rss_title_start(self, attrs):
        if self._state & 0xfc:
            self._cdata = ''

    def rss_title_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.title = self._cdata

        self._cdata = None


    def rss_link_start(self, attrs):
        if self._state & 0xfc:
            self._cdata = ''

    def rss_link_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.link = self._cdata

        self._cdata = None


    def rss_description_start(self, attrs):
        if self._state & 0xfc:
            self._cdata = ''

    def rss_description_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.descr = self._cdata

        self._cdata = None


    def atom_entry_start(self, attrs):
        self._state = (self._state & ~0x04) | 0x08
        self._items.append(Data(title='', link='', descr=''))

    def atom_entry_end(self):
        if self._items[-1].descr == '' and self._summary:
            self._items[-1].descr = self._summary

        self._state = (self._state & ~0x08) | 0x04


    def atom_title_start(self, attrs):
        if self._state & 0xfc:
            self._cdata = ''

    def atom_title_end(self):
        if self._state & 0xfc:
            elem = self._current_elem()
            if elem != None:
                elem.title = self._cdata

        self._cdata = None


    def atom_link_start(self, attrs):
        elem = self._current_elem()
        if elem == None:
            return

        if elem.link and attrs.has_key('http://purl.org/atom/ns# type') and (attrs['http://purl.org/atom/ns# type'] != 'text/html'):
            return

        if attrs.has_key('http://purl.org/atom/ns# href'):
            elem.link = attrs['http://purl.org/atom/ns# href']

    def atom_link_end(self):
        pass


    def atom_tagline_start(self, attrs):
        if self._state & 0x04:
            self._cdata = ''
            if attrs.has_key('http://purl.org/atom/ns# mode'):
                self._content_mode = attrs['http://purl.org/atom/ns# mode']

    def atom_tagline_end(self):
        if self._state & 0x04:
            if self._content_mode == 'base64':
                self._cdata = self._cdata.decode('base64')
            elem = self._current_elem()
            if elem != None:
                elem.descr = self._cdata

        self._cdata = None
        self._content_mode = None


    def atom_content_start(self, attrs):
        if self._state & 0x08:
            self._cdata = ''
            if attrs.has_key('http://purl.org/atom/ns# mode'):
                self._content_mode = attrs['http://purl.org/atom/ns# mode']

    def atom_content_end(self):
        if self._state & 0x08:
            if self._content_mode == 'base64':
                self._cdata = self._cdata.decode('base64')
            elem = self._current_elem()
            if elem != None and elem != '':
                elem.descr = self._cdata

        self._cdata = None
        self._content_mode = None


    def atom_summary_start(self, attrs):
        if self._state & 0x08:
            self._cdata = ''
            if attrs.has_key('http://purl.org/atom/ns# mode'):
                self._content_mode = attrs['http://purl.org/atom/ns# mode']

    def atom_summary_end(self):
        if self._state & 0x08:
            if self._content_mode == 'base64':
                self._cdata = self._cdata.decode('base64')
            self._summary = self._cdata

        self._cdata = None
        self._content_mode = None


    def unknown_starttag(self, tag, attrs):
        if self._format == '':
            print 'format not recognised, start-tag', tag.encode('iso8859-1', 'replace')
            self._format = 'unknown'

        if (self._cdata != None) and (tag[:29] == 'http://www.w3.org/1999/xhtml '):
            self._cdata += '<' + tag[29:]
            for attr, val in attrs.items():
                if attr[:29] == 'http://www.w3.org/1999/xhtml ':
                    self._cdata += ' ' + attr[29:] + '="' + val.decode(self._encoding) + '"'
            self._cdata += '>'

        if tag[-8:] == ' channel':
            print 'unknown namespace for', tag.encode('iso8859-1', 'replace')
	elif tag[-5:] == ' item':
            print 'unknown namespace for', tag.encode('iso8859-1', 'replace')
        elif self._state & 0xfc:
            if tag[-6:] == ' title':
                print 'unknown namespace for', tag.encode('iso8859-1', 'replace')
	    elif tag[-5:] == ' link':
                print 'unknown namespace for', tag.encode('iso8859-1', 'replace')
	    elif tag[-12:] == ' description':
                print 'unknown namespace for', tag.encode('iso8859-1', 'replace')

    def unknown_endtag(self, tag):
        if (self._cdata != None) and (tag[:29] == 'http://www.w3.org/1999/xhtml '):
            self._cdata += '</' + tag[29:] + '>'

    def handle_unicode_data(self, data):
        if self._cdata != None:
            self._cdata += data
            if len(self._cdata) > 16 * 1024:
                raise ValueError('item exceeds maximum allowed size')

    def handle_data(self, data):
        self.handle_unicode_data(data.decode(self._encoding))

    def handle_cdata(self, data):
        self.handle_unicode_data(data.decode(self._encoding))

    def handle_charref(self, name):
        try:
            if name[0] == 'x':
                n = int(name[1:], 16)
            else:
                n = int(name)
        except ValueError:
            self.unknown_charref(name)
            return
        if not 0 <= n <= 65535:
            self.unknown_charref(name)
            return
        self.handle_unicode_data(unichr(n))

    def unknown_entityref(self, entity):
        try:
            self.handle_unicode_data(ENTITIES[entity])
        except KeyError:
            print 'ignoring unknown entity ref', entity.encode('iso8859-1', 'replace')

    def _current_elem(self):
        if self._state & 0x08:
            return self._items[-1]
        elif self._state & 0x04:
            return self._channel
        else:
            return None


##
# Database Schema:
#  'S' -> resource_id sequence number (4-byte struct)
#  'S' + resource_id -> URL
#  'R' + URL -> resource_id (4-byte struct)
#  'D' + resource_id -> Resource data
#  'E' + resource_id -> error information (string)
#  'I' + resource_id -> Resource info
#  'H' + resource_id -> Resource history
#  'T' + resource_id -> Resource times
##
class RSS_Resource:
    NR_ITEMS = 48

    _db = RSS_Resource_db()
    _redirect_cb = None
    http_proxy = None


    def __init__(self, url, db_cursor=None):
        self._lock = threading.Lock()
        self._url = url
        self._url_protocol, self._url_host, self._url_path = split_url(url)

        if db_cursor == None:
            cursor = RSS_Resource._db.cursor()
        else:
            cursor = db_cursor
        db = cursor.getconnection()

        self._id = None
        self._last_updated, self._last_modified = None, None
        self._etag = None
        self._invalid_since, self._err_info = None, None
        self._redirect, self._redirect_seq = None, None
        self._penalty = 0
        title, description, link = None, None, None

        cursor.execute('SELECT rid, last_updated, last_modified, etag, invalid_since, redirect, redirect_seq, penalty, err_info, title, description, link FROM resource WHERE url=?',
                       (self._url,))
        for row in cursor:
            self._id, self._last_updated, self._last_modified, self._etag, self._invalid_since, self._redirect, self._redirect_seq, self._penalty, self._err_info, title, description, link = row

        if self._id == None:
            cursor.execute('INSERT INTO resource (url) VALUES (?)',
                           (self._url,))
            self._id = db.last_insert_rowid()

        if self._last_updated == None:
            self._last_updated = 0

        if self._penalty == None:
            self._penalty = 0

        if title == None:
            title = self._url
        if link == None:
            link = ''
        if description == None:
            description = ''

        self._channel_info = Data(title=title, link=link, descr=description)

        self._history = []
        cursor.execute('SELECT time_items0, time_items1, time_items2, time_items3, time_items4, time_items5, time_items6, time_items7, time_items8, time_items9, time_items10, time_items11, time_items12, time_items13, time_items14, time_items15, nr_items0, nr_items1, nr_items2, nr_items3, nr_items4, nr_items5, nr_items6, nr_items7, nr_items8, nr_items9, nr_items10, nr_items11, nr_items12, nr_items13, nr_items14, nr_items15 FROM resource_history WHERE rid=?',
                       (self._id,))
        for row in cursor:
            history_times = filter(lambda x: x!=None, row[0:16])
            history_nr = filter(lambda x: x!=None, row[16:32])
            self._history = zip(history_times, history_nr)


    def lock(self):
        self._lock.acquire()

    def unlock(self):
        self._lock.release()


    def url(self):
        return self._url

    def id(self):
        return self._id

    def channel_info(self):
        return self._channel_info

    def times(self):
        last_updated, last_modified, invalid_since = self._last_updated, self._last_modified, self._invalid_since
        if last_modified == None:
            last_modified = 0
    
        return last_updated, last_modified, invalid_since

    def redirect_info(self, db_cursor=None):
        if self._redirect == None:
            return None, None

        if db_cursor == None:
            cursor = RSS_Resource._db.cursor()
        else:
            cursor= db_cursor

        cursor.execute('SELECT url FROM resource WHERE rid=?',
                       (self._redirect,))
        redirect_url = None
        for row in cursor:
            redirect_url = row[0]

        return redirect_url, self._redirect_seq


    def error_info(self):
        return self._err_info


    def history(self):
        return self._history


    # @return ([item], next_item_id, redirect_resource, redirect_seq, [redirects])
    # locks the resource object if new_items are returned
    def update(self, db=None, redirect_count=5):
        error_info = None
        nr_new_items = 0
        feed_xml_downloaded = False
        feed_xml_changed = False
        first_item_id = None
        items = []

        prev_updated = self._last_updated
        self._last_updated = int(time.time())

        if not self._invalid_since:
            # expect the worst, will be reset later
            self._invalid_since = self._last_updated


        if db == None:
            db = RSS_Resource_db()

        cursor = db.cursor()
        db_txn_end = None

        redirect_tries = redirect_count
        redirect_permanent = True
        redirect_resource = None
        redirect_seq = None
        redirects = []

        try:
            url_protocol, url_host, url_path = self._url_protocol, self._url_host, self._url_path

            while redirect_tries > 0:
                redirect_tries = -(redirect_tries - 1)

                if redirect_permanent:
                    redirect_url = url_protocol + '://' + url_host + url_path
                    if redirect_url != self._url:
                        print 'redirect: %s -> %s' % (self._url.encode('iso8859-1', 'replace'), redirect_url.encode('iso8859-1', 'replace'))
                        if RSS_Resource._redirect_cb:
                            redirect_resource, redirects = RSS_Resource._redirect_cb(redirect_url, cursor, -redirect_tries)

                            # only perform the redirect if target is valid
                            if redirect_resource._invalid_since:
                                error_info = redirect_resource._err_info
                                self._last_modified = redirect_resource._last_modified
                                self._etag = redirect_resource._etag
                                redirect_resource = None
                            else:
                                redirect_items, redirect_seq = redirect_resource.get_headlines(0, cursor)

                                cursor.execute('BEGIN')
                                db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))

                                items, first_item_id, nr_new_items = self._process_new_items(redirect_items, cursor)
                                del redirect_items

                                self._last_modified = None
                                self._etag = None

                                self._redirect = redirect_resource._id
                                self._redirect_seq = redirect_seq
                                cursor.execute('UPDATE resource SET redirect=?, redirect_seq=? WHERE rid=?',
                                               (self._redirect,
                                                self._redirect_seq, self._id))

                            break


                if RSS_Resource.http_proxy:
                    host = RSS_Resource.http_proxy
                    request = 'http://' + url_host + url_path
                else:
                    host = url_host
                    request = url_path

                h = httplib.HTTP(host)
                h.putrequest('GET', request)
                # adjust the socket timeout after the connection has been
                # established
                if hasattr(h._conn.sock, 'settimeout'):
                    h._conn.sock.settimeout(SOCKET_TIMEOUT)
                elif hasattr(h._conn.sock, 'set_timeout'):
                    h._conn.sock.set_timeout(SOCKET_TIMEOUT)

                if not RSS_Resource.http_proxy:
                    h.putheader('Host', url_host)
                h.putheader('Pragma', 'no-cache')
                h.putheader('Cache-Control', 'no-cache')
                h.putheader('Accept-Encoding', 'deflate, gzip')
                h.putheader('User-Agent', 'jabrss (http://JabXPCOM.sunsite.dk/jabrss/)')
                if self._last_modified:
                    h.putheader('If-Modified-Since',
                                rfc822.formatdate(self._last_modified))
                if self._etag != None:
                    h.putheader('If-None-Match', self._etag)
                h.endheaders()
                errcode, errmsg, headers = h.getreply()

                # check the error code
                if (errcode >= 200) and (errcode < 300):
                    feed_xml_downloaded = True

                    try:
                        self._last_modified = rfc822.mktime_tz(rfc822.parsedate_tz(headers['last-modified']))
                    except:
                        self._last_modified = None

                    try:
                        self._etag = headers['etag']
                    except:
                        self._etag = None

                    content_encoding = headers.get('content-encoding', None)
                    transfer_encoding = headers.get('transfer-encoding', None)

                    if (content_encoding == 'gzip') or (transfer_encoding == 'gzip'):
                        print 'gzip-encoded data'
                        decoder = Gzip_Decompressor()
                    elif (content_encoding == 'deflate') or (transfer_encoding == 'deflate'):
                        print 'deflate-encoded data'
                        decoder = Deflate_Decompressor()
                    else:
                        decoder = Null_Decompressor()

                    rss_parser = Feed_Parser()

                    f = h.getfile()
                    bytes_received = 0
                    bytes_processed = 0
                    xml_started = 0
                    file_hash = md5.new()

                    l = f.read(4096)
                    while l:
                        bytes_received = bytes_received + len(l)
                        if bytes_received > 48 * 1024:
                            raise ValueError('file exceeds maximum allowed size')

                        data = decoder.feed(l)
                        file_hash.update(data)

                        if not xml_started:
                            data = string.lstrip( data)
                            if data:
                                xml_started = 1

                        bytes_processed = bytes_processed + len(data)
                        if bytes_processed > 96 * 1024:
                            raise ValueError('file exceeds maximum allowed decompressed size')

                        rss_parser.feed(data)

                        l = f.read(4096)

                    data = decoder.flush()
                    file_hash.update(data)
                    rss_parser.feed(data)
                    rss_parser.close()
                    new_channel_info = normalize_obj(rss_parser._channel)

                    cursor.execute('BEGIN')
                    db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))

                    hash_buffer = buffer(file_hash.digest())
                    cursor.execute('UPDATE resource SET hash=? WHERE rid=? AND (hash IS NULL OR hash<>?)',
                                   (hash_buffer, self._id, hash_buffer))
                    feed_xml_changed = (db.changes() != 0)

                    self._update_channel_info(new_channel_info, cursor)

                    new_items = map(lambda x: normalize_item(x),
                                    rss_parser._items[:RSS_Resource.NR_ITEMS])
                    new_items.reverse()

                    items, first_item_id, nr_new_items = self._process_new_items(new_items, cursor)
                    del new_items

                # handle "304 Not Modified"
                elif errcode == 304:
                    # RSS resource is valid
                    self._invalid_since = None
                # handle "301 Moved Permanently", "302 Found" and
                # "307 Temporary Redirect"
                elif (errcode >= 300) and (errcode < 400):
                    if errcode != 301:
                        redirect_permanent = False

                    redirect_url = headers.get('location', None)
                    if redirect_url:
                        if not re_validprotocol.match(redirect_url):
                            if redirect_url[0] == '/':
                                redirect_url = '%s://%s%s' % (url_protocol, url_host, redirect_url)
                            else:
                                base_url = '%s://%s%s' % (url_protocol, url_host, url_path)
                                base_url = base_url[:base_url.rindex('/')]
                                redirect_url = '%s://%s%s/%s' % (url_protocol, url_host, base_url, redirect_url)

                        print 'Following redirect (%d) to "%s"' % (errcode, redirect_url.encode('iso8859-1', 'replace'))
                        url_protocol, url_host, url_path = split_url(redirect_url)
                        redirect_tries = -redirect_tries
                    else:
                        print errcode, errmsg, headers
                        error_info = 'HTTP: %d %s' % (errcode, errmsg)
                else:
                    print errcode, errmsg, headers
                    error_info = 'HTTP: %d %s' % (errcode, errmsg)

            if self._invalid_since and not error_info and redirect_tries == 0:
                error_info = 'redirect: maximum number of redirects exceeded'
        except socket.error, e:
            error_info = 'socket: ' + str(e)
        except TimeoutException, e:
            error_info = 'timeout: ' + str(e)
        except httplib.HTTPException, e:
            error_info = 'HTTP: ' + str(e)
        except DecompressorError, e:
            error_info = 'decompressor: ' + str(e)
        except UnicodeError, e:
            error_info = 'encoding: ' + str(e)
        except LookupError, e:
            error_info = 'encoding: ' + str(e)
        except xmllib.Error, e:
            error_info = 'RDF/XML parser: ' + str(e)
        except ValueError, e:
            error_info = 'misc: ' + str(e)
        except:
            traceback.print_exc(file=sys.stdout)

        if error_info:
            print 'Error: %s' % (error_info,)

        if db_txn_end == None:
            cursor.execute('BEGIN')
            db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))

        if error_info != self._err_info:
            self._err_info = error_info
            cursor.execute('UPDATE resource SET err_info=? WHERE rid=?',
                           (self._err_info, self._id))

        if not self._invalid_since:
            if feed_xml_downloaded:
                if nr_new_items > 0:
                    # downloaded and new items available, good
                    self._penalty = (5 * self._penalty) / 6
                elif not feed_xml_changed:
                    # downloaded, but not changed, very bad
                    self._penalty = (3 * self._penalty) / 4 + 256
                else:
                    # downloaded and changed, but no new items, bad
                    self._penalty = (15 * self._penalty) / 16 + 64
            else:
                # "not modified" response from server, good
                self._penalty = (3 * self._penalty) / 4

        cursor.execute('UPDATE resource SET last_modified=?, last_updated=?, etag=?, invalid_since=?, penalty=? WHERE rid=?',
                       (self._last_modified, self._last_updated, self._etag,
                        self._invalid_since, self._penalty, self._id))

        if nr_new_items:
            new_items = items[-nr_new_items:]
            next_item_id = first_item_id + len(items)
        else:
            new_items = []
            next_item_id = None

        return new_items, next_item_id, redirect_resource, redirect_seq, redirects


    def _update_channel_info(self, new_channel_info, cursor):
        if self._channel_info != new_channel_info:
            self._channel_info = new_channel_info

            cursor.execute('UPDATE resource SET title=?, link=?, description=? WHERE rid=?',
                           (self._channel_info.title,
                            self._channel_info.link,
                            self._channel_info.descr,
                            self._id))


    # @return ([item], first_item_id, nr_new_items)
    def _process_new_items(self, new_items, cursor):
        items, next_item_id = self.get_headlines(0, cursor)
        first_item_id = next_item_id - len(items)

        nr_new_items = self._update_items(items, new_items)
        del new_items
        if nr_new_items:
            self.lock()

        if len(items) > RSS_Resource.NR_ITEMS:
            first_item_id += len(items) - RSS_Resource.NR_ITEMS
            del items[:-RSS_Resource.NR_ITEMS]
            cursor.execute('DELETE FROM resource_data WHERE rid=? AND seq_nr<?',
                           (self._id, first_item_id))

        # RSS resource is valid
        self._invalid_since = None

        if nr_new_items:
            # update history information
            self._history.append((int(time.time()), nr_new_items))
            self._history = self._history[-16:]

            history_times = map(lambda x: x[0], self._history)
            if len(history_times) < 16:
                history_times += (16 - len(history_times)) * [None]

            history_nr = map(lambda x: x[1], self._history)
            if len(history_nr) < 16:
                history_nr += (16 - len(history_nr)) * [None]

            cursor.execute('INSERT INTO resource_history (rid, time_items0, time_items1, time_items2, time_items3, time_items4, time_items5, time_items6, time_items7, time_items8, time_items9, time_items10, time_items11, time_items12, time_items13, time_items14, time_items15, nr_items0, nr_items1, nr_items2, nr_items3, nr_items4, nr_items5, nr_items6, nr_items7, nr_items8, nr_items9, nr_items10, nr_items11, nr_items12, nr_items13, nr_items14, nr_items15) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                           tuple([self._id] + history_times + history_nr))

            i = first_item_id
            for item in items:
                cursor.execute('INSERT INTO resource_data (rid, seq_nr, title, link, descr_plain, descr_xhtml) VALUES (?, ?, ?, ?, ?, ?)',
                               (self._id, i,
                                item.title, item.link,
                                item.descr_plain,
                                item.descr_xhtml))
                i += 1

        return items, first_item_id, nr_new_items


    # @return nr_new_items
    def _update_items(self, items, new_items):
        nr_old_items = len(items)
        nr_new_items = 0

        for item in new_items:
            found = False

            for i in range(0, nr_old_items):
                if compare_items(items[i], item):
                    items[i] = item
                    found = True

            if not found:
                items.append(item)
                nr_new_items = nr_new_items + 1

        return nr_new_items


    # @return ([item], next id)
    def get_headlines(self, first_id, db_cursor=None):
        if db_cursor == None:
            cursor = RSS_Resource._db.cursor()
        else:
            cursor = db_cursor

        if first_id == None:
            first_id = 0

        cursor.execute('SELECT seq_nr, published, title, link, descr_plain, descr_xhtml FROM resource_data WHERE rid=? AND seq_nr>=? ORDER BY seq_nr',
                       (self._id, first_id))
        items = []
        last_id = first_id
        for seq_nr, published, title, link, descr_plain, descr_xhtml in cursor:
            if seq_nr >= last_id:
                last_id = seq_nr + 1
            items.append(Data(published=published, title=title, link=link,
                              descr_plain=descr_plain,
                              descr_xhtml=descr_xhtml))

        return items, last_id


    def next_update(self, randomize=True):
        min_interval = 45*60
        max_interval = 24*60*60

        if len(self._history) >= 2:
            hist_items = len(self._history)

            sum_items = reduce(lambda x, y: (y[0], x[1] + y[1]),
                               self._history[1:])[1]
            time_span = self._last_updated - self._history[0][0]

            if hist_items >= 12:
                time_span_old = self._history[hist_items / 2][0] - self._history[0][0]
                sum_items_old = reduce(lambda x, y: (y[0], x[1] + y[1]),
                                       self._history[1:hist_items / 2 + 1])[1]
                if (3 * sum_items_old < sum_items) and (5 * time_span_old < time_span):
                    time_span = time_span_old
                    sum_items = sum_items_old
                # sum_items_new = sum_items - sum_items_old
                elif (3 * sum_items_old > 2 * sum_items) and (5 * time_span_old > 4 * time_span):
                    time_span = time_span - time_span_old
                    sum_items = sum_items - sum_items_old

            interval = time_span / sum_items / 3

            # apply a bonus for well-behaved feeds
            interval = 32 * interval / (64 - self._penalty / 28)
            max_interval = 32 * max_interval / (64 - self._penalty / 28)
            min_interval = 32 * min_interval / (48 - self._penalty / 64)
        elif len(self._history) == 1:
            time_span = self._last_updated - self._history[0][0]

            interval = 30*60 + time_span / 3
            min_interval = 60*60
        elif self._invalid_since:
            time_span = self._last_updated - self._invalid_since

            interval = 4*60*60 + time_span / 4
            max_interval = 48*60*60
        else:
            interval = 8*60*60

        if string.find(string.lower(self._url), 'slashdot.org') != -1:
            # yes, slashdot sucks - this is a special slashdot
            # throttle to avaoid being banned by slashdot
            interval = interval + 150*60

        # apply upper and lower bounds to the interval
        interval = min(max_interval, max(min_interval, interval))

        # and add some random factor
        if randomize:
            return self._last_updated + interval + int(random.normalvariate(30, 50 + interval / 50))
        else:
            return self._last_updated + interval


def RSS_Resource_id2url(res_id, db_cursor=None):
    if db_cursor == None:
        cursor = RSS_Resource._db.cursor()
    else:
        cursor = db_cursor

    url = None
    cursor.execute('SELECT url FROM resource WHERE rid=?',
                   (res_id,))
    for row in cursor:
        url = row[0]

    if url == None:
        raise KeyError(res_id)

    return url


def RSS_Resource_simplify(url):
    url_protocol, url_host, url_path = split_url(url)

    simple_url = url_protocol + '://' + url_host + url_path
    # TODO: return simple_url
    return url


if __name__ == '__main__':
    import sys

    if len(sys.argv) >= 2:
        resource = RSS_Resource(sys.argv[1])

        new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update()
        channel_info = resource.channel_info()
        print channel_info.title.encode('iso8859-1', 'replace'), channel_info.link.encode('iso8859-1', 'replace'), channel_info.descr.encode('iso8859-1', 'replace')
        if len(new_items) > 0:
            print 'new items', map(lambda x: (x.title.encode('iso8859-1', 'replace'), x.link.encode('iso8859-1', 'replace')), new_items), next_item_id
