#!/usr/bin/python
# Copyright (C) 2001-2003, Christof Meerwald
# http://JabXPCOM.sunsite.dk

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

import codecs, gdbm, httplib, rfc822, os, random, re, socket, string, struct
import sys, time, threading, traceback, zlib
import xmllib

# try to use timeoutsocket if it is available
try:
    import timeoutsocket
    timeoutsocket.setDefaultSocketTimeout(60)
    TimeoutException = timeoutsocket.Timeout
except ImportError:
    class TimeoutException(Exception):
        pass


re_validprotocol = re.compile('^(?P<protocol>[a-z]+):(?P<rest>.*)$')
re_supportedprotocol = re.compile('^(http)$')

re_validhost = re.compile('^(?P<host>[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)(:(?P<port>[0-9a-z]+))?(?P<path>(/.*)?)$')
re_blockhost = re.compile('^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)')

re_blank = re.compile('([ \\t\\n][ \\t\\n]+|[\\t\\n])')

re_spliturl = re.compile('^(?P<protocol>[a-z]+)://(?P<host>[^/]+)(?P<path>/?.*)$')

random.seed()


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

    if re_blockhost.match(url_host):
        raise UrlError('host "%s" not allowed' % (url_host,))

    return (url_protocol, url_host, url_path)


def normalize_text(s):
    r = re_blank.search(s)
    while r:
        s = s[:r.start()] + ' ' + s[r.end():]
        r = re_blank.search(s)

    return string.strip(s)


def compare_items(l, r):
    ltitle, llink = l[0:2]
    rtitle, rlink = r[0:2]

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


class DecompressorError(ValueError):
    pass

class Null_Decompressor:
    def feed(self, s):
        return s

    def flush(self):
        return ''


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
        res = None
        while (res == None) and self._state_feed:
            res = self._state_feed(self)

            if res:
                self._update_crc(res)

        if self._state_feed:
            raise IOError, "premature EOF"

        return res

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


class RSS_Parser(xmllib.XMLParser):
    def __init__(self):
        xmllib.XMLParser.__init__(self, accept_utf8=1)

        self.elements = {
            'channel' :
            (self.channel_start, self.channel_end),
            'http://my.netscape.com/rdf/simple/0.9/ channel' :
            (self.channel_start, self.channel_end),
            'http://purl.org/rss/1.0/ channel' :
            (self.channel_start, self.channel_end),

            'item' :
            (self.item_start, self.item_end),
            'http://my.netscape.com/rdf/simple/0.9/ item' :
            (self.item_start, self.item_end),
            'http://purl.org/rss/1.0/ item' :
            (self.item_start, self.item_end),

            'title' :
            (self.title_start, self.title_end),
            'http://my.netscape.com/rdf/simple/0.9/ title' :
            (self.title_start, self.title_end),
            'http://purl.org/rss/1.0/ title' :
            (self.title_start, self.title_end),

            'link' :
            (self.link_start, self.link_end),
            'http://my.netscape.com/rdf/simple/0.9/ link' :
            (self.link_start, self.link_end),
            'http://purl.org/rss/1.0/ link' :
            (self.link_start, self.link_end),

            'description' :
            (self.description_start, self.description_end),
            'http://my.netscape.com/rdf/simple/0.9/ description' :
            (self.description_start, self.description_end),
            'http://purl.org/rss/1.0/ description' :
            (self.description_start, self.description_end),
            }

        self._encoding = 'utf-8'
        self._feed_encoding = None
        self._bytes = 0

        self._state = 0

        self._channel = ['', '', '']
        self._items = []

    def handle_xml(self, encoding, standalone):
        if encoding and not self._feed_encoding:
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


    def channel_start(self, attrs):
        self._state = self._state | 0x04

    def channel_end(self):
        self._state = self._state & ~0x04


    def item_start(self, attrs):
        self._state = self._state | 0x08
        self._items.append(['', '', ''])

    def item_end(self):
        self._state = self._state & ~0x08


    def title_start(self, attrs):
        if self._state & 0xfc:
            self._state = (self._state & 0xfc) | 0x01

    def title_end(self):
        self._state = self._state & 0xfc


    def link_start(self, attrs):
        if self._state & 0xfc:
            self._state = (self._state & 0xfc) | 0x02

    def link_end(self):
        self._state = self._state & 0xfc


    def description_start(self, attrs):
        if self._state & 0xfc:
            self._state = (self._state & 0xfc) | 0x03

    def description_end(self):
        self._state = self._state & 0xfc


    def unknown_starttag(self, tag, attrs):
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
        pass

    def handle_unicode_data(self, data):
        if self._state & 0x08:
            elem = self._items[-1]
        elif self._state & 0x04:
            elem = self._channel
        else:
            return

        if self._state & 0x03:
            elem[(self._state & 0x03) - 1] = elem[(self._state & 0x03) - 1] + data
            if len(elem[(self._state & 0x03) - 1]) > 16 * 1024:
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
    _db = gdbm.open('jabrss_urls.db', 'c')
    _db.reorganize()
    _db_updates = 0
    _db_sync = threading.Lock()
    http_proxy = None

    try:
        _seq_nr = struct.unpack('>l', _db['S'])[0]
    except:
        _seq_nr = 0


    def __init__(self, url):
        self._url = url
        self._url_protocol, self._url_host, self._url_path = split_url(url)

        RSS_Resource._db_sync.acquire()
        try:
            self._id_str = RSS_Resource._db['R' + self._url.encode('utf-8')]
            self._id = struct.unpack('>l', self._id_str)[0]
        except KeyError:
            RSS_Resource._seq_nr += 1
            RSS_Resource._db['S'] = struct.pack('>l', RSS_Resource._seq_nr)
            self._id = RSS_Resource._seq_nr
            self._id_str = struct.pack('>l', self._id)
            RSS_Resource._db['R' + self._url.encode('utf-8')] = self._id_str
            RSS_Resource._db['S' + self._id_str] = self._url

        try:
            times_str = RSS_Resource._db['T' + self._id_str]
        except KeyError:
            times_str = ''

        if len(times_str) == 8:
            self._last_modified, self._last_updated = struct.unpack('>ll', times_str)
            self._invalid_since = 0
        elif len(times_str) == 12:
            self._last_modified, self._last_updated, self._invalid_since = struct.unpack('>lll', times_str)
        else:
            self._last_modified = 0
            self._last_updated = 0
            self._invalid_since = 0

        try:
            self._channel_info = tuple(string.split(RSS_Resource._db['I' + self._id_str].decode('utf-8'), '\0'))
        except KeyError:
            self._channel_info = ('', '', '')

        self._history = []
        try:
            history_str = RSS_Resource._db['H' + self._id_str]
            self._first_item_id = struct.unpack('>l', history_str[0:4])[0]
            for i in range(4, len(history_str), 8):
                self._history.append(struct.unpack('>ll',
                                                   history_str[i:i + 8]))
        except KeyError:
            self._first_item_id = 0

        RSS_Resource._db_sync.release()


    def url(self):
        return self._url

    def id(self):
        return self._id

    def channel_info(self):
        return self._channel_info

    def times(self):
        return (self._last_updated, self._last_modified, self._invalid_since)

    def error_info(self):
        error_info = None

        if self._invalid_since:
            RSS_Resource._db_sync.acquire()
            try:
                error_info = RSS_Resource._db['E' + self._id_str].decode('utf-8')
            except KeyError:
                pass
            RSS_Resource._db_sync.release()

        return error_info


    def history(self):
        return self._history


    def update(self):
        error_info = None
        nr_new_items = 0
        items = []

        self._last_updated = int(time.time())

        if self._invalid_since == 0:
            # expect the worst, will be reset later
            self._invalid_since = self._last_updated

        try:
            redirect_tries = 5
            redirect_permanent = 1
            url_protocol, url_host, url_path = (self._url_protocol, self._url_host, self._url_path)

            while redirect_tries > 0:
                redirect_tries = -(redirect_tries - 1)

                if redirect_permanent:
                    simple_url = url_protocol + '://' + url_host + url_path
                    if simple_url != self._url:
                        RSS_Resource._db_sync.acquire()
                        merge_needed = RSS_Resource._db.has_key('R' + simple_url.encode('utf-8'))
                        RSS_Resource._db_sync.release()

                        if merge_needed:
                            print 'permanent redirect: %s -> %s (merge needed)' % (self._url.encode('iso8859-1', 'replace'), simple_url.encode('iso8859-1', 'replace'))
                        else:
                            print 'permanent redirect: %s -> %s' % (self._url.encode('iso8859-1', 'replace'), simple_url.encode('iso8859-1', 'replace'))

                if RSS_Resource.http_proxy:
                    host = RSS_Resource.http_proxy
                    request = 'http://' + url_host + url_path
                else:
                    host = url_host
                    request = url_path

                h = httplib.HTTP(host)
                h.putrequest('GET', request)
                if not RSS_Resource.http_proxy:
                    h.putheader('Host', url_host)
                h.putheader('Pragma', 'no-cache')
                h.putheader('Cache-Control', 'no-cache')
                h.putheader('Accept-Encoding', 'gzip')
                h.putheader('User-Agent', 'jabrss (http://JabXPCOM.sunsite.dk/jabrss/)')
                if self._last_modified > 0:
                    h.putheader('If-Modified-Since',
                                rfc822.formatdate(self._last_modified))
                h.endheaders()
                errcode, errmsg, headers = h.getreply()

                # check the error code
                if (errcode >= 200) and (errcode < 300):
                    content_encoding = headers.get('content-encoding', None)
                    transfer_encoding = headers.get('transfer-encoding', None)

                    if (content_encoding == 'gzip') or (transfer_encoding == 'gzip'):
                        print 'gzip-encoded data'
                        decoder = Gzip_Decompressor()
                    else:
                        decoder = Null_Decompressor()

                    rss_parser = RSS_Parser()

                    f = h.getfile()
                    bytes_received = 0
                    bytes_processed = 0
                    xml_started = 0

                    l = f.read(4096)
                    while l:
                        if not xml_started:
                            l = string.lstrip(l)
                            if l:
                                xml_started = 1

                        bytes_received = bytes_received + len(l)
                        if bytes_received > 48 * 1024:
                            raise ValueError('file exceeds maximum allowed size')

                        data = decoder.feed(l)

                        bytes_processed = bytes_processed + len(data)
                        if bytes_processed > 96 * 1024:
                            raise ValueError('file exceeds maximum allowed decompressed size')

                        rss_parser.feed(data)

                        l = f.read(4096)

                    rss_parser.feed(decoder.flush())
                    rss_parser.close()
                    new_channel_info = tuple(map(normalize_text,
                                                 rss_parser._channel))
                    RSS_Resource._db_sync.acquire()
                    if self._channel_info != new_channel_info:
                        self._channel_info = new_channel_info
                        RSS_Resource._db['I' + self._id_str] = string.join(self._channel_info, '\0').encode('utf-8')

                    try:
                        items = map(lambda x: tuple(string.split(x, '\0')), string.split(RSS_Resource._db['D' + self._id_str].decode('utf-8'), '\014'))
                    except KeyError:
                        items = []
                    RSS_Resource._db_sync.release()

                    nr_old_items = len(items)

                    new_items = map(lambda x: map(normalize_text, x),
                                    rss_parser._items[:RSS_Resource.NR_ITEMS])
                    new_items.reverse()
                    for item in new_items:
                        item = tuple(item)
                        found = 0

                        for i in range(0, nr_old_items):
                            if compare_items(items[i], item):
                                items[i] = item
                                found = 1

                        if not found:
                            items.append(item)
                            nr_new_items = nr_new_items + 1

                    if len(items) > RSS_Resource.NR_ITEMS:
                        self._first_item_id += len(items) - RSS_Resource.NR_ITEMS
                        del items[:-RSS_Resource.NR_ITEMS]

                    try:
                        self._last_modified = rfc822.mktime_tz(rfc822.parsedate_tz(headers['last-modified']))
                    except KeyError:
                        pass

                    # RSS resource is valid
                    self._invalid_since = 0

                    if nr_new_items:
                        # update history information
                        self._history.append((int(time.time()), nr_new_items))
                        self._history = self._history[-16:]

                        RSS_Resource._db_sync.acquire()
                        RSS_Resource._db['D' + self._id_str] = string.join(map(lambda x: string.join(x, '\0'), items), '\014').encode('utf-8')
                        RSS_Resource._db['H' + self._id_str] = struct.pack('>l', self._first_item_id) + string.join(map(lambda x: struct.pack('>ll', x[0], x[1]), self._history), '')

                        if RSS_Resource._db_updates > 64:
                            RSS_Resource._db_updates = 0
                            RSS_Resource._db.reorganize()
                        else:
                            RSS_Resource._db_updates = RSS_Resource._db_updates + 1
                        RSS_Resource._db_sync.release()

                # handle "301 Moved Permanently", "302 Found" and
                # "307 Temporary Redirect"
                elif errcode == 304:
                    # RSS resource is valid
                    self._invalid_since = 0
                elif (errcode >= 300) and (errcode < 400):
                    if errcode != 301:
                        redirect_permanent = 0

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

        RSS_Resource._db_sync.acquire()
        if error_info:
            RSS_Resource._db['E' + self._id_str] = error_info.encode('utf-8')
        else:
            try:
                del RSS_Resource._db['E' + self._id_str]
            except KeyError:
                pass
        RSS_Resource._db['T' + self._id_str] = struct.pack('>lll', self._last_modified, self._last_updated, self._invalid_since)
        RSS_Resource._db_sync.release()
        if nr_new_items:
            return self._channel_info, items[-nr_new_items:], self._first_item_id + len(items) - 1
        else:
            return self._channel_info, [], self._first_item_id + len(items) - 1


    def get_headlines(self, first_id):
        RSS_Resource._db_sync.acquire()
        try:
            items = map(lambda x: tuple(string.split(x, '\0')), string.split(RSS_Resource._db['D' + self._id_str].decode('utf-8'), '\014'))
        except KeyError:
            items = []
        RSS_Resource._db_sync.release()

        last_id = self._first_item_id + len(items) - 1
        if first_id >= self._first_item_id:
            items = items[first_id + 1 - self._first_item_id:]

        return items, last_id


    def next_update(self, randomize=1):
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

            interval = min(24*60*60,
                           max(30*60, time_span / sum_items / 3))
        elif len(self._history) == 1:
            time_span = self._last_updated - self._history[0][0]

            interval = min(24*60*60, max(60*60, 30*60 + time_span / 3))
        elif self._invalid_since:
            time_span = self._last_updated - self._invalid_since

            interval = min(48*60*60, 4*60*60 + time_span / 4)
        else:
            interval = 8*60*60

        if string.find(string.lower(self._url), 'slashdot.org') != -1:
            # yes, slashdot sucks - this is a special slashdot
            # throttle to avaoid being banned by slashdot
            interval = interval + 180*60

        if randomize:
            return self._last_updated + interval + int(random.normalvariate(30, 50 + interval / 50))
        else:
            return self._last_updated + interval


def RSS_Resource_id2url(res_id):
    RSS_Resource._db_sync.acquire()
    url = RSS_Resource._db['S' + struct.pack('>l', res_id)]
    RSS_Resource._db_sync.release()

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

    channel_info, new_items, last_item_id = resource.update()
    if len(new_items) > 0:
        print 'new items', new_items
