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

import cgi, os, string, sys, time

import parserss
from parserss import RSS_Resource, RSS_Resource_id2url, RSS_Resource_simplify
from parserss import RSS_Resource_db, RSS_Resource_Cursor
from parserss import UrlError

def html_encode(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def process_id(id, db):
    url = RSS_Resource_id2url(id, db.cursor())

    resource = RSS_Resource(url, db)
    next_update = resource.next_update(False)

    if next_update <= now:
        new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update()

        if redirect_resource != None:
            resource = redirect_resource

    channel_info = resource.channel_info()
    sys.stdout.write('<div class="resheader"><h2><a href="%s">%s</a></h2>\n' % (html_encode(channel_info.link.encode('ascii' ,'replace')), html_encode(channel_info.title).encode('utf-8')))

    last_updated, last_modified, invalid_since = resource.times()

    sys.stdout.write('<span class="resinfo">Resource <a href="%s">id %d</a>, feed penalty: %d %%<br />\n' % (html_encode(resource.url()), resource.id(), 100*resource.penalty() / 1024))
    if last_modified:
        sys.stdout.write('updated: %s, ' % (time.asctime(time.gmtime(last_modified)),))
    sys.stdout.write('polled %s' % (time.asctime(time.gmtime(last_updated)),))

    if invalid_since:
        sys.stdout.write('<br /><span class="error">Error: %s</span>' % (resource.error_info(),))

    sys.stdout.write('</span></div>\n<ul class="headlines">\n')
    items, last_id = resource.get_headlines(None)
    items = items[-15:]
    items.reverse()
    for item in items:
        sys.stdout.write('<li><a href="%s">%s</a></li>\n' % (html_encode(item.link.encode('ascii', 'replace')), html_encode(item.title).encode('utf-8')))

    sys.stdout.write('</ul>\n')

    return resource.id()


script_dir = os.path.split(os.getenv('SCRIPT_FILENAME'))[0]
stylesheet = 'http://cmeerw.org/style/webrss.css'

if os.getenv('SERVER_NAME').find('beta.cmeerw.org') != -1:
    parserss.DB_FILENAME = os.path.join(script_dir, '../../files/db/webrss-beta.db')
elif os.getenv('SERVER_NAME').find('cmeerw.org') != -1:
    parserss.DB_FILENAME = os.path.join(script_dir, '../../files/db/webrss.db')
else:
    stylesheet = 'http://cmeerw.hacking.cmeerw.net/style/webrss.css'
    parserss.DB_FILENAME = os.path.join(script_dir, '../db/webrss.db')

parserss.INTERVAL_DIVIDER = 5
parserss.MIN_INTERVAL = 45*60
parserss.MAX_INTERVAL = 12*60*60

def log_message(*msg):
    pass

parserss.log_message = log_message
parserss.init()

db = RSS_Resource_db()
now = int(time.time())

ids = []

form = cgi.FieldStorage()
if form.has_key('id'):
    ids = map(string.atoi, form['id'].value.split(','))

if form.has_key('url'):
    url = form['url'].value
    resource = RSS_Resource(url, db)
    if resource != None:
        new_ids = ids + [resource.id()]
        query = ','.join(map(lambda x: str(x), new_ids))

        sys.stdout.write('Status: 301\r\n')
        sys.stdout.write('Location: http://%s%s?id=%s\r\n' % (html_encode(os.getenv('SERVER_NAME')), html_encode(os.getenv('SCRIPT_NAME')), query))
        sys.stdout.write('\r\n')
        sys.exit(0)

sys.stdout.write('Content-Type: text/html;charset=utf-8\r\n')
sys.stdout.write('\r\n')
sys.stdout.write('''<html><head>
<link type="text/css" rel="stylesheet" href="%s" />
<title>WebRSS (built on JabRSS technology)</title>
</head><body bgcolor="#ffffff">
<h1>WebRSS (built on JabRSS technology)</h1>
''' % (html_encode(stylesheet),))

new_ids = []
for id in ids:
    new_ids.append(process_id(id, db))

query = ','.join(map(lambda x: str(x), new_ids))
sys.stdout.write('<hr /><h1>Control</h1>\n')
sys.stdout.write('<p><ul>\n')
sys.stdout.write('<li><a href="http://%s%s?id=%s">Bookmark URL</a></li>\n' % (html_encode(os.getenv('SERVER_NAME')), html_encode(os.getenv('SCRIPT_NAME')), query))
sys.stdout.write('<li><form action="http://%s%s"><input type="hidden" name="id" value="%s" />URL: <input type="text" name="url" /> <input type="submit" value="Add" /></form></li>\n' % (html_encode(os.getenv('SERVER_NAME')), html_encode(os.getenv('SCRIPT_NAME')), query))
sys.stdout.write('</ul></p>\n')

sys.stdout.write('</p>\n')
sys.stdout.write('</body></html>\n')
