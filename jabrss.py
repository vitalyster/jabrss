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

import bisect, getopt, os, string, struct, sys, thread, threading, time
import traceback
import apsw
import xpcom.components

from parserss import RSS_Resource, RSS_Resource_id2url, RSS_Resource_simplify
from parserss import RSS_Resource_db
from parserss import UrlError


TEXT_WELCOME = '''\
Welcome to JabRSS. Please note that the current privacy policy is quite simple: all your data are belong to me and might be sold to your favorite spammer. :-) For more information, please visit the JabRSS Web site at http://jabrss.cmeerw.org

BTW, if you like this service, you can help keeping it running by making a donation, see http://cmeerw.org/donate.html'''

TEXT_NEWUSER = '''

Now there is only one more thing to do before you can use JabRSS: you have to authorize the presence subscription request from JabRSS. This is necessary so that JabRSS knows your presence status and only sends you RSS headlines when you are online.'''

TEXT_HELP = '''\
Supported commands:

subscribe http://host.domain/path/feed.rss
unsubscribe http://host.domain/path/feed.rss
info http://host.domain/path/feed.rss
list
set ( plaintext | chat | headline )
set also_deliver [ Away ] [ XA ] [ DND ]
set size_limit <num>
set store_messages <num>
configuration
show statistics
show usage

Please refer to the JabRSS command reference at http://cmeerw.org/dev/book/view/30 for more information.

And of course, if you like this service you might also consider a donation, see http://cmeerw.org/donate.html'''

TEXT_MIGRATE = '''\
In order to improve the JabRSS service it has been moved to a new Jabber server. Your settings have just been migrated to the new JabRSS instance. Please see http://cmeerw.org/dev/node/view/122 for all details.'''


JABBER_SERVER = None
JABBER_HOST = None
JABBER_USER = None
JABBER_PASSWORD = None
MIGRATE_FROM = None
MIGRATE_TO = None


opts, args = getopt.getopt(sys.argv[1:], 'f:h:p:s:u:',
                           ['password-file=', 'password=',
                            'server=', 'connect-host=', 'username=',
                            'migrate-from=', 'migrate-to='])

for optname, optval in opts:
    if optname == '-f' or optname == '--password-file':
        fd = open(optval, 'r')
        JABBER_PASSWORD = string.strip(fd.readline())
        fd.close()
    elif optname == '-c' or optname == '--connect-host':
        JABBER_HOST = optval
    elif optname == '-p' or optname == '--password':
        JABBER_PASSWORD = optval
    elif optname == '-s' or optname == '--server':
        JABBER_SERVER = optval
    elif optname == '-u' or optname == '--username':
        JABBER_USER = optval
    elif optname == '--migrate-from':
        MIGRATE_FROM = optval.lower()
    elif optname == '--migrate-to':
        MIGRATE_TO = optval

if JABBER_SERVER == None:
    JABBER_SERVER = raw_input('Jabber server: ')
if JABBER_USER == None:
    JABBER_USER = raw_input('Username: ')
if JABBER_PASSWORD == None:
    JABBER_PASSWORD = raw_input('Password: ')

if JABBER_HOST == None:
    JABBER_HOST = JABBER_SERVER

if JABBER_HOST.find(':') == -1:
    JABBER_HOST += ':5222'


http_proxy = os.getenv('http_proxy')
if http_proxy and (http_proxy[:7] == 'http://'):
    http_proxy = http_proxy[7:]
    if http_proxy[-1] == '/':
        http_proxy = http_proxy[:-1]
else:
    http_proxy = None

https_proxy = os.getenv('https_proxy')
if https_proxy and (https_proxy[:7] == 'http://'):
    https_proxy = https_proxy[7:]
    if https_proxy[-1] == '/':
        https_proxy = https_proxy[:-1]
else:
    https_proxy = None

socks_proxy = os.getenv('socks_proxy')


RSS_Resource.http_proxy = http_proxy


# initialize the event-queue stuff
event_queue_service = xpcom.components.classes['@mozilla.org/event-queue-service;1'].getService(xpcom.components.interfaces.nsIEventQueueService)

event_queue_service.createThreadEventQueue()
event_queue = event_queue_service.getSpecialEventQueue(event_queue_service.CURRENT_THREAD_EVENT_QUEUE)
event_queue.init(0)

main_thread = xpcom.components.classes['@mozilla.org/thread;1'].createInstance(xpcom.components.interfaces.nsIThread).currentThread


# get a proxy object manager
proxy_object_manager = xpcom.components.classes['@mozilla.org/xpcomproxy;1'].getService(xpcom.components.interfaces.nsIProxyObjectManager)


JABBERSESSION_CONTRACTID = '@JabXPCOM.sunsite.dk/Session;1'
TCPSTREAM_CONTRACTID = '@JabXPCOM.sunsite.dk/TcpStream;1'
HTTPPROXYSTREAM_CONTRACTID = '@JabXPCOM.sunsite.dk/HttpProxyStream;1'
SOCKSPROXYSTREAM_CONTRACTID = '@JabXPCOM.sunsite.dk/SocksProxyStream;1'

jabISession = xpcom.components.interfaces.jabISession
jabIPacket = xpcom.components.interfaces.jabIPacket
jabIPresence = xpcom.components.interfaces.jabIPresence
jabIInfoQuery = xpcom.components.interfaces.jabIInfoQuery
jabIConstMessage = xpcom.components.interfaces.jabIConstMessage
judoIConstElement = xpcom.components.interfaces.judoIConstElement

jab_session = xpcom.components.classes[JABBERSESSION_CONTRACTID].createInstance(jabISession)


class Resource_Guard:
    def __init__(self, cleanup_handler):
        self._cleanup_handler = cleanup_handler

    def __del__(self):
        self._cleanup_handler()


def get_db():
    db = apsw.Connection('jabrss.db')
    db.setbusytimeout(3000)
    return db

db = get_db()


class DataStorage:
    def __init__(self):
        self._users = {}
        self._users_sync = threading.Lock()
        self._resources = {}
        self._res_uids = {}


    def _redirect_cb(self, redirect_url, cursor, redirect_count):
        redirect_resource = self.get_resource(redirect_url, cursor)
        redirect_resource.unlock()

        new_items, next_item_id, redirect_target, redirect_seq, redirects = redirect_resource.update(cursor.getconnection(), redirect_count)
        if len(new_items) > 0:
            redirect_resource.unlock()
            redirects.append((redirect_resource, new_items, next_item_id))

        if redirect_target != None:
            redirect_resource = redirect_target

        return redirect_resource, redirects


    def users_lock(self):
        self._users_sync.acquire()

    def users_unlock(self):
        self._users_sync.release()


    # get resource (by URL) from cache, database or create new object
    # @param res_cursor db cursor for resource database
    # @return resource (already locked, must be unlocked)
    def get_resource(self, url, res_cursor=None, lock=True):
        resource_url = RSS_Resource_simplify(url)

        while resource_url != None:
            cached_resource = True

            try:
                # TODO: possible race-condition with evict_resource
                resource = self._resources[resource_url]
                if lock:
                    resource.lock()
            except KeyError:
                resource = RSS_Resource(resource_url, res_cursor)
                if lock:
                    resource.lock()
                cached_resource = False

            resource_url, redirect_seq = resource.redirect_info()

            if resource_url != None and lock:
                resource.unlock()

        if not cached_resource:
            self._resources[resource.url()] = resource
            self._resources[resource.id()] = resource
            RSS_Resource.schedule_update(resource)

        return resource

    # @throws KeyError
    def get_cached_resource(self, url):
        simple_url = RSS_Resource_simplify(url)
        return self._resources[simple_url]

    def get_resource_by_id(self, res_id, res_cursor=None):
        try:
            return self._resources[res_id]
        except KeyError:
            resource_url = RSS_Resource_id2url(res_id)
            return self.get_resource(resource_url, res_cursor, False)


    def evict_resource(self, resource):
        try:
            del self._resources[resource.url()]
        except KeyError:
            pass
        try:
            del self._resources[resource.id()]
        except KeyError:
            pass

        try:
            del self._res_uids[resource.id()]
        except KeyError:
            pass


    def get_resource_uids(self, resource, db_cursor=None):
        res_id = resource.id()

        try:
            res_uids = self._res_uids[res_id]
        except KeyError:
            res_uids = []

            if db_cursor == None:
                cursor = db.cursor()
            else:
                cursor = db_cursor

            cursor.execute('SELECT uid FROM user_resource WHERE rid=?',
                           (res_id,))
            for row in cursor:
                res_uids.append(row[0])

            self._res_uids[res_id] = res_uids


        return res_uids


    # @throws KeyError
    def get_user(self, jid):
        pos = string.find(jid, '/')
        if pos != -1:
            jid_resource = jid[pos + 1:]
            jid = jid[:pos]
        else:
            jid_resource = ''

        jid = jid.lower()

        return self._users[jid], jid_resource

    # @throws KeyError
    def get_user_by_id(self, uid):
        return self._users[uid]

    def get_new_user(self, jid, presence_show):
        pos = string.find(jid, '/')
        if pos != -1:
            jid_resource = jid[pos + 1:]
            jid = jid[:pos]
        else:
            if presence_show == None:
                jid_resource = None
            else:
                jid_resource = ''

        jid = jid.lower()

        try:
            user = self._users[jid]
            user.set_presence(jid_resource, presence_show)
            return user, jid_resource
        except KeyError:
            user = JabberUser(jid, jid_resource, presence_show)

            self.users_lock()
            try:
                self._users[jid] = user
                self._users[user.uid()] = user
            finally:
                self.users_unlock()

            for res_id in user._res_ids:
                try:
                    storage.get_resource_by_id(res_id)
                except:
                    print 'caught exception adding new user'
                    traceback.print_exc(file=sys.stdout)

            return user, jid_resource

    def evict_user(self, user):
        self.users_lock()
        try:
            try:
                del self._users[user.jid()]
            except KeyError:
                pass

            try:
                del self._users[user.uid()]
            except KeyError:
                pass
        finally:
            self.users_unlock()

    def evict_all_users(self):
        self.users_lock()
        self._users = {}
        self.users_unlock()


    def remove_user(self, user):
        cursor = db.cursor()
        cursor.execute('BEGIN')
        db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))

        cursor.execute('DELETE FROM user_stat WHERE uid=?',
                       (user.uid(),))
        cursor.execute('DELETE FROM user_resource WHERE uid=?',
                       (user.uid(),))
        cursor.execute('DELETE FROM user WHERE uid=?',
                       (user.uid(),))
        del db_txn_end

        print 'user %s (id %d) deleted' % (user._jid.encode('iso8859-1', 'replace'), user._uid)
        self.evict_user(user)



storage = DataStorage()
RSS_Resource._redirect_cb = storage._redirect_cb

last_migrated = 0


def strip_resource(jid):
    pos = string.find(jid, '/')
    if pos != -1:
        jid = jid[:pos]

    return jid.lower()

class JabberUser:
    ##
    # self._jid
    # self._uid
    # self._uid_str
    # self._res_ids
    # self._configuration & 0x0003 .. message type
    #   (0 = plain text, 1 = headline messages, 2 = chat message, 3 = reserved)
    # self._configuration & 0x001c .. deliver when away
    #   (4 = away, 8 = xa, 16 = dnd)
    # self._configuration & 0x0020 .. migration flag
    # self._store_messages .. number of messages that should be stored
    # self._size_limit .. limit the size of descriptions
    # self._stat_start .. first day corresponding to _nr_headlines[-1]
    # self._nr_headlines[8] .. number of headlines delivered (per week)
    # self._size_headlines[8] .. size of headlines delivered (per week)
    ##
    def __init__(self, jid, jid_resource, show=None):
        self._jid = jid
        if jid_resource != None:
            self._jid_resources = {jid_resource : show}
        else:
            self._jid_resources = {}
        self._update_presence()

        self._configuration = 0
        self._store_messages = 16
        self._size_limit = None

        cursor = db.cursor()

        try:
            cursor.execute('SELECT uid, conf, store_messages, size_limit FROM user WHERE jid=?',
                       (self._jid,))
            self._uid, self._configuration, self._store_messages, self._size_limit = cursor.next()
        except StopIteration:
            cursor.execute('INSERT INTO user (jid, conf, store_messages, size_limit) VALUES (?, ?, ?, ?)',
                           (self._jid, self._configuration, self._store_messages, self._size_limit))
            self._uid = db.last_insert_rowid()

        if self._size_limit == None:
            self._size_limit = 0
        else:
            self._size_limit *= 16


        self._res_ids = []
        cursor.execute('SELECT rid FROM user_resource WHERE uid=?',
                       (self._uid,))
        for row in cursor:
            self._res_ids.append(row[0])

        self._stat_start = 0
        self._nr_headlines = []
        self._size_headlines = []

        cursor.execute('SELECT start, nr_msgs0, nr_msgs1, nr_msgs2, nr_msgs3, nr_msgs4, nr_msgs5, nr_msgs6, nr_msgs7, size_msgs0, size_msgs1, size_msgs2, size_msgs3, size_msgs4, size_msgs5, size_msgs6, size_msgs7 FROM user_stat WHERE uid=?',
                       (self._uid,))
        for row in cursor:
            self._stat_start = row[0]
            self._nr_headlines = list(row[1:9])
            self._size_headlines = list(row[9:17])

        self._adjust_statistics()


    def _adjust_statistics(self):
        gmtime = time.gmtime()
        new_stat_start = gmtime[7] - gmtime[6]

        if self._stat_start <= new_stat_start:
            shift = (new_stat_start - self._stat_start) / 7
        else:
            shift = (new_stat_start + 366 - self._stat_start) / 7

        self._nr_headlines = self._nr_headlines[shift:]
        self._size_headlines = self._size_headlines[shift:]
        self._stat_start = new_stat_start

        if len(self._nr_headlines) < 8:
            self._nr_headlines += (8 - len(self._nr_headlines)) * [0]
        if len(self._size_headlines) < 8:
            self._size_headlines += (8 - len(self._size_headlines)) * [0]

    def _commit_statistics(self, db_cursor=None):
        if db_cursor == None:
            cursor = db.cursor()
        else:
            cursor = db_cursor

        cursor.execute('INSERT INTO user_stat (uid, start, nr_msgs0, nr_msgs1, nr_msgs2, nr_msgs3, nr_msgs4, nr_msgs5, nr_msgs6, nr_msgs7, size_msgs0, size_msgs1, size_msgs2, size_msgs3, size_msgs4, size_msgs5, size_msgs6, size_msgs7) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                          tuple([self._uid, self._stat_start] + self._nr_headlines + self._size_headlines))


    def uid(self):
        return self._uid

    def jid(self):
        return self._jid


    # @return (day of year, [nr_headlines])
    def get_statistics(self):
        return (self._stat_start, self._nr_headlines, self._size_headlines)


    def set_message_type(self, message_type):
        self._configuration = (self._configuration & ~0x0003) | (message_type & 0x0003)
        self._update_configuration()

    def get_message_type(self):
        return self._configuration & 0x0003


    def set_migrated(self, migrated):
        if migrated:
            migrated_val = 0x20
        else:
            migrated_val = 0
        self._configuration = (self._configuration & ~0x0020) | migrated_val
        self._update_configuration()

    def get_migrated(self):
        return (self._configuration & 0x0020) != 0


    def set_size_limit(self, size_limit):
        if size_limit > 0:
            self._size_limit = min(size_limit, 3072)
        else:
            self._size_limit = 0
        self._update_configuration()

    def get_size_limit(self):
        if self._size_limit > 0:
            return min(self._size_limit, 3072)
        else:
            return 1024


    def set_store_messages(self, store_messages):
        self._store_messages = min(64, max(0, store_messages))
        self._update_configuration()

    def get_store_messages(self):
        return self._store_messages


    def get_deliver_when_away(self):
        return self._configuration & 0x4

    def get_deliver_when_xa(self):
        return self._configuration & 0x8

    def get_deliver_when_dnd(self):
        return self._configuration & 0x10

    def set_delivery_state(self, state):
        self._configuration = (self._configuration & ~0x001c) | ((state & 7) << 2)
        self._update_configuration()
        

    def _update_configuration(self):
        cursor = db.cursor()
        cursor.execute('UPDATE user SET conf=?, store_messages=?, size_limit=? WHERE uid=?',
                       (self._configuration, self._store_messages, self._size_limit / 16, self._uid))

    def set_configuration(self, conf, store_messages, size_limit):
        self._configuration = conf
        self._store_messages = store_messages
        self._size_limit = size_limit
        self._update_configuration()

    def get_configuration(self):
        return (self._configuration, self._store_messages, self._size_limit)


    def _update_presence(self):
        new_show = jabIPresence.stOffline
        for show in self._jid_resources.values():
            if (show >= jabIPresence.stOnline) and ((show < new_show) or (new_show == jabIPresence.stOffline)):
                new_show = show

        self._show = new_show

    def set_presence(self, jid_resource, show):
        if show == None:
            return

        if show > jabIPresence.stOffline:
            self._jid_resources[jid_resource] = show
        else:
            try:
                del self._jid_resources[jid_resource]
            except KeyError:
                pass

            if jid_resource == '':
                for res in self._jid_resources.keys():
                    try:
                        del self._jid_resources[res]
                    except KeyError:
                        pass

        self._update_presence()

    # @throws KeyError
    def presence(self, jid_resource=None):
        if jid_resource == None:
            return self._show
        else:
            return self._jid_resources[jid_resource]


    def get_delivery_state(self, presence=0):
        if presence == 0:
            presence = self.presence()

        if (presence == jabIPresence.stOnline) or (presence == jabIPresence.stChat):
            return 1
        # self._configuration & 0x001c .. deliver when away
        #   (4 = away, 8 = xa, 16 = dnd)
        elif (presence == jabIPresence.stAway) and (self._configuration & 0x4):
            return 1
        elif (presence == jabIPresence.stXA) and (self._configuration & 0x8):
            return 1
        elif (presence == jabIPresence.stDND) and (self._configuration & 0x10):
            return 1

        return 0


    def resources(self):
        return self._res_ids

    # @throws ValueError
    def add_resource(self, resource, seq_nr=None, db_cursor=None):
        res_id = resource.id()
        if res_id not in self._res_ids:
            self._res_ids.append(res_id)

            # also update storage res->uid mapping
            res_uids = storage.get_resource_uids(resource, db_cursor)
            res_uids.append(self.uid())

            if db_cursor == None:
                cursor = db.cursor()
            else:
                cursor = db_cursor

            cursor.execute('INSERT INTO user_resource (uid, rid, seq_nr) VALUES (?, ?, ?)',
                           (self._uid, res_id, seq_nr))
        else:
            raise ValueError(res_id)

    # @throws ValueError
    def remove_resource(self, resource, db_cursor=None):
        res_id = resource.id()

        self._res_ids.remove(res_id)

        # also update storage res->uid mapping
        res_uids = storage.get_resource_uids(resource)
        try:
            res_uids.remove(self.uid())
        except ValueError:
            pass
        if len(res_uids) == 0:
            storage.evict_resource(resource)

        if db_cursor == None:
            cursor = db.cursor()
        else:
            cursor = db_cursor

        cursor.execute('DELETE FROM user_resource WHERE uid=? AND rid=?',
                       (self._uid, res_id))

    def headline_id(self, resource, db_cursor=None):
        if db_cursor == None:
            cursor = db.cursor()
        else:
            cursor = db_cursor

        cursor.execute('SELECT seq_nr FROM user_resource WHERE uid=? AND rid=?',
                       (self._uid, resource.id()))

        headline_id = None
        for row in cursor:
            headline_id = row[0]

        if headline_id == None:
            headline_id = 0

        return headline_id


    def update_headline(self, resource, headline_id, new_items=[],
                        db_cursor=None):
        db_txn_end = None
        if db_cursor == None:
            cursor = db.cursor()
            cursor.execute('BEGIN')
            db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))
        else:
            cursor = db_cursor

        cursor.execute('UPDATE user_resource SET seq_nr=? WHERE uid=? AND rid=?',
                       (headline_id, self._uid, resource.id()))

        if new_items:
            self._adjust_statistics()
            self._nr_headlines[-1] += len(new_items)
            items_size = reduce(lambda size, x: (size + len(x.title) +
                                                 len(x.link) +
                                                 (x.descr_plain!=None and len(x.descr_plain))),
                                [0] + new_items)
            self._size_headlines[-1] += items_size
            self._commit_statistics(cursor)

        del db_txn_end


class JabberSessionEventHandler:
    _com_interfaces_ = [xpcom.components.interfaces.jabISessionEvtConnected,
                        xpcom.components.interfaces.jabISessionEvtDisconnected,
                        xpcom.components.interfaces.jabISessionEvtAuthError,
                        xpcom.components.interfaces.jabISessionEvtIq,
                        xpcom.components.interfaces.jabISessionEvtMessage,
                        xpcom.components.interfaces.jabISessionEvtUnknownPacket,
                        xpcom.components.interfaces.jabISessionEvtIqVersion,
                        xpcom.components.interfaces.jabISessionEvtIqLast,
                        xpcom.components.interfaces.jabISessionEvtPresence,
                        xpcom.components.interfaces.jabISessionEvtPresenceRequest]

    def __init__(self, jab_session):
        self._jab_session = jab_session

        self._update_queue = []
        self._update_queue_cond = threading.Condition()
        RSS_Resource.schedule_update = self.schedule_update

        self._connected = 0
        self._shutdown = 0


    def _process_help(self, message, user):
        reply = message.reply(TEXT_HELP)
        self._jab_session.sendPacket(reply)

    def _process_list(self, message, user):
        reply_body = []
        for res_id in user.resources():
            resource = storage.get_resource_by_id(res_id)
            res_updated, res_modified, res_invalid = resource.times()
            if res_invalid == None:
                reply_body.append(resource.url())
            else:
                error_info = resource.error_info()
                if error_info:
                    reply_body.append('%s (Error: %s)' % (resource.url(),
                                                          error_info))
                else:
                    reply_body.append('%s (error)' % (resource.url(),))

        if reply_body:
            reply_body.sort()
            reply = message.reply(string.join(reply_body, '\n'))
        else:
            reply = message.reply('Sorry, you are currently not subscribed to any RSS feeds.')
        self._jab_session.sendPacket(reply)


    def _process_set(self, message, user, argstr):
        try:
            arg = string.strip(argstr)
            if arg == 'plaintext':
                user.set_message_type(0)
                reply_body = 'Message type set to "plaintext"'
            elif arg == 'headline':
                user.set_message_type(1)
                reply_body = 'Message type set to "headline"'
            elif arg == 'chat':
                user.set_message_type(2)
                reply_body = 'Message type set to "chat"'
            else:
                args = string.split(arg)
                if args[0] == 'also_deliver':
                    deliver_cfg = 0

                    for s in args[1:]:
                        s = string.lower(s)
                        if s == 'away':
                            deliver_cfg = deliver_cfg | 1
                        elif s == 'xa':
                            deliver_cfg = deliver_cfg | 2
                        elif s == 'dnd':
                            deliver_cfg = deliver_cfg | 4
                        elif s == 'none':
                            pass
                        else:
                            raise 'unknown setting for "also_deliver"'

                    user.set_delivery_state(deliver_cfg)
                    reply_body = '"also_deliver" setting adjusted'
                elif args[0] == 'store_messages':
                    store_messages = string.atoi(args[1])
                    user.set_store_messages(store_messages)
                    reply_body = '"store_messages" setting adjusted'
                elif args[0] == 'size_limit':
                    size_limit = string.atoi(args[1])
                    user.set_size_limit(size_limit)
                    reply_body = '"size_limit" setting adjusted'
                else:
                    reply_body = 'Unknown configuration option'
        except:
            reply_body = 'Unknown error setting configuration option'

        reply = message.reply(reply_body)
        self._jab_session.sendPacket(reply)


    def _process_config(self, message, user):
        reply_body = ['Current configuration:']

        message_type = user.get_message_type()
        if message_type == 0:
            reply_body.append('message type "plaintext"')
        elif message_type == 1:
            reply_body.append('message type "headline"')
        elif message_type == 2:
            reply_body.append('message type "chat"')
        else:
            reply_body.append('message type <reserved>')

        deliver_when_away = user.get_deliver_when_away()
        deliver_when_xa = user.get_deliver_when_xa()
        deliver_when_dnd = user.get_deliver_when_dnd()
        if deliver_when_away or deliver_when_xa or deliver_when_dnd:
            deliver_list = []
            if deliver_when_away:
                deliver_list.append('Away')
            if deliver_when_xa:
                deliver_list.append('XA')
            if deliver_when_dnd:
                deliver_list.append('DND')
            reply_body.append('Headlines will also be delivered when you are %s' % (string.join(deliver_list, ', ')))

        store_messages = user.get_store_messages()
        reply_body.append('At most %d headlines will be stored for later delivery' % (store_messages,))

        size_limit = user.get_size_limit()
        if size_limit:
            reply_body.append('The size of a headline message will be limited to about %d bytes' % (size_limit,))

        reply = message.reply(string.join(reply_body, '\n'))
        self._jab_session.sendPacket(reply)


    def _process_statistics(self, message, user):
        cursor = db.cursor()
        reply_body = ['Statistics:']

        cursor.execute('SELECT count(uid) FROM user')

        total_users = 0
        for row in cursor:
            total_users = row[0]

        cursor.execute('SELECT count(rid) FROM (SELECT DISTINCT rid FROM user_resource)')

        total_resources = 0
        for row in cursor:
            total_resources = row[0]

        reply_body.append('Users online/total: %d/%d' %
                          (len(storage._users) / 2, total_users))
        reply_body.append('RDF feeds used/total: %d/%d' %
                          (len(storage._resources) / 2, total_resources))

        reply = message.reply(string.join(reply_body, '\n'))
        self._jab_session.sendPacket(reply)


    def _process_usage(self, message, user):
        reply_body = ['Usage Statistics:']

        reply_body.append('subscribed to %d feeds' % (len(user.resources())))

        stat_start, nr_headlines, size_headlines = user.get_statistics()

        stat_start = stat_start - (len(nr_headlines) - 1) * 7
        time_base = time.mktime((time.localtime()[0], 1, 1, 0, 0, 0, 0, 0, -1)) - 24*60*60
        for i in range(0, len(nr_headlines)):
            nr = nr_headlines[i]
            size = size_headlines[i]
            if nr > 0:
                month1, day1 = time.localtime(time_base + stat_start*24*60*60)[1:3]
                month2, day2 = time.localtime(time_base + (stat_start + 6)*24*60*60)[1:3]
                if size > 11*1024:
                    size_str = '%d kiB' % (size / 1024,)
                else:
                    size_str = '%d Bytes' % (size,)
                reply_body.append('%d/%d - %d/%d: %d headlines (%s)' % (day1, month1, day2, month2, nr, size_str))

            stat_start = stat_start + 7

        reply = message.reply(string.join(reply_body, '\n'))
        self._jab_session.sendPacket(reply)


    def _process_migrate(self, message, argstr):
        args = string.split(argstr)

        jid = args[0]
        conf = map(lambda x: string.atoi(x, 16), string.split(args[1], ','))
        args = args[2:]
        jid = strip_resource(jid)

        msg_text = TEXT_MIGRATE
        try:
            storage.get_user(jid)
        except KeyError:
            msg_text += TEXT_NEWUSER

        user, jid_resource = storage.get_new_user(jid, None)
        print 'migrating user', user.jid().encode('iso8859-1', 'replace')
        user.set_configuration(conf[0], conf[1], conf[2])

        for arg in args:
            try:
                url = arg.encode('ascii')

                resource = storage.get_resource(url)
                try:
                    user.add_resource(resource)

                    new_items, headline_id = resource.get_headlines(0)
                    # suppress headline delivery
                    user.update_headline(resource, headline_id, [])
                    # TODO
                finally:
                    resource.unlock()

            except UrlError, url_error:
                pass
            except ValueError:
                pass
            except:
                print user.jid().encode('iso8859-1', 'replace'), 'error subscribing to', url
                traceback.print_exc(file=sys.stdout)

        self._jab_session.sendPacket(self._jab_session.createPresenceRequest(user.jid(), jabIPresence.ptSubRequest))

        self._jab_session.sendPacket(self._jab_session.createMessage(user.jid(), msg_text, jabIConstMessage.mtNormal))


    def _process_subscribe(self, message, user, argstr):
        if MIGRATE_TO:
            reply = message.reply('Sorry, this JabRSS instance doesn\'t support subscriptions to new feeds anymore, please migrate your account to the new JabRSS instance at %s' % (MIGRATE_TO,))
            self._jab_session.sendPacket(reply)
            return


        args = string.split(argstr)

        for arg in args:
            try:
                url = arg.encode('ascii')

                resource = storage.get_resource(url)
                try:
                    url = resource.url()
                    user.add_resource(resource)

                    new_items, headline_id = resource.get_headlines(0)
                    if new_items:
                        self._send_headlines(self._jab_session, user, resource,
                                             new_items)
                        user.update_headline(resource, headline_id, new_items)
                finally:
                    resource.unlock()

                print user.jid().encode('iso8859-1', 'replace'), 'subscribed to', url
                reply = message.reply('You have been subscribed to %s' % (url,))
            except UrlError, url_error:
                print user.jid().encode('iso8859-1', 'replace'), 'error (%s) subscribing to' % (url_error.args[0],), url
                reply = message.reply('Error (%s) subscribing to %s' % (url_error.args[0], url))
            except ValueError:
                print user.jid().encode('iso8859-1', 'replace'), 'already subscribed to', url
                reply = message.reply('You are already subscribed to %s' % (url,))
            except:
                print user.jid().encode('iso8859-1', 'replace'), 'error subscribing to', url
                traceback.print_exc(file=sys.stdout)
                reply = message.reply('For some reason you couldn\'t be subscribed to %s' % (url,))

            self._jab_session.sendPacket(reply)

    def _process_unsubscribe(self, message, user, argstr):
        args = string.split(argstr)

        for arg in args:
            url = arg.encode('ascii')

            try:
                resource = storage.get_cached_resource(url)
                resource.lock()
                try:
                    user.remove_resource(resource)
                finally:
                    resource.unlock()

                print user.jid().encode('iso8859-1', 'replace'), 'unsubscribed from', url
                reply = message.reply('You have been unsubscribed from %s' % (url,))
            except KeyError:
                reply = message.reply('For some reason you couldn\'t be unsubscribed from %s' % (url,))
            except ValueError:
                reply = message.reply('No need to unsubscribe, you weren\'t subscribed to %s anyway' % (url,))

            self._jab_session.sendPacket(reply)

    def _process_info(self, message, user, argstr):
        args = string.split(argstr)

        for arg in args:
            url = arg.encode('ascii')

            try:
                resource = storage.get_cached_resource(url)

                last_updated, last_modified, invalid_since = resource.times()
                next_update = resource.next_update(0)
                history = resource.history()

                text = ['Information about %s' % (url,)]
                text.append('')
                text.append('Last polled: %s GMT' % (time.asctime(time.gmtime(last_updated)),))

                if len(history):
                    text.append('Last updated: %s GMT' % (time.asctime(time.gmtime(history[-1][0])),))
                text.append('Next poll: ca. %s GMT' % (time.asctime(time.gmtime(next_update)),))
                text.append('Update interval: ~%d min' % ((next_update - last_updated) / 60,))

                if invalid_since:
                    error_info = resource.error_info()
                    if error_info:
                        text.append('')
                        text.append('Error: %s' % (error_info,))

                if len(history) >= 4:
                    sum_items = reduce(lambda x, y: (y[0], x[1] + y[1]),
                                       history[1:-1])[1]
                    time_span = history[-1][0] - history[0][0]

                    msg_rate = sum_items / (time_span / 2592000.0)

                    if msg_rate > 150.0:
                        rate_unit = 'day'
                        msg_rate = int(msg_rate / 30.0)
                    elif msg_rate > 22.0:
                        rate_unit = 'week'
                        msg_rate = int(msg_rate / (30.0/7.0))
                    else:
                        rate_unit = 'month'
                        msg_rate = int(msg_rate)

                    text.append('')
                    text.append('Frequency: ~%d headlines per %s' % (msg_rate, rate_unit))

                reply = message.reply(string.join(text, '\n'))
            except KeyError:
                reply = message.reply('No information available about %s' % (url,))

            self._jab_session.sendPacket(reply)

    def _remove_user(self, jid):
        iq = self._jab_session.createInfoQuery('', jabIInfoQuery.iqtSet)
        query = iq.addQuery('roster')
        item = query.addElement('item')
        item.putAttrib('jid', jid)
        item.putAttrib('subscription', 'remove')

        #print 'sending remove request', jid.encode('iso8859-1', 'replace')
        self._jab_session.sendPacket(iq)

    # delete all user information from database and evict user
    def _delete_user(self, jid):
        try:
            user, jid_resource = storage.get_new_user(jid,
                                                      jabIPresence.stOffline)

            print 'deleting user\'s %s subscriptions: %s' % (jid.encode('iso8859-1', 'replace'), repr(user.resources()))
            for res_id in user.resources():
                resource = storage.get_resource_by_id(res_id)
                user.remove_resource(resource)

            storage.remove_user(user)
        except KeyError:
            traceback.print_exc(file=sys.stdout)


    def onConnected(self, tag):
        print 'connected, id:', tag.getAttrib('id').encode('iso8859-1', 'replace'), tag.toXML().encode('iso8859-1', 'replace')

        # request agents list from server
        iq_agents = self._jab_session.createInfoQuery('', jabIInfoQuery.iqtGet)
        iq_agents.addQuery('agents')
        self._jab_session.sendPacket(iq_agents)

        my_presence = self._jab_session.createMyPresence(jabIPresence.ptAvailable,
                                                         jabIPresence.stOnline,
                                                         '', 0)
        self._jab_session.sendPacket(my_presence)
        self._connected = 1

    def onDisconnected(self):
        if self._connected:
            self._connected = 0

            storage.evict_all_users()

            # reconnect after some timeout
            print 'disconnected'
            if not self._shutdown:
                thread.start_new_thread(wait_and_reconnect,
                                        (self._jab_session, event_queue, 60))

    def onAuthError(self, code, data):
        print 'authError', code, data.encode('iso8859-1', 'replace')
        self._connected = 0
        self._jab_session.disconnect()

    def onIq(self, tag):
        if tag.getAttrib('type') == 'result':
            query = tag.findElement('query')
            if query:
                xmlns = query.getAttrib('xmlns')
                print 'iq', xmlns.encode('iso8859-1', 'replace')
            else:
                xmlns = None

            if xmlns == 'jabber:iq:roster':
                subscribers = {}
                for item in query.findElements('item'):
                    item.queryInterface(judoIConstElement)

                    jid = strip_resource(item.getAttrib('jid'))
                    subscription = item.getAttrib('subscription')
                    if subscription == 'both':
                        subscribers[jid.lower()] = True
                    else:
                        print 'subscription for user "%s" is "%s" (!= "both")' % (jid.encode('iso8859-1', 'replace'), subscription.encode('iso8859-1', 'replace'))
                        self._remove_user(jid)

                cursor = db.cursor()
                cursor.execute('SELECT jid FROM user')
                delete_users = []
                for row in cursor:
                    username = row[0]
                    if not subscribers.has_key(username):
                        delete_users.append(username)

                for username in delete_users:
                    print 'user "%s" in database, but not subscribed to the service' % (username.encode('iso8859-1', 'replace'),)
                    self._delete_user(username)

            elif xmlns == 'jabber:iq:agents':
                # ignore agents
                pass
            else:
                print 'iq', tag.toXML().encode('iso8859-1', 'replace')
        else:
            print 'iq', tag.toXML().encode('iso8859-1', 'replace')

    def onMessage(self, message):
        if message.type == jabIConstMessage.mtError:
            print 'ignoring error message from', message.sender.encode('iso8859-1', 'replace')
            return
        elif (message.type != jabIConstMessage.mtNormal) and (message.type != jabIConstMessage.mtChat):
            print 'ignoring unknown message type from', message.sender.encode('iso8859-1', 'replace')
            return

        body = string.strip(message.body)
        print 'message', message.sender.encode('iso8859-1', 'replace'), body.encode('iso8859-1', 'replace')

        if body[:8] == 'migrate ' and MIGRATE_FROM == message.sender.lower():
            self._process_migrate(message, body[8:])
            return

        try:
            user, jid_resource = storage.get_user(message.sender)

            if body == 'help':
                self._process_help(message, user)
            elif body == 'list':
                self._process_list(message, user)
            elif body[:4] == 'set ':
                self._process_set(message, user, body[4:])
            elif (body == 'configuration') or (body == 'config'):
                self._process_config(message, user)
            elif (body == 'statistics') or (body == 'show statistics'):
                self._process_statistics(message, user)
            elif (body == 'usage') or (body == 'show usage'):
                self._process_usage(message, user)
            elif body[:10] == 'subscribe ':
                self._process_subscribe(message, user, body[10:])
            elif body[:12] == 'unsubscribe ':
                self._process_unsubscribe(message, user, body[12:])
            elif body[:5] == 'info ':
                self._process_info(message, user, body[5:])
            elif body == 'debug resources':
                resources = storage._resources.keys()
                resources.sort()
                print repr(resources)
            elif body == 'debug users':
                users = storage._users.keys()
                users.sort()
                print repr(users)
            else:
                reply = message.reply('Unknown command. Please refer to the documentation at http://cmeerw.org/dev/book/view/30')
                self._jab_session.sendPacket(reply)
        except KeyError:
            traceback.print_exc(file=sys.stdout)

    def onUnknownPacket(self, tag):
        print 'unknownPacket', tag.toXML().encode('iso8859-1', 'replace')
        if tag.name == 'stream:error':
            print 'stream error: close connection and try to reconnect'

            storage.evict_all_users()

            if self._connected:
                self._connected = 0
                self._jab_session.disconnect()

                # reconnect after some timeout
                if not self._shutdown:
                    thread.start_new_thread(wait_and_reconnect,
                                            (self._jab_session, event_queue, 60))

    def onIqVersion(self):
        print 'iqVersion'
        return ('jabrss', '0.40', '')

    def onIqLast(self):
        print 'iqLast'
        return ''

    def onPresence(self, presence, type):
        global last_migrated

        print 'presence', presence.sender.encode('iso8859-1', 'replace'), presence.type, presence.show

        if (presence.type == jabIPresence.ptUnsubscribed):
            self._delete_user(presence.sender)
            self._remove_user(presence.sender)

        elif (presence.type == jabIPresence.ptAvailable):
            user, jid_resource = storage.get_new_user(presence.sender,
                                                      presence.show)

            if user.get_delivery_state(presence.show):
                subs = None
                if MIGRATE_TO != None and not user.get_migrated():
                    # limit rate of account migration to at most 1 account
                    # per 30 seconds
                    if last_migrated + 30 < time.time():
                        # migrate user to another JabRSS instance
                        subs = []

                for res_id in user.resources():
                    resource = storage.get_resource_by_id(res_id)
                    if subs != None:
                        subs.append(resource.url())

                    try:
                        resource.lock()
                        headline_id = user.headline_id(resource)
                        old_id = headline_id

                        new_items, headline_id = resource.get_headlines(headline_id)
                        if new_items:
                            self._send_headlines(self._jab_session, user,
                                                 resource, new_items)

                        redirect_url, redirect_seq = resource.redirect_info()
                        if redirect_url != None:
                            try:
                                user.remove_resource(resource)
                            except ValueError:
                                pass
                            resource.unlock()

                            resource = storage.get_resource(redirect_url)
                            try:
                                user.add_resource(resource, redirect_seq)
                            except ValueError:
                                pass

                        elif new_items or headline_id != old_id:
                            user.update_headline(resource, headline_id,
                                                 new_items)
                    finally:
                        resource.unlock()

                if subs != None:
                    print 'migrating user', presence.sender.encode('iso8859-1', 'replace')
                    msg_text = 'migrate %s ' % (user.jid(),)
                    msg_text += '%08x,%02x,%04x ' % user.get_configuration()
                    msg_text += ' '.join(subs)
                    self._jab_session.sendPacket(self._jab_session.createMessage(MIGRATE_TO, msg_text, jabIConstMessage.mtNormal))
                    user.set_migrated(1)
                    last_migrated = time.time()
                    self._jab_session.sendPacket(self._jab_session.createMessage(presence.sender, TEXT_MIGRATE, jabIConstMessage.mtNormal))

        elif (presence.type != jabIPresence.ptSubscribed):
            try:
                user, jid_resource = storage.get_user(presence.sender)
                user.set_presence(jid_resource, presence.show)
                if user.presence() == jabIPresence.stOffline:
                    print 'evicting user', user.jid().encode('iso8859-1', 'replace')
                    storage.evict_user(user)
            except KeyError:
                pass
 
    def onPresenceRequest(self, presence):
        print 'presenceRequest', presence.sender.encode('iso8859-1', 'replace'), presence.type, presence.show


        # accept presence request
        if presence.type == jabIPresence.ptSubRequest:
            if MIGRATE_TO:
                message = self._jab_session.createMessage(presence.sender, 'Sorry, this JabRSS instance doesn\'t accept new users, please use the new JabRSS instance at %s instead.' % (MIGRATE_TO,), jabIConstMessage.mtNormal)
                self._jab_session.sendPacket(message)
                self._remove_user(presence.sender)
                return

            self._jab_session.sendPacket(presence.reply(jabIPresence.ptSubscribed))
        elif presence.type == jabIPresence.ptUnsubRequest:
            self._jab_session.sendPacket(presence.reply(jabIPresence.ptUnsubscribed))
            self._delete_user(presence.sender)
            self._remove_user(presence.sender)

        if presence.type == jabIPresence.ptSubRequest:
            self._jab_session.sendPacket(presence.reply(jabIPresence.ptSubRequest))

            msg_text = TEXT_WELCOME
            try:
                storage.get_user(presence.sender)
            except KeyError:
                msg_text += TEXT_NEWUSER

            welcome_message = self._jab_session.createMessage(presence.sender, msg_text, jabIConstMessage.mtNormal)
            self._jab_session.sendPacket(welcome_message)


    def _send_headlines(self, jab_session, user, resource, items, not_stored=False):
        print 'sending', user.jid().encode('iso8859-1', 'replace'), resource.url()
        message_type = user.get_message_type()

        channel_info = resource.channel_info()

        if message_type == 0 or message_type == 2:
            body = ''

            if not not_stored and (len(items) > user.get_store_messages()):
                body = body + ('%d headlines suppressed (from %s)\n\n' % (len(items) - user.get_store_messages(), channel_info.title))
                items = items[-user.get_store_messages():]

            for item in items:
                try:
                    title, link, descr = (item.title, item.link, item.descr_plain)
                    
                    if not descr or (descr == title):
                        body = body + ('%s\n%s\n\n' % (title, link))
                    else:
                        body = body + ('%s\n%s\n%s\n\n' % (title, link,
                                                           descr[:user.get_size_limit()]))
                except ValueError:
                    print 'trying to unpack tuple of wrong size', repr(item)

            if message_type == 0:
                mt = jabIConstMessage.mtNormal
            else:
                mt = jabIConstMessage.mtChat
            message = jab_session.createMessage(user.jid(), body, mt)
            message.setSubject(channel_info.title)
            jab_session.sendPacket(message)
        elif message_type == 1:
            if not not_stored and (len(items) > user.get_store_messages()):
                message = jab_session.createMessage(user.jid(),
                                                    '%d headlines suppressed' % (len(items) - user.get_store_messages(),),
                                                    jabIConstMessage.mtHeadline)
                message.setSubject(channel_info.title)
                message.queryInterface(jabIPacket)
                oob_ext = message.addExtension('oob')
                oob_url = oob_ext.addElement('url')
                oob_url.addCDATA(channel_info.link)
                oob_desc = oob_ext.addElement('desc')
                oob_desc.addCDATA(channel_info.descr)

                jab_session.sendPacket(message)

                items = items[-user.get_store_messages():]

            for item in items:
                try:
                    title, link = (item.title, item.link)

                    if item.descr_plain:
                        description = item.descr_plain
                    else:
                        description = title

                    message = jab_session.createMessage(user.jid(),
                                                        description[:user.get_size_limit()],
                                                        jabIConstMessage.mtHeadline)
                    message.setSubject(channel_info.title)
                    message.queryInterface(jabIPacket)
                    oob_ext = message.addExtension('oob')
                    oob_url = oob_ext.addElement('url')
                    oob_url.addCDATA(link)
                    oob_desc = oob_ext.addElement('desc')
                    oob_desc.addCDATA(title)

                    jab_session.sendPacket(message)
                except ValueError:
                    print 'trying to unpack tuple of wrong size', repr(item)


    def schedule_update(self, resource):
        self._update_queue_cond.acquire()
        next_update = resource.next_update()
        print 'scheduling', resource.url(), time.asctime(time.localtime(next_update))

        bisect.insort(self._update_queue, (next_update, resource))
        if self._update_queue[0] == (next_update, resource):
            self._update_queue_cond.notifyAll()

        self._update_queue_cond.release()


    def run(self, jab_session_proxy):
        try:
            time.sleep(20)
            print 'starting RSS/RDF updater'
            db = get_db()
            res_db = RSS_Resource_db()

            self._update_queue_cond.acquire()
            while not self._shutdown:
                if self._update_queue:
                    timeout = self._update_queue[0][0] - int(time.time())

                    if timeout > 3:
                        if timeout > 300:
                            print 'updater waiting for %d seconds' % (timeout,)
                        self._update_queue_cond.wait(timeout)
                    else:
                        resource = self._update_queue[0][1]
                        del self._update_queue[0]

                        self._update_queue_cond.release()
                        self._update_resource(resource, jab_session_proxy, db, res_db)
                        self._update_queue_cond.acquire()
                else:
                    print 'updater queue empty...'
                    self._update_queue_cond.wait()

            self._update_queue_cond.release()
        except:
            print 'updater thread caught exception...'
            traceback.print_exc(file=sys.stdout)
            sys.exit(1)

        print 'updater shutting down...'
        if self._shutdown:
            self._shutdown += 1


    def _update_resource(self, resource, jab_session_proxy, db, res_db=None):
        redirect_url, redirect_seq = resource.redirect_info()
        if redirect_url != None:
            return

        cursor = db.cursor()
        db_txn_end = None
        redirect_resource = None
        redirects = []

        resource.lock(); need_unlock = True
        try:
            uids = storage.get_resource_uids(resource, cursor)

            storage.users_lock()
            try:
                used = False
                for uid in uids:
                    try:
                        user = storage.get_user_by_id(uid)
                        used = True
                    except KeyError:
                        pass

                if not used:
                    storage.evict_resource(resource)
            finally:
                storage.users_unlock()

            if used:
                resource.unlock(); need_unlock = False
                try:
                    print time.asctime(), 'updating', resource.url()
                    new_items, next_item_id, redirect_resource, redirect_seq, redirects = resource.update(res_db)

                    if len(new_items) > 0:
                        need_unlock = True

                    if len(new_items) > 0 or redirect_resource != None:
                        deliver_users = []
                        uids = storage.get_resource_uids(resource, cursor)
                        cursor.execute('BEGIN')
                        db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))
                        for uid in uids:
                            try:
                                user = storage.get_user_by_id(uid)

                                if redirect_resource != None:
                                    try:
                                        user.add_resource(redirect_resource,
                                                          redirect_seq,
                                                          cursor)
                                    except ValueError:
                                        pass

                                if len(new_items) and user.get_delivery_state():
                                    if redirect_resource == None:
                                        user.update_headline(resource,
                                                             next_item_id,
                                                             new_items, cursor)
                                    else:
                                        user.remove_resource(resource, cursor)

                                    deliver_users.append(user)

                                elif len(new_items) == 0:
                                    user.remove_resource(resource, cursor)

                            except KeyError:
                                # just means that the user is no longer online
                                pass

                        # we need to unlock the resource here to
                        # prevent deadlock (the main thread, which is
                        # needed for sending, might be blocked waiting
                        # to acquire resource)
                        db_txn_end = None
                        if need_unlock:
                            resource.unlock(); need_unlock = False

                        for user in deliver_users:
                            self._send_headlines(jab_session_proxy, user,
                                                 resource, new_items, True)
                except:
                    print 'exception caught updating', resource.url()
                    traceback.print_exc(file=sys.stdout)

                if need_unlock:
                    resource.unlock(); need_unlock = False
                if redirect_resource == None:
                    self.schedule_update(resource)
        finally:
            db_txn_end = None
            if need_unlock:
                resource.unlock(); need_unlock = False

        for resource, new_items, next_item_id in redirects:
            deliver_users = []

            cursor.execute('BEGIN')
            db_txn_end = Resource_Guard(lambda cursor=cursor: cursor.execute('END'))
            resource.lock(); need_unlock = True
            try:
                print 'processing updated resource', resource.url()
                uids = storage.get_resource_uids(resource, cursor)
                for uid in uids:
                    try:
                        user = storage.get_user_by_id(uid)

                        if user.get_delivery_state():
                            headline_id = user.headline_id(resource, cursor)
                            if headline_id < next_item_id:
                                user.update_headline(resource,
                                                     next_item_id,
                                                     new_items, cursor)

                                deliver_users.append(user)
                    except KeyError:
                        # just means that the user is no longer online
                        pass

            finally:
                db_txn_end = None
                if need_unlock:
                    resource.unlock(); need_unlock = False

            for user in deliver_users:
                self._send_headlines(jab_session_proxy, user,
                                     resource, new_items, True)


# register event handlers
event_handler = JabberSessionEventHandler(jab_session)

jab_session.connectEvtConnected(event_handler)
jab_session.connectEvtDisconnected(event_handler)
jab_session.connectEvtAuthError(event_handler)
jab_session.connectEvtIq(event_handler)
jab_session.connectEvtMessage(event_handler)
jab_session.connectEvtUnknownPacket(event_handler)
jab_session.connectEvtIqVersion(event_handler)
jab_session.connectEvtIqLast(event_handler)
jab_session.connectEvtPresence(event_handler)
jab_session.connectEvtPresenceRequest(event_handler)

jab_session_input = proxy_object_manager.getProxyForObject(event_queue, xpcom.components.interfaces.jabIDataStream, jab_session.inputStream, 5)


def wait_and_reconnect(jab_session, event_queue, timespan):
    while 1:
        print 'waiting for next connection attempt in', timespan, 'seconds'
        
        time.sleep(timespan)

        if timespan < 300:
            timespan = 2*timespan + 30

        jab_session_input = proxy_object_manager.getProxyForObject(event_queue, xpcom.components.interfaces.jabIDataStream, jab_session.inputStream, 5)

        tcp_stream = xpcom.components.classes[TCPSTREAM_CONTRACTID].createInstance(xpcom.components.interfaces.jabIDataStream)
        tcp_stream.queryInterface(xpcom.components.interfaces.jabIStreamClientConnector)
        tcp_stream.queryInterface(xpcom.components.interfaces.jabIStreamOutputConnector)

        if socks_proxy:
            proxy_stream = xpcom.components.classes[SOCKSPROXYSTREAM_CONTRACTID].createInstance(xpcom.components.interfaces.jabIDataStream)
        elif https_proxy:
            proxy_stream = xpcom.components.classes[HTTPPROXYSTREAM_CONTRACTID].createInstance(xpcom.components.interfaces.jabIDataStream)
        else:
            proxy_stream = None

        print 'attempting TCP connect'
        if proxy_stream:
            proxy_stream.queryInterface(xpcom.components.interfaces.jabIStreamClientConnector)
            proxy_stream.queryInterface(xpcom.components.interfaces.jabIStreamChainConnector)
            proxy_stream.queryInterface(xpcom.components.interfaces.jabIStreamOutputConnector)

            proxy_stream.connect_client(jab_session_input)
            proxy_stream.chain(tcp_stream)

            if socks_proxy:
                rc = tcp_stream.connect_output(socks_proxy, None)
            else:
                rc = tcp_stream.connect_output(https_proxy, None)

            if not rc:
                rc = proxy_stream.connect_output(JABBER_HOST, None)
        else:
            tcp_stream.connect_client(jab_session_input)
            rc = tcp_stream.connect_output(JABBER_HOST, None)

        if not rc:
            jab_session.outputStream = tcp_stream

            print 'establishing Jabber session...'
            event_handler._connected = -1
            jab_session.connect(JABBER_SERVER, jabISession.atAutoAuth,
                                JABBER_USER, 'jabxpcom', JABBER_PASSWORD, 0)
            return

def console_handler(jab_session_proxy):
    try:
        while 1:
            s = raw_input()
    except EOFError:
        pass

    # initiate a clean shutdown
    print 'JabRSS shutting down...'
    event_handler._shutdown = 1

    jab_session_proxy.disconnect()
    event_handler._update_queue_cond.acquire()
    event_handler._update_queue_cond.notifyAll()
    event_handler._update_queue_cond.release()

    while event_handler._connected or (event_handler._shutdown < 2):
        time.sleep(1)

    print 'shutting down event loop'
    main_thread.interrupt()


wait_and_reconnect(jab_session, event_queue, 0)

jab_session_proxy = proxy_object_manager.getProxyForObject(event_queue, xpcom.components.interfaces.jabISession, jab_session, 5)
thread.start_new_thread(event_handler.run, (jab_session_proxy,))

thread.start_new_thread(console_handler, (jab_session_proxy,))


event_queue.eventLoop()


print 'JabRSS shutdown complete'
