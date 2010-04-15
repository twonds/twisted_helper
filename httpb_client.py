# Copyright Christopher Zorn (tofu@thetofu.com) See LICENSE
from twisted.internet import defer, protocol, reactor, stdio
from twisted.python import log, reflect
try:
    from twisted.words.xish import domish, utility
except:
    from twisted.xish import domish, utility
from twisted.web import http

from twisted.words.protocols.jabber import xmlstream, client, jid

from twisted.protocols import basic
import urlparse
import random, binascii, base64, md5, sha, time, os, random

import os, sys
import time

from wokkel.generic import parseXml

TLS_XMLNS = 'urn:ietf:params:xml:ns:xmpp-tls'
SASL_XMLNS = 'urn:ietf:params:xml:ns:xmpp-sasl'
BIND_XMLNS = 'urn:ietf:params:xml:ns:xmpp-bind'
SESSION_XMLNS = 'urn:ietf:params:xml:ns:xmpp-session'

NS_HTTP_BIND = "http://jabber.org/protocol/httpbind"

class Error(Exception):
    stanza_error = ''
    punjab_error = ''
    msg          = ''
    def __init__(self,msg = None):
        self.stanza_error = msg
        self.punjab_error = msg
        self.msg          = msg
        
    def __str__(self):
        return self.stanza_error
    

class RemoteConnectionFailed(Error):
    msg = 'remote-connection-failed'
    stanza_error = 'remote-connection-failed'
    
    
class NodeNotFound(Error):
    msg = '404 not found'

class NotAuthorized(Error):
    pass

class NotImplemented(Error):
    pass


class XMPPAuthenticator(client.XMPPAuthenticator):
    """
    Authenticate against an xmpp server using BOSH
    """

class QueryProtocol(http.HTTPClient):
    noisy = False
    def connectionMade(self):
        self.factory.sendConnected(self)
        self.sendBody(self.factory.cb, cookie=self.factory.cookie)

    def sendCommand(self, command, path):
        self.transport.write('%s %s HTTP/1.0\r\n' % (command, path))
            
    def sendBody(self, b, close = 0, cookie=None):
        self.sendCommand('POST', self.factory.url)
        bxml = b.toXml().encode('utf-8')
        if cookie:
            self.sendHeader("Cookie", cookie)
        self.sendHeader('User-Agent', 'Twisted/XEP-0124')
        self.sendHeader('Host', self.factory.host)
        self.sendHeader('Content-type', 'text/xml')
        self.sendHeader('Content-length', str(len(bxml)))
        self.endHeaders()
        self.transport.write(bxml)


    def handleHeader(self, key, value):
        if key.lower() == 'set-cookie':
            if self.noisy:
                log.msg('====================== handle cookie =================')
                log.msg(getattr(self.factory, 'cookie', None))
            srv, info = value.split(";",1)
            self.factory.cookie = srv


    def handleStatus(self, version, status, message):
        if status != '200':
            self.factory.badStatus(status, message)

    def handleResponse(self, contents):
        self.factory.parseResponse(contents, self)

    def lineReceived(self, line):
        if self.firstLine:
            self.firstLine = 0
            l = line.split(None, 2)
            version = l[0]
            status = l[1]
            try:
                message = l[2]
            except IndexError:
                # sometimes there is no message
                message = ""
            self.handleStatus(version, status, message)
            return
        if line:
            key, val = line.split(':', 1)
            val = val.lstrip()
            self.handleHeader(key, val)
            if key.lower() == 'content-length':
                self.length = int(val)
        else:
            self.__buffer = []
            self.handleEndHeaders()
            self.setRawMode()

    def handleResponseEnd(self):
        self.firstLine = 1
        if self.__buffer != None:
            b = ''.join(self.__buffer)
            self.__buffer = None
            self.handleResponse(b)

    def handleResponsePart(self, data):
        self.__buffer.append(data)

    def connectionLost(self, reason):
        pass


class QueryFactory(protocol.ClientFactory):
    """ a factory to create http client connections.
    """
    deferred = None
    noisy = False
    protocol = QueryProtocol
    cookie = None

    def __init__(self, url, host, b):
        self.url, self.host = url, host
        self.deferred = defer.Deferred()
        self.cb = b

    def send(self, b):
        self.deferred = defer.Deferred()
        self.client.sendBody(b, cookie=self.cookie)
        
        return self.deferred

    def parseResponse(self, contents, protocol):
        self.client = protocol

        try:
            element = parseXml(contents)
            body_tag = element
            elements = element.children
        except Exception, ex:
            log.err(str(ex))
            raise
        else:
            if type('') == type(body_tag):
                return defer.fail((body_tag))

            if body_tag.hasAttribute('type') and body_tag['type'] == 'terminate':
                if self.deferred.called:
                    return defer.fail((body_tag,elements))
                else:            
                    self.deferred.errback((body_tag,elements))
                return
            if self.deferred.called:
                return defer.succeed((body_tag,elements))
            else:
                self.deferred.callback((body_tag,elements))

    def sendConnected(self, q):
        self.q = q
        
    
    def clientConnectionLost(self, _, reason):
        try:
            self.client = None
            if not self.deferred.called:
                self.deferred.errback(reason)
                
        except:
            return reason
        
    clientConnectionFailed = clientConnectionLost

    def badStatus(self, status, message):
        if not self.deferred.called:
            self.deferred.errback(ValueError(status, message))
            


import random, sha, md5

class Keys:
    """ A class to generate keys for BOSH """
    def __init__(self):
        self.set_keys()
        
        
    def set_keys(self):
        seed = random.randint(30,1000000)
        self.num_keys = random.randint(55,255)
        self.k = []
        self.k.append(seed)
        for i in range(self.num_keys-1):
            x = i + 1
            self.k.append(sha.new(str(self.k[x-1])).hexdigest())

        self.key_index = self.num_keys - 1
    
    def getKey(self):
        self.key_index = self.key_index - 1
        return self.k.pop(self.key_index)

    def firstKey(self):
        if self.key_index == self.num_keys - 1:
            return 1
        else:
            return 0

    def lastKey(self):
        if self.key_index == 0:
            return 1
        else:
            return 0


class Proxy:
    """A Proxy for making BOSH calls.

    Pass the URL of the remote BOSH server to the constructor.

    """
    cookie = None
    def __init__(self, url):
        """
        Parse the given url and find the host and port to connect to.
        """
        parts = urlparse.urlparse(url)
        self.url = urlparse.urlunparse(('', '')+parts[2:])
        if self.url == "":
            self.url = "/"
        if ':' in parts[1]:
            self.host, self.port = parts[1].split(':')
            self.port = int(self.port)
        else:
            self.host, self.port = parts[1], None
        self.secure = parts[0] == 'https'
        

    def connect(self, b):        
        """
        Make a connection to the web server and send along the data.
        """

        self.factory = QueryFactory(self.url, self.host, b)
        self.factory.cookie = self.cookie
        if self.secure:
            from twisted.internet import ssl
            reactor.connectSSL(self.host, self.port or 443,
                               self.factory, ssl.ClientContextFactory())
        else:
            reactor.connectTCP(self.host, self.port or 80, self.factory)


        return self.factory.deferred


    def send(self, b, cookie=None):
        """ Send data to the web server. """
        if cookie:
            self.cookie = cookie
        # if keepalive is off we need a new query factory
        # TODO - put a check to reuse the factory, right now we open a new one.
        d = self.connect(b)
        return d

class HTTPBClientConnector:
    """
    BOSH client connector. 

    @ivar url: The BOSH endpoint
    @type url: C{str}

    """
    def __init__(self, url):
        self.url = url
        

    def connect(self, factory):
        self.proxy = Proxy(self.url)
        self.xs = factory.buildProtocol(self.proxy.host)
        self.xs.proxy = self.proxy
        self.xs.connectionMade()


    def disconnect(self):
        self.xs.connectionLost('disconnect')
        self.xs = None

        
class HTTPBindingStream(xmlstream.XmlStream):
    """
    BOSH wrapper that acts like L{xmlstream.XmlStream}

    """

    window = 5
    hold   = 1

    def __init__(self, authenticator):
        xmlstream.XmlStream.__init__(self, authenticator)
        self.base_url = '/xmpp-httpbind/'
        self.host = 'stanziq.com'
        self.mechanism = 'ANONYMOUS'
        # request id
        self.rid = random.randint(0, 10000000)
        # session id
        self.session_id = 0
        # keys
        self.keys = Keys()
        self.initialized = False
        self.requests = []
        self.recieved_features = False
        self.auth_sent = False
        self.cookie = None
        self.send_queue = []

    def _cbConnect(self, result):
        r,e = result
        ms = ''
        self.cookie = self.proxy.factory.cookie
        self.stream_reset = False
        self.session_id = r['sid']
        self.authid = r['authid']
        self.namespace = self.authenticator.namespace
        self.otherHost = self.authenticator.otherHost
        self.dispatch(self, xmlstream.STREAM_START_EVENT)
        # Setup observer for stream errors
        self.addOnetimeObserver("/error[@xmlns='%s']" % xmlstream.NS_STREAMS,
                                self.onStreamError)
        stream_started = True
        self.initialized = True

        try:
            if len(e)>0 and e[0].name == 'features':
                self.recieved_features = True

                features = {}
                for feature in e[0].children:
                    features[(feature.uri, feature.name)] = feature


                self.authenticator.xmlstream.features = features
                
                self.authenticator.initializeStream()

                stream_started = False
            
        except Exception, ex:
            stream_started = False
            raise ex
        
        if stream_started:
        
            r['version'] = r['ver']
            self.authenticator.streamStarted(r)
            self.send()
            stream_started = False
            
    def _ebError(self, e):
        log.err(e)
        log.err(str(e))
        log.err(e.getErrorMessage())
        
        #raise e
        
    def _cbReset(self, result):
        r, e = result
        
        if len(e)>0 and e[0].name == 'features':
            self.recieved_features = True
            
            features = {}
            for feature in e[0].children:
                features[(feature.uri, feature.name)] = feature


            self.authenticator.xmlstream.features = features
            
            self.authenticator.initializeStream()

        self.stream_reset = True
            

    def _initializeStream(self):
        """ Initialize binding session.
        
        Just need to create a session once, this can be done elsewhere, but here will do for now.
        """
        b = domish.Element((NS_HTTP_BIND, 'body'))
        
        b['content']  = 'text/xml; charset=utf-8'
        
        b['rid']      = str(self.rid)
        b['to']       = self.authenticator.jid.host

        b['xml:lang'] = 'en'

        b['xmlns:xmpp'] = 'urn:xmpp:xbosh'
        b['xmpp:restart'] = 'true'

        if not self.initialized:
            b['hold']     = str(self.hold)
            b['wait']     = '60'
            b['xmpp:version'] = '1.0'
            b['ver'] = '1.6'
            b['window'] = str(self.window)
            # FIXME - there is an issue with the keys
            # b = self.key(b)

            d = self.proxy.connect(b)
            d.addCallback(self._cbConnect)
        else:
            self.rid = self.rid + 1
            b['rid']      = str(self.rid)
            b['sid']      = str(self.session_id)
            d = self.proxy.connect(b)
            d.addCallback(self._cbReset)

        d.addErrback(self._ebError)
        
        return d


    def key(self,b):
        if self.keys.lastKey():
            self.keys.setKeys()
        
        if self.keys.firstKey():
            b['newkey'] = self.keys.getKey()
        else:
            b['key'] = self.keys.getKey()
        return b

    def _cbSend(self, result, rid):
        body, elements = result
        self.requests.pop(0)
        self.window += 1
        if body.hasAttribute('type') and body['type'] == 'terminate':
            reactor.close()
        for e in elements:
            if self.rawDataInFn:
                try:
                    self.rawDataInFn(e.toXml())
                except:
                    pass
            if e.name == 'features':
                #self.onFeatures(e)

                features = {}
                for feature in e.children:
                    features[(feature.uri, feature.name)] = feature


                self.authenticator.xmlstream.features = features
                
                self.authenticator.initializeStream()
                
                self.recieved_features = False
            else:
                self.onElement(e)

        # if no elements lets send out another poll
        if len(self.requests)==0:
            self.send()
           
    def send(self, obj = None):
        objs = self.send_queue
        objs.append(obj)
        if self.session_id == 0:
            return defer.succeed(False)
        if self.window > self.hold+1:
            self.window = self.window - 1
            self.send_queue = []
        else:
            # append objects to send later
            self.send_queue.append(obj)
            return defer.succeed(False)
        provided = domish.IElement.providedBy(obj)
        if not self.stream_reset and not provided:
            return defer.succeed(False)
        b = domish.Element((NS_HTTP_BIND,"body"))
        b['content']  = 'text/xml; charset=utf-8'
        self.rid = self.rid + 1
        b['rid']      = str(self.rid)
        b['sid']      = str(self.session_id)
        b['xml:lang'] = 'en'
        b['xmlns:xmpp'] = 'urn:xmpp:xbosh'
        for obj in objs:
            if obj is not None:            
                provided = domish.IElement.providedBy(obj)
                if provided:
                    if self.rawDataOutFn:
                        self.rawDataOutFn(str(obj.toXml()))
                    b.addChild(obj)
        #b = self.key(b)
        
        self.requests.append(b)
        d = self.proxy.send(b, self.cookie)        
        d.addCallback(self._cbSend, b['rid'])
        return d


class HTTPBindingStreamFactory(xmlstream.XmlStreamFactory):
    """
    Factory for HTTPBindingStream protocol objects.
    """

    def buildProtocol(self, _):
        self.resetDelay()
        xs = HTTPBindingStream(self.authenticator)
        xs.factory = self
        for event, fn in self.bootstraps: xs.addObserver(event, fn)
        return xs
        
