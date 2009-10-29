#!/usr/bin/env python
# Copyright Christopher Zorn (tofu@thetofu.com) See LICENSE
import sys
from twisted.internet import reactor

from zope.interface import implements
from twisted.internet import defer
from twisted.words.protocols.jabber import (
    xmlstream, sasl, client as jclient, sasl_mechanisms, jid)
from twisted.python import log
from wokkel.xmppim  import MessageProtocol
from wokkel import client

import httpb_client

VERSION = 0.1

## override internal stuff so that we can get sasl anonymous
class Anonymous(object):
    implements(sasl_mechanisms.ISASLMechanism)
    name = 'ANONYMOUS'
    
    def getInitialResponse(self):
        return None


class SASLInitiatingInitializer(sasl.SASLInitiatingInitializer):
    def setMechanism(self):
        jid = self.xmlstream.authenticator.jid
        password = self.xmlstream.authenticator.password

        mechanisms = sasl.get_mechanisms(self.xmlstream)

        if jid.user is not None:
            if 'DIGEST-MD5' in mechanisms:
                self.mechanism = sasl_mechanisms.DigestMD5('xmpp',
                                                           jid.host,
                                                           None,
                                                           jid.user,
                                                           password)
            elif 'PLAIN' in machanisms:
                self.mechanism = sasl_mechanisms.Plain(None, jid.user, 
                                                       password)
            else:
                raise sasl.SASLNoAcceptableMechanism()
        else:
            if 'ANONYMOUS' in mechanisms:
                self.mechanism = Anonymous()
            else:
                raise sasl.SASLNoAccetableMechanism()


class XMPPAuthenticator(jclient.XMPPAuthenticator):
    def associateWithStream(self, xs):
        xmlstream.ConnectAuthenticator.associateWithStream(self, xs)

        xs.initializers = [jclient.CheckVersionInitializer(xs)]
        inits = [(xmlstream.TLSInitiatingInitializer, False),
                 (SASLInitiatingInitializer, True),
                 (jclient.BindInitializer, False),
                 (jclient.SessionInitializer, False),
                 ]

        for initClass, required in inits:
            init = initClass(xs)
            init.required = required
            xs.initializers.append(init)


class ClientFactory(client.DeferredClientFactory):
    def __init__(self, jid, password):
        self.authenticator = XMPPAuthenticator(jid, password)
        client.DeferredClientFactory.__init__(self, jid, password)

    def buildProtocol(self, addr):
        xs = self.protocol(self.authenticator)
        xs.factory = self
        self.installBootstraps(xs)
        return xs


class BOSHClientFactory(ClientFactory):
    protocol = httpb_client.HTTPBindingStream


def boshClientCreator(url, factory):
    proxy = httpb_client.Proxy(url)
    xs = factory.buildProtocol(proxy.host)
    xs.proxy = proxy
    xs.connectionMade()
    return factory.deferred


@defer.inlineCallbacks
def createClient(bosh, domain, debug):
    if bosh:
        factory = BOSHClientFactory(jid.internJID(domain), None)
    else:
        factory = ClientFactory(jid.internJID(domain), None)
    factory.streamManager.logTraffic = debug

    protocol = MessageProtocol()
    protocol.setHandlerParent(factory.streamManager)

    if bosh:
        yield boshClientCreator(bosh, factory)
    else:
        yield client.clientCreator(factory)
        



if __name__ == '__main__':

    from optparse import OptionParser
    parser = OptionParser(usage='%prog [options] server', version=VERSION)


    parser.add_option('-b', '--bosh', action='store', dest='bosh',
                      help='BOSH url for using BOSH instead of direct. \n Example: "http://xmpp.stanziq.com:5280/xmpp-httpbind"')
    
    parser.add_option('-d', '--debug', action='store', dest='debug',
                      help='Show debug information.')

    ## set default values
    parser.set_defaults(bosh=None) # default is raw
    parser.set_defaults(server="localhost")
    parser.set_defaults(debug=False)

    options, args = parser.parse_args()
    if len(args) == 0:
        parser.print_help()
        sys.exit(0)
    options.server = args[0]
        
    log.startLogging(sys.stdout)
    reactor.callWhenRunning(createClient,
                            options.bosh,
                            options.server,
                            options.debug)
    reactor.run()
