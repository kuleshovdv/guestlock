#!/usr/bin/env python
# -*- coding:utf-8 -*-
from twisted.protocols import basic
from twisted.web import soap, server
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory 
from twisted.protocols.basic import LineOnlyReceiver
from twisted.application import service, internet
from twisted.internet import task
import hashlib 
import hmac
import MySQLdb
from MySQLdb import Error
import random
import time
from fastjsonrpc.server import JSONRPCServer
import ConfigParser

allowCommands = ("OPEN", "ACTIVATE", "DEACTIVATE")
statusRequest = ("DOOR", "STATUS")
allowAnswers = ('OK', 'NO', 'ACTIVE', 'NOTACTIVE', 'OPEN', 'CLOSE', 'EXIT')

def getPassword(passLen):
    str1 = '123456789'
    str2 = 'qwertyuiopasdfghjklzxcvbnm'
    str3 = str2.upper()
    str4 = str1+str2+str3
    ls = list(str4)
    random.shuffle(ls)
    return ''.join([random.choice(ls) for x in range(passLen)])


class CommandProtocol(LineOnlyReceiver): 
    name = ""
    isKey = False
    Validated = False
    authKey = ""
    lastActivity = time.time()
    requestValidate = time.time()
    lastComandTime = 0
    sequrityRequest = None
    answer = None
    
    def getSecret(self):
        try:
            self.factory.conn.ping(True)
            cursor = self.factory.conn.cursor()
            cursor.execute("SELECT `Secret` FROM `devices` WHERE deviceID='" + self.getName() + "'")
            rows = cursor.fetchall()
                        
            if cursor.rowcount > 0:
                cursor.close()
                return rows[0][0].strip() 
            else:
                cursor.close()
                return None
            
        except Error as e:
            print(e)
            return None

        finally:
            cursor.close()
            
    def getRole(self):
        try:
            self.factory.conn.ping(True)
            cursor = self.factory.conn.cursor()
            cursor.execute("SELECT `Role` FROM `devices` WHERE deviceID='" + self.getName() + "'")
            rows = cursor.fetchall()
                        
            if cursor.rowcount > 0:
                cursor.close()
                return rows[0][0].strip().upper() 
            else:
                cursor.close()
                return None
            
        except Error as e:
            print(e)
            return None

        finally:
            cursor.close()
        
            
    def validKey(self,lockID):
        if not self.isKey:
            return False
        if self.transport.getPeer().host == "127.0.0.1":
            return True
        
        try:
            self.factory.conn.ping(True)
            cursor = self.factory.conn.cursor()
            cursor.execute("SELECT `rights` FROM `hosts` WHERE (`lock`='" + lockID + "') AND (`lockkey`='"+ self.getName() + "')")
            rows = cursor.fetchall()
            
            if cursor.rowcount > 0:
                cursor.close()
                return rows[0][0]
            else:
                cursor.close()
                return False
        except Error as e:
            print(e)
            return False

        finally:
            cursor.close()
            
    def validGuest(self, guestID):
#        timeStamp = str(long(time.time() / 30))
        if self.isKey or (not self.Validated):
            return False
        try:
            self.factory.conn.ping(True)
            cursor = self.factory.conn.cursor()
            cursor.execute('''
                            SELECT `hash` FROM `guests` 
                            WHERE 
                            (`ValidFrom` <= NOW()) AND (`ValidTo` >= NOW())
                            AND (`Lock` = '%s')
                            AND (`guestID` = '%s')
                            ''' 
                            % (self.getName(),guestID)) 
            
            rows = cursor.fetchall()
            cursor.close()
            if len(rows):
                return rows[0][0]
            else:
                return False 
            
        except Error as e:
            print(e)
            return False

    def getName(self): 
        if self.name!="": 
            return self.name 
        return self.transport.getPeer().host 

    def connectionMade(self): 
        print "New connection from "+self.getName()
        if self.transport.getPeer().host == "127.0.0.1":
            self.isKey = True 
            self.Validated = True
        d = {self.getName() : self}
        self.factory.clients.update(d)
        self.sendLine("GUESTLOCK SERVER v0.2")
        reactor.callLater(5, factory.chekAuth, self)

    def connectionLost(self, reason): 
        print "Lost connection from "+self.getName() 
        self.factory.clients.pop(self.getName()) 
        #self.factory.sendMessageToAllclients(self.getName()+" has disconnected.") 
        

    def lineReceived(self, line):
        print "<" + line 
        #cmndStr = line.upper()
        
        if len(line) == 0:
            return
        
        if line[0] == '/':
            cmnd = line[1:].split(":")
            cmnd[0] = cmnd[0].upper()
        else:
            return
        
        #print cmnd
        
        self.lastActivity = time.time()
        #print self.getName()+" said "+line
        #if line[:3] == "/OK"
        if cmnd[0] in ("KEY", "ID"):
            if len(cmnd) == 2:
                if cmnd[1].strip() in self.factory.clients.keys():
                    self.sendLine("This Device ID %s already online" % cmnd[1])
                    print cmnd[1] + " already online"
                else: 
                    oldName = self.getName() 
                    self.name = cmnd[1].strip() 
                    self.factory.clients.pop(oldName)
                    self.factory.clients.update({self.getName() : self})
                    print oldName+" changed ID to "+self.getName() 
                    self.authKey = getPassword(12)
                    self.sendLine("ANSW:"+self.authKey)
                    self.isKey = False
                    self.Validated = False
                    self.requestValidate = time.time()
                    print self.getName() +" has requested validation: " + self.authKey
                    reactor.callLater(5, factory.chekAuth, self)
        elif cmnd[0]=="EXIT": 
            self.transport.loseConnection()
        elif cmnd[0]=="ANSW":
            secret = self.getSecret() 
            if secret:
                self.Validated = (hmac.new(key=secret, msg=self.authKey, digestmod=hashlib.sha1).hexdigest() == cmnd[1].strip())
                if self.Validated:
                    self.isKey = (self.getRole() == "KEY")
                    if self.isKey:
                        print self.getName() + " has authorizated as Key"
                    else:
                        print self.getName() + " has authorizated as Lock"
                else:
                    self.sendLine("Authorization fail:Wrong answer")
                    print "Wrong authorization by " + self.getName() + " secret: " + secret
                    print "Auth code: " + self.authKey
                    print "Waiting hash: " + hmac.new(key=secret, msg=self.authKey, digestmod=hashlib.sha1).hexdigest()
                    print "Answer hash: " + cmnd[1].strip()
                    self.transport.loseConnection()             
            else:
                self.sendLine("Authorization fail:This ID %s in not in Keys list" % self.getName())
                self.transport.loseConnection()
                
        if self.isKey: #Only from keys
            if (cmnd[0] in allowCommands + statusRequest) & (len(cmnd) > 1):
                adresat = self.factory.clients.get(cmnd[1],None)
                if adresat:
                    adresat.sendLine(cmnd[0] + ":" + self.getName())
                    if cmnd[0] in allowCommands:
                        adresat.lastComandTime = time.time()
                else:
                    self.sendLine("OFFLINE:"+ cmnd[1])

        else: # Only from locks
            if cmnd[0]=="RE":
                if len(cmnd) >= 3:
                    cursor = self.factory.conn.cursor()
                    cursor.execute("""
                    UPDATE commandlog SET sessionkey='%s' WHERE id=%s
                    """ % (cmnd[1], cmnd[2]))
                    self.factory.conn.commit()
                    cursor.close()

#            elif cmnd[0]=="PONG":
#                print self.getName() + " still online"
            elif cmnd[0]=="GUEST":
                if len(cmnd) > 1:
                    print line
                    guestHash = self.validGuest(cmnd[1])
                    if guestHash: 
                        self.sendLine("GUEST:%s" % guestHash)
                        self.lastComandTime = time.time()
                        print "Guest ID: " + cmnd[1] + " has opened Lock ID: " + self.getName() 
                    else:
                        #self.sendLine("GUEST")
                        print "Incorrect guest: " + cmnd[1] + " for access to Lock ID: " + self.getName()
                    
            else: 
                if (cmnd[0] in allowAnswers) & (len(cmnd) > 1):
                    cursor = self.factory.conn.cursor()
                    cursor.execute("""
                    UPDATE commandlog SET result='%s' WHERE id=%s
                    """ % (cmnd[0],cmnd[1]))
                    self.factory.conn.commit()
                    cursor.close()
                            
    def sendLine(self, line): 
        print ">" + line
        self.transport.write(line+"\r\n") 
        
        

class CommandProtocolFactory(ServerFactory): 

    protocol = CommandProtocol 
    clients = {} 
    
    def mySQLdbConnect(self):
        try:
            self.conn = MySQLdb.connect(host=settings.get('MySQL', 'host'),
                                        user=settings.get('MySQL', 'user'),
                                        passwd=settings.get('MySQL', 'passwd'),
                                        db=settings.get('MySQL', 'db'))
        except Error as e:
            print(e)
            return False
        else:
            print "MySLQ connection success"
            return True
            
    def __init__(self):
        self.clients = {}
        if self.mySQLdbConnect():
            print "Server ready!"
        else:
            print "Data base error. Server doesn't work correctly."
            
            
    def chekAuth(self, clietObject):
        if not clietObject.Validated:
            print "Client ID: %s did not finish authentication on time" % clietObject.getName() 
            clietObject.transport.loseConnection()
            cursor = self.conn.cursor()
            cursor.execute("""
            INSERT INTO bancandidates (ipAddress,rate) VALUES (INET_ATON('%s'),1)
            ON DUPLICATE KEY UPDATE rate=rate+1
            """ % clietObject.transport.getPeer().host)
            self.conn.commit()
            cursor.close()
            

    def sendMessageToAllclients(self, mesg): 
        for client in self.clients.values():
            client.sendLine(mesg)
            
    def lockPinger(self):
        #print "Ping!"
        self.conn.ping(True)
        for client in self.clients.values():
            if (time.time() - client.lastActivity > 120):
                    print "Device ID: %s has disconnecting by timeout" % client.getName()
                    client.transport.loseConnection()
            client.sendLine("PING")
        


def sendCommand(lockID, command, clientIP):
    cursor = factory.conn.cursor()
    cursor.execute("""
    INSERT INTO commandlog (lockid, command, ip) VALUES ('%s','%s', INET_ATON('%s'))
    """ % (lockID, command, clientIP))
    commandID = cursor.lastrowid
    adresat = factory.clients.get(lockID,None)
    if adresat:
        adresat.sendLine(command + ":" + str(commandID))
    else:
        cursor.execute("""
        UPDATE commandlog SET result='OFFLINE' WHERE id=%s
        """ % commandID)
    factory.conn.commit()
    cursor.close()
    return commandID

def confirmCode(lockID, codeAnswer):
    adresat = factory.clients.get(str(lockID),None)
    if adresat:
        adresat.sendLine("AUTH:" + str(codeAnswer))
        return True
    else:
        return False
    
def getSessionKey(commandID):
    cursor = factory.conn.cursor()
    cursor.execute("""
    SELECT sessionkey FROM commandlog WHERE id=%s
    """ % commandID)
    if cursor.rowcount > 0:
        rows = cursor.fetchall()
        key = rows[0][0]
    else:
        key = None
    cursor.close()        
    return key
    
def getResult(commandID):
    cursor = factory.conn.cursor()
    cursor.execute("""
    SELECT result FROM commandlog WHERE id=%s
    """ % commandID)
    if cursor.rowcount > 0:
        rows = cursor.fetchall()
        key = rows[0][0]
    else:
        key = None
    cursor.close()        
    return key



class soapCommander(soap.SOAPPublisher):
    __clientIP = None
    
    def render(self, request):
        self.__clientIP = request.getClientIP()
        return soap.SOAPPublisher.render(self, request)
    
    def soap_echo(self, message):
        return message
    
    def soap_myip(self):
        return self.clientIP
    
    def soap_sendCommand(self, lockID, command):
        return sendCommand(lockID, command, self.__clientIP)
    
    def soap_open(self, lockID):
        return sendCommand(lockID, 'OPEN') 
    
    def soap_activate(self, lockID):
        return sendCommand(lockID, 'ACTIVATE')

    def soap_deactivate(self, lockID):
        return sendCommand(lockID, 'DEACTIVATE')

    def soap_status(self, lockID):
        return sendCommand(lockID, 'STATUS')
    
    def soap_door(self, lockID):
        return sendCommand(lockID, 'DOOR')
   
    def soap_confirmCode(self, lockID, codeAnswer):
        return confirmCode(lockID, codeAnswer)
    
    def soap_getSessionKey(self, commandID):
        return getSessionKey(commandID)
    
    def soap_getResult(self, commandID):
        return getResult(commandID)



class jsonRPCcommander(JSONRPCServer):
    __clientIP = None

    def render(self, request):
        self.__clientIP = request.getClientIP()
        return JSONRPCServer.render(self, request)
    
    def jsonrpc_echo(self, data):
        return data
  
    def jsonrpc_myip(self):
        return self.clientIP
    
    def jsonrpc_sendCommand(self, lockID, command):
        return sendCommand(lockID, command, self.__clientIP)
    
    def jsonrpc_open(self, lockID):
        return sendCommand(lockID, 'OPEN', self.__clientIP) 
    
    def jsonrpc_activate(self, lockID):
        return sendCommand(lockID, 'ACTIVATE', self.__clientIP)

    def jsonrpc_deactivate(self, lockID):
        return sendCommand(lockID, 'DEACTIVATE', self.__clientIP)

    def jsonrpc_status(self, lockID):
        return sendCommand(lockID, 'STATUS', self.__clientIP)
    
    def jsonrpc_door(self, lockID):
        return sendCommand(lockID, 'DOOR', self.__clientIP)
   
    def jsonrpc_confirmCode(self, lockID, codeAnswer):
        return confirmCode(lockID, codeAnswer)
    
    def jsonrpc_getSessionKey(self, commandID):
        return getSessionKey(commandID)
    
    def jsonrpc_getResult(self, commandID):
        return getResult(commandID)


    
print "Starting server..."

settings = ConfigParser.ConfigParser()
settings.read('CommandServer.conf')

print "GUESTLOCK protocol on port: " + settings.get('GuestLock', 'port')
print "SOAP protocol on port: " + settings.get('SOAP', 'port')
print "jsonRPC protocol on port: " + settings.get('jsonRPC', 'port')

factory = CommandProtocolFactory()
factory.protocol = CommandProtocol

pinger = task.LoopingCall(factory.lockPinger)
pinger.start(60, False) 

if __name__ == '__main__':
    reactor.listenTCP(int(settings.get('GuestLock', 'port')), factory)
    reactor.listenTCP(int(settings.get('SOAP', 'port')), server.Site(soapCommander()))
    reactor.listenTCP(int(settings.get('jsonRPC', 'port')), server.Site(jsonRPCcommander()))
    reactor.run()
elif __name__ == '__builtin__':
    application = service.Application("CommandServer")
    internet.TCPServer(int(settings.get('SOAP', 'port')), server.Site(soapCommander())).setServiceParent(application)
    internet.TCPServer(int(settings.get('jsonRPC', 'port')), server.Site(jsonRPCcommander())).setServiceParent(application)
    internet.TCPServer(12345, factory).setServiceParent(application)


