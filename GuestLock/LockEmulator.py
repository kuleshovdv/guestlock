#!/usr/bin/env python

import socket
import threading
import hashlib 
import hmac
import random
import time

host = '176.109.105.70'
port = 443

lockID = 'OL6KSD82JN3'
lockPass = 'dErPaRoL'
lockSecret = 'dErPaRoL'

guestPass = ''

allowCommand = ("OPEN", "ACTIVATE", "DEACTIVATE", "GUEST")
statusRequest = ("DOOR", "STATUS")


def getPassword(passLen):
    str1 = '123456789'
    str2 = 'qwertyuiopasdfghjklzxcvbnm'
    str3 = str2.upper()
    str4 = str1+str2+str3
    ls = list(str4)
    random.shuffle(ls)
    return ''.join([random.choice(ls) for x in range(passLen)])


def validateServer(socetToServer, commandID):
    requestKey = getPassword(8)
    print "> /RE:%s" % requestKey
    socetToServer.send("/RE:%s:%s\r\n" % (requestKey, commandID))
    answer = socetToServer.recv(1024).strip()
    print "$ " + answer
    print "# " + hmac.new(key=requestKey, msg=lockSecret, digestmod=hashlib.sha1).hexdigest()
    answer = answer.split(":")
    if (answer[0] == "AUTH") and (len(answer) > 1):
        return hmac.new(key=requestKey, msg="dErPaRoL", digestmod=hashlib.sha1).hexdigest() == answer[1]   
    else:
        return False
    

def reciveData(socetToServer):
    lockActive = False
    while True:
        try:
            answer = socetToServer.recv(1024).strip()
            print "$ " + answer
            cmnd = answer.split(":")
            
            if answer:
                if cmnd[0] == "PING":
                    #print "It was ping signal"
                    socetToServer.send("/PONG\r\n")
                    print "$ " + answer
                    cmnd = answer.split(":")
                elif cmnd[0] == "ANSW":
                    #print "> /ANSW:%s\r\n" % hmac.new(key="dErPaRoL", msg=cmnd[1], digestmod=hashlib.sha1).hexdigest()
                    socetToServer.send("/ANSW:%s\r\n" % hmac.new(key=lockPass, msg=cmnd[1], digestmod=hashlib.sha1).hexdigest())
                    pass
                #print cmnd
                elif cmnd[0] in allowCommand + statusRequest:
                    if cmnd[0] == "GUEST":
                        if cmnd[1] == hmac.new(key=lockSecret, msg=guestPass, digestmod=hashlib.sha1).hexdigest():
                            print "WELCOME!!!"
                        else:
                            print "GET OUT"        
                    elif validateServer(socetToServer, cmnd[1]):
                        print "Server VALID"
                        report = "OK"
                        if cmnd[0] == "DOOR":
                            report = "CLOSE"
                        elif cmnd[0] == "STATUS":
                            if lockActive:
                                report = "ACTIVE"
                            else:
                                report = "NOTACTIVE"
                        elif cmnd[0] == "ACTIVATE":
                            lockActive = True
                        elif cmnd[0] == "DEACTIVATE":
                            lockActive = False
                        if len(cmnd) > 1:
                            print "> /%s:%s\r\n" % (report, cmnd[1])
                            socetToServer.send("/%s:%s\r\n" % (report, cmnd[1]))
                        else:
                            socetToServer.send("/%s:\r\n" % report) 
                    else:
                        print "Server NOT valid"                        
        except:
            print "Connection lost"
            break


socetToServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

socetToServer.connect((host, port))

print socetToServer.recv(1024)

t = threading.Thread(target=reciveData, args=(socetToServer,))
t.daemon = True
t.start()

socetToServer.send("/ID:" + lockID + "\r\n")

while True:
    commandString = raw_input(">")
    if commandString == "exit":
        break
    command = commandString.split(":")
     
    if (command[0] == "/GUEST") and (len(command) > 2):
        guestPass = command[2]
        commandString = ':'.join(command[:2])
        print commandString 
    socetToServer.send(commandString+"\r\n")

socetToServer.close()
