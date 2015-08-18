#!/usr/bin/env python

import requests
import json
import hashlib 
import hmac
import time

lockID = 'YJK7RS7S5L5'
lockSecret = 'password'

def jsonCall(procName, *args):
    url = "http://192.168.1.7:8081/"
    headers = {'content-type': 'application/json'}
    payload = {
        "method": procName,
        "params": args,
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    print response
    return response["result"]

def main():
    commandID = jsonCall('status', lockID)
    sessionID = jsonCall('getSessionKey', commandID)
    if sessionID:
        hashCode = hmac.new(key=str(sessionID), msg=lockSecret, digestmod=hashlib.sha1).hexdigest()
        jsonCall('confirmCode', lockID, hashCode)
    time.sleep(0.1)
    print jsonCall('getResult', commandID)
    
         

if __name__ == "__main__":
    main()
