#!/usr/bin/env python

import requests
import json
import hashlib 
import hmac
import time

lockID = 'OL6KSD82JN3'
lockSecret = 'dErPaRoL'
url = "http://176.109.105.70:8088/"

def jsonCall(procName, *args):
    
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
    commandID = jsonCall('open', lockID)
    sessionID = jsonCall('getSessionKey', commandID)
    if sessionID:
        hashCode = hmac.new(key=str(sessionID), msg=lockSecret, digestmod=hashlib.sha1).hexdigest()
        jsonCall('confirmCode', lockID, hashCode)
    #time.sleep(0.1)
    print jsonCall('getResult', commandID)
    
         

if __name__ == "__main__":
    main()
