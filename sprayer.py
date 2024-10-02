import requests
import os
from urllib3.exceptions import InsecureRequestWarning
import base64
from Crypto.Cipher import AES
from Crypto import Random
import sys

requiredEnvVars = ["METHOD_HEX", "URL_HEX", "HEADERS_HEX", "BODY_HEX", "AES256_KEY_HEX"]
missingEnvVars = [var for var in requiredEnvVars if os.getenv(var) is None]

if missingEnvVars:
    missingVarsStr = ", ".join(missingEnvVars)
    raise ValueError(f"Missing environment variables: {missingVarsStr}")

methodHex = os.getenv("METHOD_HEX")
urlHex = os.getenv("URL_HEX")
headersHex = os.getenv("HEADERS_HEX", default="")
bodyHex = os.getenv("BODY_HEX", default="")
aesKeyHex = os.getenv("AES256_KEY_HEX", default="")

def aes256_encrypt(dataStr, keyHexStr):
    """
         Encrypt using AES-256-CBC GCM random iv
        'keyHexStr' must be in hex, generate with 'openssl rand -hex 32'
    """
    try:
        key = bytes.fromhex(keyHexStr) # Key size: 256 bits => AES-256
        iv = Random.get_random_bytes(12) # Recommended nonce size for AES GCM : 12 bytes

        cipher = AES.new(key, AES.MODE_GCM, iv)

        cipher_data = cipher.encrypt(dataStr.encode("utf-8"))
        tag = cipher.digest()

        result = iv.hex()+cipher_data.hex()+tag.hex() # Result : IV + CIPHER DATA + TAG (Tag is used by GCM for authentication purposes)
    except Exception as e:
        print("Cannot encrypt datas...")
        print(e)
        exit(1)
    return result

def aes256_decrypt(encryptedDataHexStr, keyHexStr):
    """
         Encrypt using AES-256-CBC GCM random iv
        'keyHexStr' must be in hex, generate with 'openssl rand -hex 32'
    """
    try:
        key = bytes.fromhex(keyHexStr) # Key size: 256 bits => AES-256
        data = bytes.fromhex(encryptedDataHexStr)

        iv = data[:12]
        encrypted_data = data[12:-16]
        tag = data[-16:]

        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt_and_verify(encrypted_data, tag)

        result = decrypted.decode("utf-8")
    except Exception as e:
        print("Cannot decrypt datas...")
        print(e)
        exit(1)
    return result

def parseInputs(methodHex, urlHex, headersHex, bodyHex, aesKeyHex):
    method = aes256_decrypt(methodHex, aesKeyHex)
    url = aes256_decrypt(urlHex, aesKeyHex)
    
    headers = {}
    if len(headersHex) > 0:
        headersRaw = aes256_decrypt(headersHex, aesKeyHex)
        headersLines = headersRaw.splitlines()
        if len(headersLines)%2 != 0:
            raise Exception("Can not parse the request headers.")

        for i in range(0, len(headersLines), 2):
            headers[headersLines[i]] = headersLines[i+1]

    body = None
    if len(bodyHex) > 0:
        body = aes256_decrypt(bodyHex, aesKeyHex)

    return method, url, headers, body

def encryptOutputs(status, headers, body, aesKeyHex):
    statusHex = ""
    if status != None:
        statusHex = aes256_encrypt(str(status), aesKeyHex)

    headersStr = ""
    if headers != None:
        for key in headers:
            headersStr += key + "\n" + headers[key] + "\n"
        if len(headersStr) > 0:
            headersStr = headersStr[:-1]
    headersHex = aes256_encrypt(headersStr, aesKeyHex)

    bodyHex = ""
    if body != None:
        bodyHex = aes256_encrypt(body, aesKeyHex)

    return statusHex, headersHex, bodyHex

def makeRequest(method, url, headers=None, body=None):
    try:
        response = requests.request(method, url, headers=headers, data=body, verify=False)
    
        status = response.status_code
        headers = response.headers
        body = response.text

        return status, headers, body, None
    except requests.RequestException as e:
        return None, None, None, str(e)

reqMethod, reqUrl, reqHeaders, reqBody = parseInputs(methodHex, urlHex, headersHex, bodyHex, aesKeyHex)

# print("REQ_ENCRYPTED_DATA", (reqMethod, reqUrl, reqHeaders, reqBody))

respStatus, respHeaders, respBody, respErr = makeRequest(reqMethod, reqUrl, reqHeaders, reqBody)

if respErr != None:
    print("RESP_ERR", respErr)
else:
    respStatusHex, respHeadersHex, respBodyHex = encryptOutputs(respStatus, respHeaders, respBody, aesKeyHex)

    print("RESP_STATUS_ENCRYPTED_HEX", respStatusHex)
    print("RESP_HEADERS_ENCRYPTED_HEX", respHeadersHex)
    print("RESP_BODY_ENCRYPTED_HEX", respBodyHex)