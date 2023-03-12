# import tkinter module
from tkinter import *

# import other necessery modules
import random

# modules for encryption and decryption
import base64
import onetimepad
import pyDes

# creating root object
root = Tk()

# defining size of window
root.geometry("1200x6000")

# setting up the title of window
root.title("Message Encryption and Decryption")

Tops = Frame(root, width=1600, relief=SUNKEN)
Tops.pack(side=TOP)

f1 = Frame(root, width=800, relief=SUNKEN)
f1.pack(side=LEFT)

# ==============================================


lblInfo = Label(Tops, font=('helvetica', 50, 'bold'),
                text="MULTI-LAYERED \n ENCRYPTION AND DECRYPTION",
                fg="Black", bd=10, anchor='w')

lblInfo.grid(row=0, column=0)


# Initializing variables
Msg = StringVar()
mode = StringVar()
Result = StringVar()


# labels for the message
lblMsg = Label(f1, font=('arial', 16, 'bold'),
               text="MESSAGE", bd=16, anchor="w")

lblMsg.grid(row=1, column=0)
# Entry box for the message
txtMsg = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=Msg, bd=10, insertwidth=4,
               bg="powder blue", justify='right')


txtMsg.grid(row=1, column=1)

# labels for the mode
lblmode = Label(f1, font=('arial', 16, 'bold'),
                text="MODE(e for encrypt, d for decrypt)",
                bd=16, anchor="w")

lblmode.grid(row=3, column=0)
# Entry box for the mode
txtmode = Entry(f1, font=('arial', 16, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg="powder blue", justify='right')

txtmode.grid(row=3, column=1)

# labels for the result
lblResult = Label(f1, font=('arial', 16, 'bold'),
                  text="The Result-", bd=16, anchor="w")

lblResult.grid(row=2, column=2)

# Entry box for the result
txtResult = Entry(f1, font=('arial', 16, 'bold'),
                  textvariable=Result, bd=10, insertwidth=4,
                  bg="powder blue", justify='right')

txtResult.grid(row=2, column=3)



# Function to encode


def reverseEncrypt(inputMessage):
    strInput = str(inputMessage)
    reversStr = strInput[::-1]
    return str(reversStr)

def caeserCipherEncrypt(string, shift):
    cipher = ''
    for char in string:
        if char==' ':
            cipher=cipher+' '
        elif char.isupper():
            cipher = cipher + chr((ord(char) + shift - 65) % 26 + 65)
        else:
            cipher = cipher + chr((ord(char) + shift - 97) % 26 + 97)
        return str(cipher)

def base64Encryption(msg):
    sample_string = (msg)
    sample_string_bytes = sample_string.encode("ascii")
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")
    return str(base64_string)

def pydesEncrypt(msg):
    data = msg
    k = pyDes.des("DESCRYPT", pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    d = k.encrypt(data)
    return d

def enc(text):
    return(pydesEncrypt(base64Encryption(caeserCipherEncrypt(reverseEncrypt(text),10))))


    
# Function to decode
def pydesDecrypt(msg2):
    k = pyDes.des("DESCRYPT", pyDes.CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_PKCS5)
    lmao = k.decrypt(msg2).decode('ASCII')
    return str((bytes(lmao, 'utf-8')).decode("utf-8"))

def base64Decryption(decode_entry):
    base64_string = decode_entry
    base64_bytes = base64_string.encode("ascii")
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")    
    return str(sample_string)

def caeserCipherDecrypt(string, shift):
    cipher = ''
    shift = -shift
    for char in string:
        if char==' ':
            cipher=cipher+' '
        elif char.isupper():
            cipher = cipher + chr((ord(char) + shift - 65) % 26 + 65)
        else:
            cipher = cipher + chr((ord(char) + shift - 97) % 26 + 97)
    return str(cipher)

def reverseDecrypt(inputMessage):
    strInput = str(inputMessage)
    reversStr = strInput[::-1]
    return str(reversStr)

def dec(text):
    return(reverseDecrypt(caeserCipherDecrypt(base64Decryption(pydesDecrypt(text)),10)))
