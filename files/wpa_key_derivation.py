#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from pbkdf2_math import pbkdf2_hex
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

# Récupération des valeurs pouvant être trouvée dans la capture
# le ssid peut être récupéré dans le premier paquet de la capture
ssid = wpa[0].info.decode()
# l'adresse mac de l'AP se trouve également dans le premier paquet car c'est l'AP qui l'envoie en broadcast
APmac = a2b_hex(wpa[0].addr2.replace(":", ""))
# comme l'AP envoie le message en broadcast dans le premier paquet, l'adresse du client est trouvable seulement dès le deuxième paquet
Clientmac = a2b_hex(wpa[1].addr1.replace(":", ""))

# Authenticator and Supplicant Nonces
# Le paquet 6 (wpa[5]) de la capture contient le nonce de l'AP
ANonce = a2b_hex(wpa[5].load.hex()[26:90])
# Le paquet 7 (wpa[6]) de la capture contient le nonce du client
SNonce = a2b_hex(wpa[6].load.hex()[26:90])

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Le paquet 9 (wpa[8]) de la capture contient les informations dont nous avons besoin pour récupérer l'élement data
# "0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
data = scapy.utils.linehexdump(wpa[8][EAPOL], 0, 1, True).replace(" ", "").lower()[:162] + "0" * 32 + "0" * 4


print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: \t",passPhrase,"\n")
print ("SSID: \t\t",ssid,"\n")
print ("AP Mac: \t",b2a_hex(APmac).decode(),"\n")
print ("CLient Mac:\t",b2a_hex(Clientmac).decode(),"\n")
print ("AP Nonce:\t",b2a_hex(ANonce).decode(),"\n")
print ("Client Nonce:\t",b2a_hex(SNonce).decode(),"\n")
print ("data:\t\t", data)

# encodage de data en hexa
data = a2b_hex(data)

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

# expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

# calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")
