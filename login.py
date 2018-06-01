#!/usr/bin/python3
#
# example of first stage of login

import netrc
from SDL import SDL

def main():
    info = netrc.netrc()
    username, hostname, password = info.authenticators('SDL')
    sdl = SDL(hostname)
    sdl.login(username, password)

main()
