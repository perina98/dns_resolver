import subprocess
import os,sys
import os.path
import signal

if len(sys.argv) != 4:
    print("Run program as python test.py domains blacklist port")
    exit(0)
else:
    domains = sys.argv[1]
    blacklist = sys.argv[2]
    port = sys.argv[3]
    if not os.path.isfile(domains):
        print(domains,' not a file')
        exit(1)
    if not os.path.isfile(blacklist):
        print(blacklist,' not a file')
        exit(1)


def checkFail(xline):
    filepath = blacklist
    domain = xline.split('.')
    with open(filepath) as fp:
        lines = fp.read().splitlines()
        for line in lines:
            if len(line) > 0:
                if line[0] == '#':
                    continue
                line = line.split('.')
                if len(line) <= len(domain):
                    i = len(line)-1
                    while(line[len(line) - 1 - i] == domain[len(domain) - 1 - i]):
                        if (len(line) - 1 - i) == 0:
                            return True
                        i = i + 1

        return False


def checkOutput(line):
    out = str(subprocess.check_output(['dig', '@localhost', '-p', str(port), line, 'A']))
    if out.find("NOERROR") != -1:
        return False
    else:
        return True

def checkfile():
    filepath = domains
    with open(filepath) as fp:
        lines = fp.read().splitlines()
        for line in lines:
            if checkOutput(line) == 0:
                print(line,"OK")
            else:
                if checkFail(line):
                    print(line,"OK")
                else:
                    print(line,"FAIL")

dns = subprocess.Popen(["./dns", "-s", "1.1.1.1", "-p",str(port),"-f",str(blacklist)])

checkfile()
dns.send_signal(signal.SIGTERM)
