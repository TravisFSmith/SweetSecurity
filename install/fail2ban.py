import os, shutil

def install():
    os.popen('sudo apt-get install fail2ban 2>&1').read()
    cpuArch = os.uname()[4]
    if cpuArch.startswith('x86'):
        shutil.move('/etc/fail2ban/jail.d/defaults-debian.conf', '/etc/fail2ban/jail.d/defaults-debian.orig')
        with open("/etc/fail2ban/jail.d/defaults-debian.conf", "wt") as fileOut:
            fileOut.write('[sshd]\n')
            fileOut.write('enabled = true\n\n')
            fileOut.write('[apache-auth]\n')
            fileOut.write('enabled = true\n')
            fileOut.write('port = 80,443,5602,9201\n')
    else:
        #Raspbian
        with open("/etc/fail2ban/jail.d/defaults-debian.conf", "wt") as fileOut:
            fileOut.write('[ssh]\n')
            fileOut.write('enabled = true\n\n')
            fileOut.write('[apache]\n')
            fileOut.write('enabled = true\n')
            fileOut.write('port = 80,443,5602,9201\n')
    os.popen('sudo service fail2ban restart').read()