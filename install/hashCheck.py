import hashlib


def getHash(fileName):
    if fileName == 'elasticsearch-5.5.0.deb':
        return 'f386c932b2e6e661e43d81f79eaa44bdf6ecef7c'
    elif fileName == 'kibana-5.5.0-linux-x86_64.tar.gz':
        return '935e925713cb84eb1879a59ac68708fccf3361d4'
    elif fileName == 'kibana-5.5.0-linux-x86.tar.gz':
        return 'f114e00d2231508607203ec9080a8b61925fe45c'
    elif fileName == 'logstash-5.5.0.deb':
        return 'f7e5cd2e9191c9e7a2d0a616525f319343a23b64'
    elif fileName == 'bro-2.5.1.tar.gz':
        return '9c133dd3a075be1084f9bf53d79c42ddcf23633c'
    return ''

def checkHash(fileName):
    BUF_SIZE = 65536
    sha1 = hashlib.sha1()
    with open(fileName, 'rb') as file:
        while True:
            data = file.read(BUF_SIZE)
            if not data:
                break
            sha1.update(data)
    sha1=sha1.hexdigest()
    if sha1 == getHash(fileName):
        return True
    else:
        return False