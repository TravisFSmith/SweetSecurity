import hashlib


def getHash(fileName):
    if fileName == 'elasticsearch-5.3.0.deb':
        return 'dab27ca0f49463a0f2e194780186653d22327660'
    elif fileName == 'kibana-5.3.0-linux-x86_64.tar.gz':
        return '4e9daf275f8ef749fba931c1f5c35f85662efd53'
    elif fileName == 'kibana-5.3.0-linux-x86.tar.gz':
        return '6323e46abff74fd1af37a040539664d30f672cd8'
    elif fileName == 'logstash-5.3.0.deb':
        return '12f1a8c3f6de535d8a9b723e6bc396523e706f15'
    elif fileName == 'bro-2.5.tar.gz':
        return '12c6dc0c38e7515dbac530ba0890a0bce6066fa3'
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