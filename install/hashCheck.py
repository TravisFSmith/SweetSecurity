import hashlib


def getHash(fileName):
    if fileName == 'elasticsearch-5.4.3.deb':
        return '294ac7ada78a3944cf05f3d43b62d4df4dd55c8f'
    elif fileName == 'kibana-5.4.3-linux-x86_64.tar.gz':
        return 'a5892ec6fd8271d508206ee8319473a06d2a5ac6'
    elif fileName == 'kibana-5.4.3-linux-x86.tar.gz':
        return '29e4a8903ebfc6cbe75b2ef5800f83893d076318'
    elif fileName == 'logstash-5.4.3.deb':
        return '1ed81009deea11b0cc5e747bf07c1af76d9eb12d'
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