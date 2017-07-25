import hashlib


def getHash(fileName):
    if fileName == 'elasticsearch-5.5.1.deb':
        return 'd6beceeb93ade6c3bc18b76a7f0e365dd95f6f52'
    elif fileName == 'kibana-5.5.1-linux-x86_64.tar.gz':
        return '6dba24c876841fdf116a413c843f09d3e98b4002'
    elif fileName == 'kibana-5.5.1-linux-x86.tar.gz':
        return '47d7707b1b8feb490276fd69b597d27af610d28b'
    elif fileName == 'logstash-5.5.1.deb':
        return '88fbe43065cfaa6b13374f8f4a69f871b7110208'
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