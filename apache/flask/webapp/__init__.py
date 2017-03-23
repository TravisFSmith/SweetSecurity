import datetime, os, re, time
from flask import Flask, render_template_string, request, render_template, redirect, jsonify, flash, g
from flask_mail import Mail
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
csrf = CSRFProtect()
from elasticsearch import Elasticsearch
from time import sleep
import json

#Local Scripts
import email
import es
import validators

class ConfigClass(object):
__appSettings__
    CSRF_ENABLED = True

def create_app():

    """ Flask application factory """
    # Setup Flask app and app.config
    app = Flask(__name__)
    app.config.from_object(__name__+'.ConfigClass')
    esService = Elasticsearch()
    mail = Mail(app)
    try:
        recipient=app.config['MAIL_USERNAME']
    except:
        recipient=None
    csrf.init_app(app)

    #Used to get the CSRF for client scripts
    @app.route('/csrf')
    def getCsrfToken():
        return render_template('csrf.html')

    @app.route('/')
    def home_page():
        #So we can link to kibana
        serverIP=re.search(r'^https?://([\w\d\.\-]+)',request.url).groups()
        serverIP=serverIP[0]
        deviceList=[]
        matchAll = {"query": {"match_all": {}}}
        allDevices=es.search(esService, matchAll, 'sweet_security', 'devices')
        if allDevices is not None:
            for host in allDevices['hits']['hits']:
                portCount=0
                portCountQuery = {"query": {"match_phrase": {"mac": { "query": host['_source']['mac']}}}}
                portInfo=es.search(esService, portCountQuery, 'sweet_security', 'ports')
                if portInfo is not None:
                    portCount=len(portInfo['hits']['hits'])
                deviceInfo={'hostname': host['_source']['hostname'],
                        'nickname': host['_source']['nickname'],
                        'ip': host['_source']['ip4'],
                        'mac': host['_source']['mac'],
                        'vendor': host['_source']['vendor'],
                        'ignore': str(host['_source']['ignore']),
                        'firstSeen': host['_source']['firstSeen'],
                        'lastSeen': host['_source']['lastSeen'],
                        'openPorts': portCount}
                deviceList.append(deviceInfo)
        return render_template('index.html', serverIP=serverIP, deviceList=deviceList)

    @app.route('/addDevice', methods=['POST','GET'])
    def addDevice():
        if request.method=='GET':
            return render_template('csrf.html')
        hostname=''
        ip=''
        mac=''
        vendor=''
        ignored='None'
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "key":
                    apiKey=request.form['key']
                if key == "hostname":
                    hostname=request.form['hostname']
                if key == "ip":
                    ip=request.form['ip']
                if key == "macAddress":
                    mac=request.form['macAddress']
                    #Convert mac to uppercase alphanumeric
                    mac=validators.convertMac(mac)
                if key == "vendor":
                    vendor=request.form['vendor']
                if key == "ignored":
                    ignored=request.form['ignored']
        if len(mac)==0:
            return jsonify(status="Error", reason="Must Supply MAC Address")
        if validators.macAddress(mac) == False:
            return jsonify(status="Error", reason="Invalid MAC Address")
        if len(ip) > 0 and validators.ipAddress(ip) == False:
            return jsonify(status="Error", reason="Invalid IP Address")
        if len(hostname) > 0 and validators.hostname(hostname) == False:
            return jsonify(status="Error", reason="Invalid Hostname")
        if ignored != "None" and validators.ignoreStatus(ignored) == False:
            return jsonify(status="Error", reason="Invalid Ignore Status")
        newDeviceData={'hostname': hostname,
                    'nickname': hostname,
                    'ip4': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'ignore': ignored,
                    'firstSeen': str(int(round(time.time() * 1000))),
                    'lastSeen': str(int(round(time.time() * 1000)))}
        deviceQuery = {"query": {"match_phrase": {"mac": { "query": mac }}}}
        deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
        if deviceInfo is None:
            #First ever device...
            es.write(esService, newDeviceData, 'sweet_security', 'devices')
            emailBody="Hostname: %s<br>Nickname: %s<br>IP Address: %s<br>MAC Address: %s<br>Vendor: %s" % (newDeviceData['hostname'], newDeviceData['nickname'], newDeviceData['ip4'], newDeviceData['mac'], newDeviceData['vendor'])
            email.emailUser(mail,"New Device Found",recipient,emailBody)
            return jsonify(status="Success", reason="Device added")
        elif len(deviceInfo['hits']['hits']) == 0:
            #New Device
            es.write(esService, newDeviceData, 'sweet_security', 'devices')
            emailBody="Hostname: %s<br>Nickname: %s<br>IP Address: %s<br>MAC Address: %s<br>Vendor: %s" % (newDeviceData['hostname'], newDeviceData['nickname'], newDeviceData['ip4'], newDeviceData['mac'], newDeviceData['vendor'])
            email.emailUser(mail,"New Device Found",recipient,emailBody)
            return jsonify(status="Success", reason="Device added")
        elif len(deviceInfo['hits']['hits']) == 1:
            if deviceInfo['hits']['hits'][0]['_source']['hostname'] != newDeviceData['hostname']:
                body = {'doc' : {'hostname': newDeviceData['hostname']}}
                es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
                #If user hasn't updated the nickname, update that too
                if deviceInfo['hits']['hits'][0]['_source']['hostname'] == deviceInfo['hits']['hits'][0]['_source']['nickname']:
                    body = {'doc' : {'nickname': newDeviceData['hostname']}}
                    es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])                    
            if deviceInfo['hits']['hits'][0]['_source']['ip4'] != newDeviceData['ip4']:
                body = {'doc' : {'ip4': newDeviceData['ip4']}}
                es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
            body = {'doc' : {'lastSeen': str(int(round(time.time() * 1000)))}}
            es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
            return jsonify(status="Success", reason="Device updated")
        else:
            es.consolidate(mac,esService)
            return jsonify(status="Warning", reason="Multiple devices consolidated. Next update will update device")

    @app.route('/renameDevice', methods=['POST'])
    def renameDevice():
        mac=''
        nickName=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                     mac=request.form['macAddress']
                if key == "nickName":
                     nickName=request.form['nickName']
        if len(mac)==0:
            flash(u'MAC Address Missing For Device', 'error')
            return redirect('/')
        if len(nickName)==0:
            flash(u'New Name Must Actually Have Words', 'error')
            return redirect('/')
        deviceQuery = {"query": {"match_phrase": {"mac": { "query": mac }}}}
        deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
        if deviceInfo is None:
            flash(u'Error renaming device, unknown device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 0:
            flash(u'Error renaming device, unknown device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 1:
            import cgi
            escaped = cgi.escape(nickName)
            for hit in deviceInfo['hits']['hits']:
                body = {'doc' : {'nickname': escaped}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device renamed', 'success')
            return redirect('/')
        else:
            es.consolidate(mac,esService)
            sleep(1)
            deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
            import cgi
            escaped = cgi.escape(nickName)
            for hit in deviceInfo['hits']['hits']:
                body = {'doc' : {'nickname': escaped}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device renamed', 'success')
            return redirect('/')

    @app.route('/ignoreDevice', methods=['POST'])
    def ignoreDevice():
        mac=''
        ignored=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                     mac=request.form['macAddress']
                if key == "ignored":
                     ignored=request.form['ignored']
        if len(mac)==0:
            flash(u'MAC Address Missing For Device', 'error')
            return redirect('/')
        if len(ignored)==0:
            flash(u'Missing ignore flag', 'error')
            return redirect('/')

        deviceQuery = {"query": {"match_phrase": {"mac": { "query": mac }}}}
        deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
        if deviceInfo is None:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 0:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 1:
            for hit in deviceInfo['hits']['hits']:
                body = {'doc' : {'ignore': ignored}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
            
            emailBody="Hostname: %s<br>Nickname: %s<br>IP Address: %s<br>MAC Address: %s<br>Vendor: %s" % (deviceInfo['hits']['hits'][0]['_source']['hostname'], deviceInfo['hits']['hits'][0]['_source']['nickname'], deviceInfo['hits']['hits'][0]['_source']['ip4'], deviceInfo['hits']['hits'][0]['_source']['mac'], deviceInfo['hits']['hits'][0]['_source']['vendor'])
            if int(ignored)==0:
                response=email.emailUser(mail,"Device Being Monitored",recipient,emailBody)
            else:
                response=email.emailUser(mail,"Device Bypassed",recipient,emailBody)
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device modified', 'success')
            return redirect('/')
        else:
            es.consolidate(mac,esService)
            sleep(1)
            deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
            for hit in deviceInfo['hits']['hits']:
                body = {'doc' : {'ignore': ignored}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
            emailBody="Hostname: %s<br>Nickname: %s<br>IP Address: %s<br>MAC Address: %s<br>Vendor: %s" % (deviceInfo['hits']['hits'][0]['_source']['hostname'], deviceInfo['hits']['hits'][0]['_source']['nickname'], deviceInfo['hits']['hits'][0]['_source']['ip4'], deviceInfo['hits']['hits'][0]['_source']['mac'], deviceInfo['hits']['hits'][0]['_source']['vendor'])
            if int(ignored)==0:
                email.emailUser(mail,"Device Being Monitored",recipient,emailBody)
            else:
                email.emailUser(mail,"Device Bypassed",recipient,emailBody)
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device modified', 'success')
            return redirect('/')

    @app.route('/deleteDevice', methods=['POST'])
    def deleteDevice():
        mac=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                     mac=request.form['macAddress']
        if len(mac)==0:
            flash(u'MAC Address Missing For Device', 'error')
            return redirect('/')

        deviceQuery = {"query": {"match_phrase": {"mac": { "query": mac }}}}
        deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
        if deviceInfo is None:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 0:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) > 0:
            for hit in deviceInfo['hits']['hits']:
                es.delete(esService, 'sweet_security', 'devices', hit['_id'])
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device deleted', 'success')
            return redirect('/')

    @app.route('/device/<mac>')
    def updateDevice(mac):
        deviceQuery = {"query": {"match_phrase": {"mac": { "query": mac }}}}
        deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
        if deviceInfo is None:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 0:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 1:
            for host in deviceInfo['hits']['hits']:
                portList=[]
                firstSeen = float(host['_source']['firstSeen']) / 1000.0
                lastSeen = float(host['_source']['lastSeen']) / 1000.0
                deviceInfo={'hostname': host['_source']['hostname'],
                        'nickname': host['_source']['nickname'],
                        'ip': host['_source']['ip4'],
                        'mac': host['_source']['mac'],
                        'vendor': host['_source']['vendor'],
                        'ignore': str(host['_source']['ignore']),
                        'firstSeen': datetime.datetime.fromtimestamp(firstSeen).strftime('%Y-%m-%d %H:%M:%S'),
                        'lastSeen': datetime.datetime.fromtimestamp(lastSeen).strftime('%Y-%m-%d %H:%M:%S')}
                portCountQuery = {"query": {"match_phrase": {"mac": { "query": host['_source']['mac']}}}}
                portInfo=es.search(esService, portCountQuery, 'sweet_security', 'ports')
                if portInfo is not None:
                    for port in portInfo['hits']['hits']:
                        portList.append(port['_source'])
                deviceInfo['portList']=portList
            return render_template('device.html', deviceInfo=deviceInfo)
        else:
            #This happens when the web component is still booting up and the ES index hasn't initialized
            #Sometimes we get two devices, we'll delete the old one and let the sensor send info on it's next update
            es.consolidate(mac,esService)
            #sleep for one second, otherwise ES doesn't have enough time to delete the duplicated record
            sleep(1)
            return redirect('/device/%s' % mac)

    @app.route('/addPort', methods=['POST'])
    def addPort():
        mac=''
        port=''
        protocol=''
        name=''
        product=''
        version=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                    mac=request.form['macAddress']
                    mac=validators.convertMac(mac)
                if key == "port":
                    port=request.form['port']
                if key == "protocol":
                    protocol=request.form['protocol']
                if key == "name":
                    name=request.form['name']
                if key == "version":
                    version=request.form['version']
                if key == "product":
                    product=request.form['product']
        if len(mac)==0:
            return jsonify (status='error',reason='missing mac address')
        if len(port)==0:
            return jsonify (status='error',reason='missing port number')
        if len(protocol)==0:
            return jsonify (status='error',reason='missing protocol')
        if len(name)==0:
            return jsonify (status='error',reason='missing port name')
        if len(version)==0:
            version='Unknown'
        if len(product)==0:
            product='Unknown'
        
        portQuery = {"query":{"bool":{"must":[{"match":{"mac": mac }},{ "match": { "port": port }}]}}}
        portInfo=es.search(esService, portQuery, 'sweet_security', 'ports')
        if portInfo is None:
            portData={'port': (port),
                      'protocol': protocol,
                      'name': name,
                      'mac': mac,
                      'product': product,
                      'version': version}
            es.write(esService, portData, 'sweet_security', 'ports')
            return jsonify(status='success',reason='Port added')
        elif len(portInfo['hits']['hits']) == 0:
            portData={'port': (port),
                      'protocol': protocol,
                      'name': name,
                      'mac': mac,
                      'product': product,
                      'version': version}
            es.write(esService, portData, 'sweet_security', 'ports')
            return jsonify(status='success',reason='Port added')
        elif len(portInfo['hits']['hits']) == 1:
            portData={'port': (port),
                      'protocol': protocol,
                      'name': name,
                      'mac': mac,
                      'product': product,
                      'version': version}
            previousPortData=portInfo['hits']['hits'][0]['_source']
            changeName=False
            changeProduct=False
            changeVersion=False
            if portData['name'] != previousPortData['name']:
                body = {'doc' : {'name': portData['name']}}
                es.update(esService, body, 'sweet_security', 'ports', portInfo['hits']['hits'][0]['_id'])
            if portData['product'] != previousPortData['product']:
                body = {'doc' : {'product': portData['product']}}
                es.update(esService, body, 'sweet_security', 'ports', portInfo['hits']['hits'][0]['_id'])
            if portData['version'] != previousPortData['version']:
                body = {'doc' : {'version': portData['version']}}
                es.update(esService, body, 'sweet_security', 'ports', portInfo['hits']['hits'][0]['_id'])
            return jsonify(status='success',reason='port information updated')
        else:
            return jsonify(status='error',reason='duplicate ports found')
        
        return jsonify(status='error', reason="you should not be here")

    @app.route('/getConfig', methods=['GET','POST'])
    def getConfig():
        #Get config for spoofing devices
        deviceList=[]
        matchAll = {"query": {"match_all": {}}}
        allDevices=es.search(esService, matchAll, 'sweet_security', 'devices')
        if allDevices is not None:
            for host in allDevices['hits']['hits']:
                deviceInfo={'hostname': host['_source']['hostname'],
                        'nickname': host['_source']['nickname'],
                        'ip': host['_source']['ip4'],
                        'mac': host['_source']['mac'],
                        'vendor': host['_source']['vendor'],
                        'ignore': str(host['_source']['ignore']),
                        'firstSeen': host['_source']['firstSeen'],
                        'lastSeen': host['_source']['lastSeen']}
                deviceList.append(deviceInfo)
        return jsonify(deviceList=deviceList)


    @app.route('/settings')
    def settings():
        #So we can link to kibana
        serverIP=re.search(r'^https?://([\w\d\.\-]+)',request.url).groups()
        serverIP=serverIP[0]
        elasticHealth=os.popen('service elasticsearch status').read()
        for line in elasticHealth.splitlines():
            if line.lstrip().startswith('Active: '):
                if line.lstrip().startswith('Active: active (running)'):
                    elasticHealth='Started'
                else:
                    elasticHealth='Stopped'

        else:
            logstashHealth='not available'
        kibanaHealth=os.popen('service kibana status').read()
        for line in kibanaHealth.splitlines():
            if line.lstrip().startswith('Active: '):
                if line.lstrip().startswith('Active: active (running)'):
                    kibanaHealth='Started'
                else:
                    kibanaHealth='Stopped'

        #Place holder if we want to use this in a later release. 
        #Need to add commands to sudoers command for www-data
        if os.path.isfile('/usr/share/logstash/bin/logstash'):
            logstashHealth=os.popen('service logstash status').read()
            for line in logstashHealth.splitlines():
                if line.lstrip().startswith('Active: '):
                    if line.lstrip().startswith('Active: active (running)'):
                        logstashHealth='Started'
                    else:
                        logstashHealth='Stopped'
        if os.path.isfile('/opt/nsm/bro/bin/broctl'):
            broStatus='stopped'
            broHealth=os.popen('sudo /opt/nsm/bro/bin/broctl status').read()
            broLine=0
            for line in broHealth.splitlines():
                if broLine == 1:
                    broStatus=line.split()[3]
                broLine+=1
        else:
            broStatus="not available"
        if os.path.isfile('/opt/SweetSecurity/sweetSecurity.py'):
            ssHealth=os.popen('service sweetsecurity status').read()
            for line in ssHealth.splitlines():
                if line.lstrip().startswith('Active: '):
                    if line.lstrip().startswith('Active: active (running)'):
                        ssHealth='Started'
                    else:
                        ssHealth='Stopped'
        else:
            ssHealth="not available"

        diskUsage=0
        diskUsageCommand=os.popen('df -k "/"').read()
        for line in diskUsageCommand.splitlines():
            line = line.split()
            if line[0] != 'Filesystem':
                diskUsage=int(line[4][:-1])

        memUsage={'available': 0, 'consumed': 0, 'percentUsed': 0}
        memInfo=os.popen('free -t -m').read()
        for line in memInfo.splitlines():
            if line.rstrip().startswith('Mem:'):
                memUsage['available']=line.split()[1]
                memUsage['consumed']=line.split()[2]
                memUsage['percentUsed']=int(round((float(line.split()[2]) / float(line.split()[1])) * 100,0))
        
        #Get the system status info for every sensor sending data
        sensorInfo=[]
        sensorQuery={"query":{"exists":{"field":"logstashHealth"}},"size":0,"aggs":{"distinct_hosts":{"terms":{"field":"host.keyword"}}}}
        
        sensorHostData=es.search(esService, sensorQuery, 'logstash-*', 'logs')
        if len(sensorHostData['hits']['hits']) > 0:
            for sensor in sensorHostData['aggregations']['distinct_hosts']['buckets']:
                lsHealthQuery={"sort":[{ "@timestamp" : {"order" : "desc"}}],"query": {"bool":{"must":[{"exists":{"field":"logstashHealth"}},{"term":{"host.keyword":sensor['key']}}]}}}
                lsHealthData=es.search(esService, lsHealthQuery, 'logstash-*', 'logs')
                
                broHealthQuery={"sort":[{ "@timestamp" : {"order" : "desc"}}],"query":{"bool":{"must":[{"exists":{"field":"broHealth"}},{"term":{"host.keyword":sensor['key']}}]}}}
                broHealthData=es.search(esService, broHealthQuery, 'logstash-*', 'logs')
                
                diskUsageQuery={"sort":[{ "@timestamp" : {"order" : "desc"}}],"query":{"bool":{"must":[{"exists":{"field":"diskUsage"}},{"term":{"host.keyword": sensor['key']}}]}}}
                diskUsageData=es.search(esService, diskUsageQuery, 'logstash-*', 'logs')
                
                memUsageQuery={"sort":[{ "@timestamp" : {"order" : "desc"}}],"query":{"bool":{"must":[{"exists":{"field":"memAvailable"}},{"term":{"host.keyword":sensor['key']}}]}}}
                memUsageData=es.search(esService, memUsageQuery, 'logstash-*', 'logs')
                
                sensorDiskUsage=0
                memInstalled=0
                memConsumed=0
                memPercent=0
                broStatus='Unknown'
                logstashStatus='Unknown'
                time='Unknown'
                if len(lsHealthData['hits']['hits']) > 0:
                    time=lsHealthData['hits']['hits'][0]['_source']['@timestamp']
                    logstashStatus=lsHealthData['hits']['hits'][0]['_source']['logstashHealth']
                if len(broHealthData['hits']['hits']) > 0:
                    time=broHealthData['hits']['hits'][0]['_source']['@timestamp']
                    broStatus=broHealthData['hits']['hits'][0]['_source']['broHealth']
                if len(diskUsageData['hits']['hits']) > 0:
                    time=diskUsageData['hits']['hits'][0]['_source']['@timestamp']
                    sensorDiskUsage=diskUsageData['hits']['hits'][0]['_source']['diskUsage']
                if len(memUsageData['hits']['hits']) > 0:
                    time=memUsageData['hits']['hits'][0]['_source']['@timestamp']
                    memInstalled=memUsageData['hits']['hits'][0]['_source']['memAvailable']
                    memConsumed=memUsageData['hits']['hits'][0]['_source']['memConsumed']
                    memPercent=memUsageData['hits']['hits'][0]['_source']['memPercentUsed']
                 
                time=datetime.datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%fZ')
                timeSince=datetime.datetime.now()-time
                systemInfo={
                    'time': time,
                    'timeSince': int(timeSince.seconds / 60.0),
                    'sensorName': sensor['key'],
                    'logstash': logstashStatus,
                    'broStatus': broStatus,
                    'diskUsage': int(sensorDiskUsage),
                    'memInstalled': int(memInstalled),
                    'memConsumed': int(memConsumed),
                    'memPercent': int(memPercent)
                }
                sensorInfo.append(systemInfo)
        
        return render_template('settings.html',serverIP=serverIP,esHealth=elasticHealth,kHealth=kibanaHealth,diskUsage=diskUsage,memUsage=memUsage,sensorInfo=sensorInfo)

    @app.route('/settings/manageService', methods=['POST'])
    def settingsManageService():
        serviceName=''
        action=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "serviceName":
                     serviceName=request.form['serviceName']
                if key == "action":
                     action=request.form['action']
        if serviceName=="elasticsearch":
            if action == "start":
                os.popen('sudo service elasticsearch start').read()
            elif action == "restart":
                os.popen('sudo service elasticsearch restart').read()
            elif action == "stop":
                os.popen('sudo service elasticsearch stop').read()
            else:
                return "unknown action"
        elif serviceName=="kibana":
            if action == "start":
                os.popen('sudo service kibana start').read()
            elif action == "restart":
                os.popen('sudo service kibana restart').read()
            elif action == "stop":
                os.popen('sudo service kibana stop').read()
            else:
                return "unknown action"
        return "unknown service"

    @app.route('/consolidateDevices')
    def consolidateDevices():
        matchAll = {"query": {"match_all": {}}}
        allDevices=es.search(esService, matchAll, 'sweet_security', 'devices')
        if allDevices is not None:
            for host in allDevices['hits']['hits']:
                es.consolidate(host['_source']['mac'],esService)
        flash(u'Devices Consolidated', 'success')
        return redirect('/settings')

    @app.errorhandler(CSRFError)
    def csrf_error(reason):
        return jsonify(reason=reason)

    return app

