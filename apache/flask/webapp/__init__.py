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
                        'defaultFwAction': host['_source']['defaultFwAction'],
                        'firstSeen': host['_source']['firstSeen'],
                        'lastSeen': host['_source']['lastSeen'],
                        'openPorts': portCount}
                deviceList.append(deviceInfo)
        alertQuery = {"query": {"match_phrase": {"addressed": {"query": 0}}}}
        allAlerts = es.search(esService, alertQuery, 'sweet_security_alerts', 'alerts')
        if allAlerts['hits']['total'] > 0:
            flash(u'There are %d new alerts!' % allAlerts['hits']['total'], 'error')
            alertCount = allAlerts['hits']['total']
            return render_template('index.html', serverIP=serverIP, deviceList=deviceList, alertCount=alertCount)
        return render_template('index.html', serverIP=serverIP, deviceList=deviceList)

    @app.route('/addDevice', methods=['POST', 'GET'])
    def addDevice():
        if request.method == 'GET':
            return render_template('csrf.html')
        hostname = ''
        ip = ''
        mac = ''
        vendor = ''
        # ignored='None'
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "key":
                    apiKey = request.form['key']
                if key == "hostname":
                    hostname = request.form['hostname']
                if key == "ip":
                    ip = request.form['ip']
                if key == "macAddress":
                    mac = request.form['macAddress']
                    # Convert mac to uppercase alphanumeric
                    mac = validators.convertMac(mac)
                if key == "vendor":
                    vendor = request.form['vendor']
                    # if key == "ignored":
                    #    ignored=request.form['ignored']
        if len(mac) == 0:
            return jsonify(status="Error", reason="Must Supply MAC Address")
        if validators.macAddress(mac) == False:
            return jsonify(status="Error", reason="Invalid MAC Address")
        if len(ip) > 0 and validators.ipAddress(ip) == False:
            return jsonify(status="Error", reason="Invalid IP Address")
        if len(hostname) > 0 and validators.hostname(hostname) == False:
            return jsonify(status="Error", reason="Invalid Hostname")
        # if ignored != "None" and validators.ignoreStatus(ignored) == False:
        #    return jsonify(status="Error", reason="Invalid Ignore Status")
        # Get Configuration Settings
        matchAll = {"query": {"match_all": {}}}
        ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
        if ssConfig is None:
            print "Error: configuration not found"
            return "Error: configuration not found"
        elif len(ssConfig['hits']['hits']) == 0:
            print "Error: configuration not found"
            return "Error: configuration not found"
            # configData={'defaultMonitor': 0, 'defaultIsolate': 0, 'defaultFW': 0, 'defaultLogRetention': 0}
            # es.write(esService, configData, 'sweet_security', 'configuration')

        defaultMonitorAction = 0
        defaultIsolateAction = 0
        defaultFwAction = 0
        # Get Configuration Settings
        matchAll = {"query": {"match_all": {}}}
        ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
        if ssConfig is not None:
            for config in ssConfig['hits']['hits']:
                defaultMonitorAction = config['_source']['defaultMonitor']
                defaultIsolateAction = config['_source']['defaultIsolate']
                defaultFwAction = config['_source']['defaultFW']
        if defaultFwAction == 1:
            defaultFwAction = 'ACCEPT'
        else:
            defaultFwAction = 'DROP'
        newDeviceData = {'hostname': hostname,
                         'nickname': hostname,
                         'ip4': ip,
                         'mac': mac,
                         'vendor': vendor,
                         'ignore': defaultMonitorAction,
                         'defaultFwAction': defaultFwAction,
                         'isolate': defaultIsolateAction,
                         'firstSeen': str(int(round(time.time() * 1000))),
                         'lastSeen': str(int(round(time.time() * 1000)))}
        deviceQuery = {"query": {"match_phrase": {"mac": {"query": mac}}}}
        deviceInfo = es.search(esService, deviceQuery, 'sweet_security', 'devices')
        serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
        serverIP = serverIP[0]
        if deviceInfo is None:
            # First ever device...
            es.write(esService, newDeviceData, 'sweet_security', 'devices')
            emailBody = render_template('emails/addDevice.html', deviceInfo=newDeviceData, serverIP=serverIP)
            email.emailUser(mail, "New Device Found", recipient, emailBody)
            return jsonify(status="Success", reason="Device added")
        elif len(deviceInfo['hits']['hits']) == 0:
            # New Device
            es.write(esService, newDeviceData, 'sweet_security', 'devices')
            emailBody = render_template('emails/addDevice.html', deviceInfo=newDeviceData, serverIP=serverIP)
            email.emailUser(mail, "New Device Found", recipient, emailBody)
            return jsonify(status="Success", reason="Device added")
        elif len(deviceInfo['hits']['hits']) == 1:
            if deviceInfo['hits']['hits'][0]['_source']['hostname'] != newDeviceData['hostname']:
                body = {'doc': {'hostname': newDeviceData['hostname']}}
                es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
                # If user hasn't updated the nickname, update that too
                if deviceInfo['hits']['hits'][0]['_source']['hostname'] == deviceInfo['hits']['hits'][0]['_source'][
                    'nickname']:
                    body = {'doc': {'nickname': newDeviceData['hostname']}}
                    es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
            if deviceInfo['hits']['hits'][0]['_source']['ip4'] != newDeviceData['ip4']:
                body = {'doc': {'ip4': newDeviceData['ip4']}}
                es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
            body = {'doc': {'lastSeen': str(int(round(time.time() * 1000)))}}
            es.update(esService, body, 'sweet_security', 'devices', deviceInfo['hits']['hits'][0]['_id'])
            return jsonify(status="Success", reason="Device updated")
        else:
            es.consolidate(mac, esService, 'devices')
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
        #deviceInfo = query_db('SELECT * FROM hosts where mac = ?',[mac],one=True)
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
            es.consolidate(mac,esService,'devices')
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
            serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
            serverIP = serverIP[0]
            for hit in deviceInfo['hits']['hits']:
                body = {'doc' : {'ignore': ignored}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
            emailDeviceInfo = {'hostname': deviceInfo['hits']['hits'][0]['_source']['hostname'],
                               'nickname': deviceInfo['hits']['hits'][0]['_source']['nickname'],
                               'ip': deviceInfo['hits']['hits'][0]['_source']['ip4'],
                               'mac': deviceInfo['hits']['hits'][0]['_source']['mac'],
                               'vendor': deviceInfo['hits']['hits'][0]['_source']['vendor'],
                               'ignore': ignored
                               }
            emailBody = render_template('emails/ignoreDevice.html', deviceInfo=emailDeviceInfo, serverIP=serverIP)
            if int(ignored)==0:
                response=email.emailUser(mail,"Device Being Monitored",recipient,emailBody)
            else:
                response=email.emailUser(mail,"Device Bypassed",recipient,emailBody)
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device modified', 'success')
            return redirect('/')
        else:
            serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
            serverIP = serverIP[0]
            es.consolidate(mac,esService,'devices')
            sleep(1)
            deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
            for hit in deviceInfo['hits']['hits']:
                body = {'doc' : {'ignore': ignored}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
            emailDeviceInfo = {'hostname': deviceInfo['hits']['hits'][0]['_source']['hostname'],
                               'nickname': deviceInfo['hits']['hits'][0]['_source']['nickname'],
                               'ip': deviceInfo['hits']['hits'][0]['_source']['ip4'],
                               'mac': deviceInfo['hits']['hits'][0]['_source']['mac'],
                               'vendor': deviceInfo['hits']['hits'][0]['_source']['vendor'],
                               'ignore': ignored
                               }
            emailBody = render_template('emails/ignoreDevice.html', deviceInfo=emailDeviceInfo, serverIP=serverIP)
            if int(ignored)==0:
                email.emailUser(mail,"Device Being Monitored",recipient,emailBody)
            else:
                email.emailUser(mail,"Device Bypassed",recipient,emailBody)
            #Have to delay the response so the refreshed page shows the new name
            sleep(1)
            flash(u'Device modified', 'success')
            return redirect('/')

    @app.route('/isolateDevice', methods=['POST'])
    def isolateDevice():
        mac = ''
        isolate = ''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                    mac = request.form['macAddress']
                if key == "isolate":
                    isolate = request.form['isolate']
        if len(mac) == 0:
            flash(u'MAC Address Missing For Device', 'error')
            return redirect('/')
        if len(isolate) == 0:
            flash(u'Missing isolate flag', 'error')
            return redirect('/')

        deviceQuery = {"query": {"match_phrase": {"mac": {"query": mac}}}}
        deviceInfo = es.search(esService, deviceQuery, 'sweet_security', 'devices')
        if deviceInfo is None:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 0:
            flash(u'Error finding device', 'error')
            return redirect('/')
        elif len(deviceInfo['hits']['hits']) == 1:
            for hit in deviceInfo['hits']['hits']:
                body = {'doc': {'isolate': isolate}}
                es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
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
        serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
        serverIP = serverIP[0]
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
                fwList=[]
                firstSeen = float(host['_source']['firstSeen']) / 1000.0
                lastSeen = float(host['_source']['lastSeen']) / 1000.0
                deviceInfo={'hostname': host['_source']['hostname'],
                        'nickname': host['_source']['nickname'],
                        'ip': host['_source']['ip4'],
                        'mac': host['_source']['mac'],
                        'vendor': host['_source']['vendor'],
                        'ignore': str(host['_source']['ignore']),
                        'isolate': str(host['_source']['isolate']),
                        'defaultFwAction': host['_source']['defaultFwAction'],
                        'firstSeen': datetime.datetime.fromtimestamp(firstSeen).strftime('%Y-%m-%d %H:%M:%S'),
                        'lastSeen': datetime.datetime.fromtimestamp(lastSeen).strftime('%Y-%m-%d %H:%M:%S')}
                
                #portCountQuery = {"sort":[{ "port" : {"order" : "asc"}}],"query": {"match_phrase": {"mac": { "query": host['_source']['mac']}}}}
                portCountQuery = {"query": {"match_phrase": {"mac": { "query": host['_source']['mac']}}}}
                portInfo=es.search(esService, portCountQuery, 'sweet_security', 'ports')
                if portInfo is not None:
                    for port in portInfo['hits']['hits']:
                        portInfoTmp = port['_source']
                        time = datetime.datetime.fromtimestamp(float(port['_source']['lastSeen']) / 1000.)
                        time = time.strftime('%Y-%m-%d %H:%M')
                        portInfoTmp['lastSeen'] = time
                        portInfoTmp['port'] = int(portInfoTmp['port'])
                        portList.append(portInfoTmp)
                sortedPortList = sorted(portList, key=lambda k: k['port'])
                deviceInfo['portList']=sortedPortList

                lastPortScanQuery = {"sort": [{"@timestamp": {"order": "desc"}}], "query": {"bool": { "must": [{"match": {"ipAddress": host['_source']['ip4']}}, {"match": {"action": "Port scanning"}}]}}}
                lastPortScanInfo = es.search(esService, lastPortScanQuery, 'logstash-*', 'logs', 1)
                if lastPortScanInfo is not None:
                    if len(lastPortScanInfo['hits']['hits']) > 0:
                        lastPortScan = datetime.datetime.strptime(lastPortScanInfo['hits']['hits'][0]['_source']['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
                        lastPortScan = lastPortScan.strftime('%Y-%m-%d %H:%M')
                    else:
                        lastPortScan = 'Device has not been port scanned'
                else:
                    lastPortScan = 'Device has not been port scanned'
                deviceInfo['lastPortScan'] = lastPortScan

                fwQuery = {"query": {"match_phrase": {"mac": { "query": host['_source']['mac']}}}}
                fwData=es.search(esService, fwQuery, 'sweet_security', 'firewallProfiles')
                if  fwData is not None:
                    for entry in fwData['hits']['hits']:
                        fwList.append(entry['_source'])
                deviceInfo['fwList']=fwList

            deviceAlertCount = 0
            alertQuery = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"addressed": 0}},
                            {"match_phrase": {"mac": deviceInfo['mac']}}
                        ]
                    }
                }
            }
            allAlerts = es.search(esService, alertQuery, 'sweet_security_alerts', 'alerts')
            deviceAlertCount = allAlerts['hits']['total']
            for ssAlert in allAlerts['hits']['hits']:
                firstSeen = float(ssAlert['_source']['firstSeen']) / 1000.0
                humanDate = datetime.datetime.fromtimestamp(firstSeen).strftime('%Y-%m-%d %H:%M:%S')
                ssAlert['_source']['firstSeen'] = humanDate

            baseline = []
            knownHostQuery = {"query": {"match_phrase": {"mac": {"query": deviceInfo['mac']}}}}
            knownHostData = es.search(esService, knownHostQuery, 'tardis', 'known_hosts')
            for device in knownHostData['hits']['hits']:
                baseline.append({'type': 'ip', 'value': device['_source']['ip']})
            knownDnsQuery = {"query": {"match_phrase": {"mac": {"query": mac}}}}
            knownDnsData = es.search(esService, knownDnsQuery, 'tardis', 'known_dnsqueries')
            for query in knownDnsData['hits']['hits']:
                baseline.append({'type': 'dns', 'value': query['_source']['query']})
            knownHostQuery = {"query": {"match_phrase": {"mac": {"query": mac}}}}
            knownHostData = es.search(esService, knownHostQuery, 'tardis', 'known_websites')
            for url in knownHostData['hits']['hits']:
                baseline.append({'type': 'website', 'value': url['_source']['server_name']})

            if deviceAlertCount > 0:
                flash(u'There are %d alerts for this device' % deviceAlertCount, 'error')
                return render_template('device.html', serverIP=serverIP, deviceInfo=deviceInfo,
                                       alertCount=deviceAlertCount,alerts=allAlerts['hits']['hits'], baseline=baseline)
            else:
                return render_template('device.html', serverIP=serverIP, deviceInfo=deviceInfo, baseline=baseline)
        else:
            #This happens when the web component is still booting up and the ES index hasn't initialized
            #Sometimes we get two devices, we'll delete the old one and let the sensor send info on it's next update
            es.consolidate(mac,esService,'devices')
            #sleep for one second, otherwise ES doesn't have enough time to delete the duplicated record
            sleep(1)
            return redirect('/device/%s' % mac)

    @app.route('/updateFW', methods=['POST'])
    def updateFW():
        mac=''
        fwDest=''
        fwAction=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                    mac=request.form['macAddress']
                    mac=validators.convertMac(mac)
                if key == "destination":
                    fwDest=request.form['destination']
                if key == "action":
                    fwAction=request.form['action']
        if not validators.macAddress(mac):
            print "invalid mac"
            return redirect('/')
        if not validators.url(fwDest):
            #If it's *, then we'll update the defaultFwAction for the device, bypass validation
            if fwDest != "*":
                print "invalid destination"
                return redirect('/')
        if len(fwAction) == 0:
            print "invalid action, no action given"
            return redirect('/')
        if fwAction == "true":
            fwAction="ACCEPT"
        elif fwAction == "false":
            fwAction="DROP"
        else:
            print "unknown action"
            return redirect('/')
        if fwDest == '*':
            
            deviceQuery = {"query": {"match_phrase": {"mac": { "query": mac }}}}
            deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
            if deviceInfo is None:
                flash(u'Unknown device', 'error')
                return redirect('/')
            elif len(deviceInfo['hits']['hits']) == 0:
                flash(u'Unknown device', 'error')
                return redirect('/')
            elif len(deviceInfo['hits']['hits']) == 1:
                for hit in deviceInfo['hits']['hits']:
                    body = {'doc' : {'defaultFwAction': fwAction}}
                    es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
                #Have to delay the response so the refreshed page shows the new name
                sleep(1)
                flash(u'Device updated', 'success')
                return redirect('/')
            else:
                es.consolidate(mac,esService,'devices')
                sleep(1)
                deviceInfo=es.search(esService, deviceQuery, 'sweet_security', 'devices')
                for hit in deviceInfo['hits']['hits']:
                    body = {'doc' : {'defaultFwAction': fwAction}}
                    es.update(esService, body, 'sweet_security', 'devices', hit['_id'])
                #Have to delay the response so the refreshed page shows the new name
                sleep(1)
                flash(u'Device updated', 'success')
            
        else:
            fwData={'mac': mac,
                    'destination': fwDest,
                    'action': fwAction}
            fwQuery={"query":{"bool":{"must":[{"match":{"mac": mac }},{ "match": { "destination": fwDest }}]}}}
            exists=es.search(esService,fwQuery,'sweet_security','firewallProfiles')
            if len(exists['hits']['hits']) == 0:
                es.write(esService, fwData, 'sweet_security', 'firewallProfiles')
                sleep(1)
        return "true"

    @app.route('/deleteFW', methods=['POST'])
    def deleteFW():
        mac=''
        fwDest=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "macAddress":
                    mac=request.form['macAddress']
                    mac=validators.convertMac(mac)
                if key == "destination":
                    fwDest=request.form['destination']
        if not validators.macAddress(mac):
            print "invalid mac"
            return redirect('/')
        if not validators.url(fwDest):
            print "invalid destination"
            return redirect('/')
        fwQuery={"query":{"bool":{"must":[{"match":{"mac": mac }},{ "match": { "destination": fwDest }}]}}}
        exists=es.search(esService,fwQuery,'sweet_security','firewallProfiles')
        if len(exists['hits']['hits']) > 0:
            es.delete(esService, 'sweet_security', 'firewallProfiles', exists['hits']['hits'][0]['_id'])
            sleep(1)
        return "true"


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
                      'version': version,
                      'lastSeen': str(int(round(time.time() * 1000)))}
            es.write(esService, portData, 'sweet_security', 'ports')
            return jsonify(status='success',reason='Port added')
        elif len(portInfo['hits']['hits']) == 0:
            portData={'port': (port),
                      'protocol': protocol,
                      'name': name,
                      'mac': mac,
                      'product': product,
                      'version': version,
                      'lastSeen': str(int(round(time.time() * 1000)))}
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
            body = {'doc': {'lastSeen': str(int(round(time.time() * 1000)))}}
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
                fwQuery = {"query": {"match_phrase": {"mac": { "query": host['_source']['mac']}}}}
                fwData=es.search(esService, fwQuery, 'sweet_security', 'firewallProfiles')
                fwList=[]
                if len(fwData['hits']['hits']) > 0:
                    for entry in fwData['hits']['hits']:
                        fwInfo={'action': entry['_source']['action'],'destination': entry['_source']['destination']}
                        fwList.append(fwInfo)
                if host['_source']['defaultFwAction'] == 'ACCEPT':
                    fwInfo={'action': 'ACCEPT','destination': '*'}
                else:
                    fwInfo={'action': 'DROP','destination': '*'}
                fwList.append(fwInfo)
                deviceInfo={'hostname': host['_source']['hostname'],
                        'nickname': host['_source']['nickname'],
                        'ip': host['_source']['ip4'],
                        'mac': host['_source']['mac'],
                        'vendor': host['_source']['vendor'],
                        'ignore': str(host['_source']['ignore']),
                        'firewall': fwList,
                        'isolate': str(host['_source']['isolate']),
                        'firstSeen': host['_source']['firstSeen'],
                        'lastSeen': host['_source']['lastSeen']}
                deviceList.append(deviceInfo)
        return jsonify(deviceList=deviceList)

    @app.route('/sensorHealth', methods=['POST'])
    def sensorHealth():
        sensorMac = ''
        sensorHostname = ''
        broHealth = ''
        logstashHealth = ''
        diskUsage = 0
        memConsumed = 0
        memAvailable = 0
        memPercent = 0
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "sensorMac":
                    sensorMac = request.form['sensorMac']
                if key == "sensorName":
                    sensorName = request.form['sensorName']
                if key == "broHealth":
                    broHealth = request.form['broHealth']
                if key == "logstashHealth":
                    logstashHealth = request.form['logstashHealth']
                if key == "diskUsage":
                    diskUsage = request.form['diskUsage']
                if key == "memConsumed":
                    memConsumed = request.form['memConsumed']
                if key == "memAvailable":
                    memAvailable = request.form['memAvailable']
                if key == "memPercent":
                    memPercent = request.form['memPercent']
        if len(sensorMac) == 0:
            print "unknown sensor mac"
            flash(u'Unknown Sensor MAC', 'error')
            return redirect('/')
        if len(sensorName) == 0:
            print "unknown sensor"
            flash(u'Unknown Sensor Name', 'error')
            return redirect('/settings')
        if len(broHealth) == 0:
            print "unknown bro health"
            flash(u'Unknown Bro Health', 'error')
            return redirect('/settings')
        if len(logstashHealth) == 0:
            print "unknown logstash health"
            flash(u'Unknown Logstash Health', 'error')
            return redirect('/settings')
        if len(diskUsage) == 0:
            print "unknown diskUsage"
            flash(u'Unknown Disk Usage', 'error')
            return redirect('/settings')
        if len(memConsumed) == 0:
            print "unknown memConsumed"
            flash(u'Unknown Memory Consumed', 'error')
            return redirect('/settings')
        if len(memAvailable) == 0:
            print "unknown memAvailable"
            flash(u'Unknown Memory Available', 'error')
            return redirect('/settings')
        if len(memPercent) == 0:
            print "unknown memPercent"
            flash(u'Unknown Memory Percent', 'error')
            return redirect('/settings')
        healthInfo = {'mac': sensorMac,
                      'sensorName': sensorName,
                      'broHealth': broHealth,
                      'logstashHealth': logstashHealth,
                      'diskUsage': diskUsage,
                      'memAvailable': memAvailable,
                      'memConsumed': memConsumed,
                      'memPercent': memPercent,
                      'firstSeen': str(int(round(time.time() * 1000))),
                      'lastSeen': str(int(round(time.time() * 1000)))}
        sensorStatus = 'Unknown'
        sensorQuery = {"query": {"match_phrase": {"mac": {"query": sensorMac}}}}
        sensorInfo = es.search(esService, sensorQuery, 'sweet_security', 'sensors')
        if sensorInfo is None:
            # First Ever Device
            sensorStatus = 'First Ever'
            es.write(esService, healthInfo, 'sweet_security', 'sensors')
            # emailBody = render_template('emails/addDevice.html', deviceInfo=newDeviceData, serverIP=serverIP)
            # email.emailUser(mail,"New Device Found",recipient,emailBody)
        elif len(sensorInfo['hits']['hits']) == 0:
            # newDevice
            sensorStatus = 'New Sensor'
            es.write(esService, healthInfo, 'sweet_security', 'sensors')
            # emailBody = render_template('emails/addDevice.html', deviceInfo=newDeviceData, serverIP=serverIP)
            # email.emailUser(mail,"New Device Found",recipient,emailBody)
        elif len(sensorInfo['hits']['hits']) == 1:
            # update Sensor
            body = {'doc': {'lastSeen': str(int(round(time.time() * 1000))),
                            'sensorName': sensorName,
                            'broHealth': broHealth,
                            'logstashHealth': logstashHealth,
                            'diskUsage': diskUsage,
                            'memAvailable': memAvailable,
                            'memConsumed': memConsumed,
                            'memPercent': memPercent
                            }
                    }
            es.update(esService, body, 'sweet_security', 'sensors', sensorInfo['hits']['hits'][0]['_id'])
            sensorStatus = 'Update Sensor'
        else:
            # need to consolidate then update
            sensorStatus = 'Consolidate Sensors'
            es.consolidate(sensorMac, esService, 'sensors')
        return jsonify(healthInfo=healthInfo, sensorStatus=sensorStatus)

    @app.route('/settings')
    def settings():
        # So we can link to kibana
        serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
        serverIP = serverIP[0]
        elasticHealth = os.popen('service elasticsearch status').read()
        for line in elasticHealth.splitlines():
            if line.lstrip().startswith('Active: '):
                if line.lstrip().startswith('Active: active (running)'):
                    elasticHealth = 'Started'
                else:
                    elasticHealth = 'Stopped'
        kibanaHealth = os.popen('service kibana status').read()
        for line in kibanaHealth.splitlines():
            if line.lstrip().startswith('Active: '):
                if line.lstrip().startswith('Active: active (running)'):
                    kibanaHealth = 'Started'
                else:
                    kibanaHealth = 'Stopped'

        diskUsage = 0
        diskUsageCommand = os.popen('df -k "/"').read()
        for line in diskUsageCommand.splitlines():
            line = line.split()
            if line[0] != 'Filesystem':
                diskUsage = int(line[4][:-1])

        memUsage = {'available': 0, 'consumed': 0, 'percentUsed': 0}
        memInfo = os.popen('free -t -m').read()
        for line in memInfo.splitlines():
            if line.rstrip().startswith('Mem:'):
                memUsage['available'] = line.split()[1]
                memUsage['consumed'] = line.split()[2]
                memUsage['percentUsed'] = int(round((float(line.split()[2]) / float(line.split()[1])) * 100, 0))

        ssServerStatus = 'Unknown'
        serverStatus = os.popen('service sweetsecurity_server status').read()
        for line in serverStatus.splitlines():
            if line.lstrip().startswith('Active: '):
                if line.lstrip().startswith('Active: active (running)'):
                    ssServerStatus = 'Started'
                else:
                    ssServerStatus = 'Stopped'

        defaultMonitor = 0
        defaultIsolate = 0
        defaultFW = 0
        defaultLogRetention = 0
        # Get Configuration Settings
        matchAll = {"query": {"match_all": {}}}
        ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
        if ssConfig is not None:
            for config in ssConfig['hits']['hits']:
                defaultMonitor = config['_source']['defaultMonitor']
                defaultIsolate = config['_source']['defaultIsolate']
                defaultFW = config['_source']['defaultFW']
                defaultLogRetention = config['_source']['defaultLogRetention']

        # Get the system status info for every sensor sending data
        sensorInfo = []
        matchAll = {"query": {"match_all": {}}}
        allSensors = es.search(esService, matchAll, 'sweet_security', 'sensors')
        if allSensors is not None:
            for sensor in allSensors['hits']['hits']:
                lastSeenTime = int(sensor['_source']['lastSeen']) / 1000
                timeSince = (int(datetime.datetime.now().strftime("%s")) * 1000) - int(sensor['_source']['lastSeen'])
                systemInfo = {
                    'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lastSeenTime)),
                    'timeSince': int(timeSince / 1000) / 60,
                    'sensorName': sensor['_source']['sensorName'],
                    'sensorMac': sensor['_source']['mac'],
                    'logstash': sensor['_source']['logstashHealth'],
                    'broStatus': sensor['_source']['broHealth'],
                    'diskUsage': int(sensor['_source']['diskUsage']),
                    'memInstalled': int(sensor['_source']['memAvailable']),
                    'memConsumed': int(sensor['_source']['memConsumed']),
                    'memPercent': int(sensor['_source']['memPercent'])
                }
                sensorInfo.append(systemInfo)
        alertQuery = {"query": {"match_phrase": {"addressed": {"query": 0}}}}
        allAlerts = es.search(esService, alertQuery, 'sweet_security_alerts', 'alerts')
        if allAlerts['hits']['total'] > 0:
            flash(u'There are %d new alerts!' % allAlerts['hits']['total'], 'error')
            alertCount = allAlerts['hits']['total']
            return render_template('settings.html', serverIP=serverIP, esHealth=elasticHealth, kHealth=kibanaHealth,
                               diskUsage=diskUsage, memUsage=memUsage, sensorInfo=sensorInfo, defaultFW=defaultFW,
                               defaultIsolate=defaultIsolate, defaultMonitor=defaultMonitor,
                               defaultLogRetention=defaultLogRetention, alertCount=alertCount,
                               ssServerStatus=ssServerStatus)
        else:
            return render_template('settings.html', serverIP=serverIP, esHealth=elasticHealth, kHealth=kibanaHealth,
                                   diskUsage=diskUsage, memUsage=memUsage, sensorInfo=sensorInfo, defaultFW=defaultFW,
                                   defaultIsolate=defaultIsolate, defaultMonitor=defaultMonitor,
                                   defaultLogRetention=defaultLogRetention, ssServerStatus=ssServerStatus)

    @app.route('/settings/modify', methods=['POST'])
    def settingsModify():
        settingID=''
        setting=''
        value=''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "setting":
                     setting=request.form['setting']
                if key == "value":
                     value=request.form['value']
        if setting == 'monitor':
            matchAll = {"query": {"match_all": {}}}
            ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
            if ssConfig is not None:
                for config in ssConfig['hits']['hits']:
                    settingID=config['_id']
            if value == 'Yes':
                body = {'doc' : {'defaultMonitor': 0}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == 'No':
                body = {'doc' : {'defaultMonitor': 1}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            else:
                return "Unknown value"
            sleep(1)
            return "Default monitor changed"
        if setting == 'isolate':
            matchAll = {"query": {"match_all": {}}}
            ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
            if ssConfig is not None:
                for config in ssConfig['hits']['hits']:
                    settingID=config['_id']
            if value == 'Yes':
                body = {'doc' : {'defaultIsolate': 1}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == 'No':
                body = {'doc' : {'defaultIsolate': 0}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            else:
                return "Unknown value"
            sleep(1)
            return "Default isolate changed"
        if setting == 'fw':
            matchAll = {"query": {"match_all": {}}}
            ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
            if ssConfig is not None:
                for config in ssConfig['hits']['hits']:
                    settingID=config['_id']
            if value == 'Allow':
                body = {'doc' : {'defaultFW': 1}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == 'Block':
                body = {'doc' : {'defaultFW': 0}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            else:
                return "Unknown value"
            sleep(1)
            return "Default fw changed"
        if setting == 'logRetention':
            matchAll = {"query": {"match_all": {}}}
            ssConfig = es.search(esService, matchAll, 'sweet_security', 'configuration')
            if ssConfig is not None:
                for config in ssConfig['hits']['hits']:
                    settingID=config['_id']
            if value == '7':
                body = {'doc' : {'defaultLogRetention': 7}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == '14':
                body = {'doc' : {'defaultLogRetention': 14}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == '30':
                body = {'doc' : {'defaultLogRetention': 30}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == '90':
                body = {'doc' : {'defaultLogRetention': 90}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == '180':
                body = {'doc' : {'defaultLogRetention': 180}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            elif value == '0':
                body = {'doc' : {'defaultLogRetention': 0}}
                es.update(esService, body, 'sweet_security', 'configuration', settingID)
            else:
                return "Unknown value"
            sleep(1)
        else:
            return "Unknown setting"
        return "Settings Modified"

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
        elif serviceName=="sweetsecurity_server":
            if action == "start":
                os.popen('sudo service sweetsecurity_server start').read()
            elif action == "restart":
                os.popen('sudo service sweetsecurity_server restart').read()
            elif action == "stop":
                os.popen('sudo service sweetsecurity_server stop').read()
            else:
                return "unknown action"
        return "unknown service"
        return "unknown service"


    @app.route('/deleteSensor', methods=['POST'])
    def deleteSensor():
        sensorMac = ''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "sensorMac":
                    sensorMac = request.form['sensorMac']
        if len(sensorMac) == 0:
            print "unknown sensor"
            flash(u'Unknown Sensor Name', 'error')
            return redirect('/settings')
        sensorInfo = []
        sensorQuery = {"query": {"match_phrase": {"mac": {"query": sensorMac}}}}
        sensorHostData = es.search(esService, sensorQuery, 'sweet_security', 'sensors')
        for sensor in sensorHostData['hits']['hits']:
            es.delete(esService, sensor['_index'], 'sensors', sensor['_id'])
        #Sleep so the reload will show OK
        sleep(1)
        flash(u'Sensor Deleted', 'success')
        return redirect('/settings')

    @app.route('/consolidateDevices')
    def consolidateDevices():
        matchAll = {"query": {"match_all": {}}}
        allDevices=es.search(esService, matchAll, 'sweet_security', 'devices')
        if allDevices is not None:
            for host in allDevices['hits']['hits']:
                es.consolidate(host['_source']['mac'],esService,'devices')
        flash(u'Devices Consolidated', 'success')
        return redirect('/settings')

    @app.route('/alerts/add', methods=['POST'])
    def alertAdd():
        alertType = ''
        alertMessage = ''
        logID = ''
        logIndex = ''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "alertType":
                    alertType = request.form['alertType']
                if key == "alertMessage":
                    alertMessage = request.form['alertMessage']
                if key == "logID":
                    logID = request.form['logID']
                if key == "logIndex":
                    logIndex = request.form['logIndex']
        if len(alertType) == 0:
            statusMessage='Unknown Alert Type'
            return jsonify(status='404',message=statusMessage)
        if len(alertMessage) == 0:
            statusMessage='Blank Message'
            return jsonify(status='404',message=statusMessage)
        alertInfo = {'source': alertType,
                     'message': alertMessage,
                     'firstSeen': str(int(round(time.time() * 1000))),
                     'addressed': 0}
        if len(logID) > 0:
            res = esService.get(index=logIndex, doc_type='logs', id=logID)
            resp_p=''
            orig_p=''
            website=''
            resp_h=res['_source']['resp_h']
            orig_h=res['_source']['orig_h']
            fileName=''
            fileMD5=''
            fileSHA1=''
            try:
                resp_p=res['_source']['resp_p']
                orig_p=res['_source']['orig_p']
            except: pass
            if res['_source']['path'] == '/opt/nsm/bro/logs/current/dns.log':
                website=res['_source']['query']
            elif res['_source']['path'] == '/opt/nsm/bro/logs/current/http.log' or res['_source']['path'] == '/opt/nsm/bro/logs/current/ssl.log':
                website=res['_source']['server_name']
            if res['_source']['path'] == '/opt/nsm/bro/logs/current/files.log':
                fileName=res['_source']['filename']
                fileMD5=res['_source']['md5']
                fileSHA1=res['_source']['sha1']
            logInfo={'resp_p': resp_p,
                     'resp_h': resp_h,
                     'orig_p': orig_p,
                     'orig_h': orig_h,
                     'website': website,
                     'filename': fileName,
                     'fileMD5': fileMD5,
                     'fileSHA1': fileSHA1}
            internalDeviceInfo = {}
            deviceQuery = {"query": {"match_phrase": {"ip4": {"query": orig_h}}}}
            deviceInfo = es.search(esService, deviceQuery, 'sweet_security', 'devices')
            for device in deviceInfo['hits']['hits']:
                internalDeviceInfo = {'vendor': device['_source']['vendor'],
                                      'mac': device['_source']['mac'],
                                      'nickname': device['_source']['nickname']}
                alertInfo['mac'] = device['_source']['mac']
        else:
            logInfo={}
            internalDeviceInfo={}
            alertInfo['mac'] = 'system'
        es.write(esService, alertInfo, 'sweet_security_alerts', 'alerts')
        email.emailUser(mail,"New Sweet Security Alert",recipient,alertMessage)
        return jsonify(status='200',alertType=alertType,alertMessage=alertMessage,logInfo=logInfo,internalDeviceInfo=internalDeviceInfo)

    @app.route('/alerts')
    def alerts():
        serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
        serverIP = serverIP[0]
        alertQuery = {"query": {"match_phrase": {"addressed": {"query": 0}}}}
        allAlerts = es.search(esService, alertQuery, 'sweet_security_alerts', 'alerts')
        alertCount=allAlerts['hits']['total']
        myAlerts=[]
        for ssAlert in allAlerts['hits']['hits']:
            firstSeen = float(ssAlert['_source']['firstSeen']) / 1000.0
            humanDate = datetime.datetime.fromtimestamp(firstSeen).strftime('%Y-%m-%d %H:%M:%S')
            ssAlert['_source']['firstSeen'] = humanDate
            myAlerts.append(ssAlert)
        if alertCount==0:
            return render_template('alerts.html', serverIP=serverIP, myAlerts=myAlerts)
        else:
            return render_template('alerts.html', alertCount=alertCount, serverIP=serverIP, myAlerts=myAlerts)

    @app.route('/alerts/address', methods=['POST'])
    def alertsAddress():
        logID = ''
        f = request.form
        for key in f.keys():
            for value in f.getlist(key):
                if key == "logID":
                    logID = request.form['logID']
        if len(logID) == 0:
            return jsonify(status='404',message='Unknown log id')
        print logID
        body = {'doc': {'addressed': 1}}
        es.update(esService, body, 'sweet_security_alerts', 'alerts', logID)
        body = {'doc': {'addressedDate': str(int(round(time.time() * 1000)))}}
        es.update(esService, body, 'sweet_security_alerts', 'alerts', logID)
        return jsonify(logID=logID)

    @app.route('/alerts/addressed')
    def alertsAddressed():
        serverIP = re.search(r'^https?://([\w\d\.\-]+)', request.url).groups()
        serverIP = serverIP[0]
        alertQuery = {"query": {"match_phrase": {"addressed": {"query": 1}}}}
        allAlerts = es.search(esService, alertQuery, 'sweet_security_alerts', 'alerts')
        myAlerts = []
        for ssAlert in allAlerts['hits']['hits']:
            firstSeen = float(ssAlert['_source']['firstSeen']) / 1000.0
            firstHumanDate = datetime.datetime.fromtimestamp(firstSeen).strftime('%Y-%m-%d %H:%M:%S')
            ssAlert['_source']['firstSeen'] = firstHumanDate
            addressedDate = float(ssAlert['_source']['addressedDate']) / 1000.0
            addressedHumanDate = datetime.datetime.fromtimestamp(addressedDate).strftime('%Y-%m-%d %H:%M:%S')
            ssAlert['_source']['addressedDate'] = addressedHumanDate
            myAlerts.append(ssAlert)
        alertQuery = {"query": {"match_phrase": {"addressed": {"query": 0}}}}
        adressedAlerts = es.search(esService, alertQuery, 'sweet_security_alerts', 'alerts')
        alertCount = adressedAlerts['hits']['total']
        if alertCount==0:
            return render_template('addressedAlerts.html', serverIP=serverIP, myAlerts=myAlerts)
        else:
            return render_template('addressedAlerts.html', alertCount=alertCount, serverIP=serverIP, myAlerts=myAlerts)

    @app.errorhandler(CSRFError)
    #@csrf.error_handler
    def csrf_error(reason):
        return jsonify(reason=reason)

    return app

