import os
import logging

import alert
import es

from elasticsearch import Elasticsearch
esService = Elasticsearch()

def getLogs(ip,log):
    logQuery={
       "query":{
           "bool":{
                "must":[
                    {"match":{"orig_h": ip }},
                    {"match_phrase":{"path": log }},
                    {"range" : { "@timestamp" : {"gt" : "now-1h"}}}
                ]
            }
        }
    }
    logData=es.search(esService, logQuery, 'logstash-*', 'logs')
    return logData

def connSearch(ip,mac):
    numFound=0
    connData=getLogs(ip,'/opt/nsm/bro/logs/current/conn.log')
    knownHosts=[]
    knownHostQuery={"query": {"match_phrase": {"mac": { "query": mac }}}}
    knownHostData=es.search(esService, knownHostQuery, 'tardis', 'known_hosts')
    for device in knownHostData['hits']['hits']:
        if device['_source']['ip'] not in knownHosts:
            knownHosts.append(device['_source']['ip'])

    for log in connData['hits']['hits']:
        if log['_source']['resp_h'] not in knownHosts:
            numFound += 1
            knownHosts.append(log['_source']['resp_h'])
            hostData={'mac': mac, 'ip': log['_source']['resp_h']}
            es.write(esService, hostData, 'tardis', 'known_hosts')
            alertMessage='A new IP was added to the baseline: %s' % log['_source']['resp_h']
            alert.send('Baseliner',alertMessage,log['_id'],log['_index'])
    return numFound


def dnsSearch(ip,mac):
    numFound=0
    dnsData=getLogs(ip,'/opt/nsm/bro/logs/current/dns.log')
    knownQueries=[]
    knownDnsQuery={"query": {"match_phrase": {"mac": { "query": mac }}}}
    knownDnsData=es.search(esService, knownDnsQuery, 'tardis', 'known_dnsqueries')
    for query in knownDnsData['hits']['hits']:
        if query['_source']['query'] not in knownQueries:
            knownQueries.append(query['_source']['query'])
    for log in dnsData['hits']['hits']:
        if log['_source']['query'] not in knownQueries:
            numFound += 1
            knownQueries.append(log['_source']['query'])
            dnsData={'mac': mac, 'query': log['_source']['query']}
            es.write(esService, dnsData, 'tardis', 'known_dnsqueries')
            alertMessage='A new DNS query was added to the baseline: %s' % log['_source']['query']
            alert.send('Baseliner',alertMessage,log['_id'],log['_index'])
    return numFound

def httpSearch(ip,mac):
    numFound=0
    httpData=getLogs(ip,'/opt/nsm/bro/logs/current/http.log')
    knownWebsites=[]
    knownHostQuery={"query": {"match_phrase": {"mac": { "query": mac }}}}
    knownHostData=es.search(esService, knownHostQuery, 'tardis', 'known_websites')
    for url in knownHostData['hits']['hits']:
        if url['_source']['server_name'] not in knownWebsites:
            knownWebsites.append(url['_source']['server_name'])
    for log in httpData['hits']['hits']:
        if log['_source']['server_name'] not in knownWebsites:
            numFound += 1
            knownWebsites.append(log['_source']['server_name'])
            hostData={'mac': mac, 'server_name': log['_source']['server_name']}
            es.write(esService, hostData, 'tardis', 'known_websites')
            alertMessage='A new website was added to the baseline: %s' % log['_source']['server_name']
            alert.send('Baseliner',alertMessage,log['_id'],log['_index'])
    return numFound

def sslSearch(ip,mac):
    numFound=0
    sslData=getLogs(ip,'/opt/nsm/bro/logs/current/ssl.log')
    knownWebsites=[]
    knownHostQuery={"query": {"match_phrase": {"mac": { "query": mac }}}}
    knownHostData=es.search(esService, knownHostQuery, 'tardis', 'known_websites')
    for url in knownHostData['hits']['hits']:
        if url['_source']['server_name'] not in knownWebsites:
            knownWebsites.append(url['_source']['server_name'])
    for log in sslData['hits']['hits']:
        if log['_source']['server_name'] not in knownWebsites:
            numFound += 1
            knownWebsites.append(log['_source']['server_name'])
            hostData={'mac': mac, 'server_name': log['_source']['server_name']}
            es.write(esService, hostData, 'tardis', 'known_websites')
            alertMessage='A new website was added to the baseline: %s' % log['_source']['server_name']
            alert.send('Baseliner',alertMessage,log['_id'],log['_index'])
    return numFound

def run():
    logger = logging.getLogger('SweetSecurityServerLogger')
    logger.info('Running Baseliner')
    matchAll = {"query": {"match_all": {}}}

    #Create TARDIS index if it is missing
    tardisQuery=es.search(esService, matchAll, 'tardis', 'known_hosts')
    if tardisQuery is None:
        logger.info('Creating TARDIS Index')
        #print "Creating TARDIS Index"
        os.popen('curl -XPUT \'localhost:9200/tardis?pretty\' -H \'Content-Type: application/json\' -d\' {"mappings" : {"known_hosts" : {"properties" : { "mac" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}},"destination" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}},"port" : { "type" : "text", "fields": {"raw": {"type": "keyword"}}}}}}}\'').read()

    #Get List of Known Devices
    allDevices=es.search(esService, matchAll, 'sweet_security', 'devices')
    if allDevices is not None:
        for host in allDevices['hits']['hits']:
            logger.info("Searching Device %s(%s : %s)" % (host['_source']['nickname'],host['_source']['ip4'],host['_source']['mac']))
            logger.info("    Searching conn.log")
            conn=connSearch(host['_source']['ip4'],host['_source']['mac'])
            logger.info("      Found %d new entries" % conn)

            logger.info("    Searching dns.log")
            dns=dnsSearch(host['_source']['ip4'],host['_source']['mac'])
            logger.info("      Found %d new entries" % dns)

            logger.info("    Searching http.log")
            http=httpSearch(host['_source']['ip4'],host['_source']['mac'])
            logger.info("      Found %d new entries" % http)

            logger.info("    Searching ssl.log")
            ssl=sslSearch(host['_source']['ip4'],host['_source']['mac'])
            logger.info("      Found %d new entries" % ssl)



