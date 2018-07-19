import sys
import re
import pandas as pd
import matplotlib.pyplot as plt

#fname = sys.argv[1]
fname = 'access_logs.txt'

#attacker_ip = sys.argv[2]
#attarcker_ip = '112.204.10.15'
attacker_ip = input('Enter target ip:')

log_regex = re.compile((r'(\d+\.\d+\.\d+\.\d+)\s'     #host ip
                       r'(\S+)\s'    #rfc1413
                       r'(\S+)\s'    #userid
                       r'\[(.*?)\]\s'    #time
                       r'"(.*?)"\s'    #http request
                       r'(\S+)\s'    #status code
                       r'(\S+)\s'    #size of object returned
                       r'"(.*?)"\s'    #referrer
                       r'"(.*?)"'))    #user-agent

attacker_dict = {}
crawl_dict = {}
ua_dict = {}

access_dict = {}
for i in range(0,24):
    access_dict[str(i)] = 0

time_series = []

with open(fname,'r') as infile:
    nlines = len(list(infile))
    
    #apparently list(infile) takes it to end of file 
    infile.seek(0)
    
    for i in range(0,nlines):
        line = infile.readline()
        
        #segment the parts of each log entry
        found = re.match(log_regex,line)
        if found:
            log_segments = found.groups()
        else:
            print(line)
            
        #check if the host ip matches our target's ip
        if log_segments[0] == attacker_ip:
            
            #extract time series
            time_series.append(log_segments[3])
            
            #count the frequencies of all status codes
            status_code = log_segments[5]
            if status_code in attacker_dict:
                attacker_dict[status_code] = attacker_dict[status_code] + 1
            else:
                attacker_dict[status_code] = 1
            
            #count the frequencies of all crawl depths
            http_request = log_segments[4]
            depth = http_request.count('/')
            if depth in crawl_dict:
                crawl_dict[depth] = crawl_dict[depth] + 1
            else:
                crawl_dict[depth] = 1
                
            #count the frequencies of all user agents
            user_agent = log_segments[8]
            ua_machine_regex = re.compile(r'\((.*?);')
            found = re.search(ua_machine_regex,user_agent)
            if found:
                ua_machine = found.group(1)
            else:
                print(line)
            if ua_machine in ua_dict:
                ua_dict[ua_machine] = ua_dict[ua_machine] + 1
            else:
                ua_dict[ua_machine] = 1

for each in time_series:
    hour = each[12:14]
    if hour in access_dict:
        access_dict[hour] = access_dict[hour] + 1
    else:
        access_dict[hour] = 1

plt.bar(access_dict.keys(),access_dict.values())
plt.xlabel('Time of day')
plt.ylabel('Activity')
plt.show()

plt.bar(attacker_dict.keys(),attacker_dict.values())
plt.xlabel('Status codes')
plt.ylabel('Frequencies')
plt.show()

plt.bar(crawl_dict.keys(),crawl_dict.values())
plt.xlabel('Crawl depth')
plt.ylabel('Frequencies')
plt.show()

plt.bar(ua_dict.keys(),ua_dict.values())
plt.xlabel('User agent')
plt.ylabel('Frequencies')
plt.show()
