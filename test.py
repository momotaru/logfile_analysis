import sys
import re
import collections
import pandas as pd
import matplotlib.pyplot as plt

#fname = sys.argv[1]
fname = 'access_logs.txt'

#attacker_ip = sys.argv[2]
#attarcker_ip = '112.204.10.15'
attacker_ip = input('Enter target ip:')

#log format
log_regex = re.compile((r'(\d+\.\d+\.\d+\.\d+)\s'     #host ip
                       r'(\S+)\s'    #rfc1413
                       r'(\S+)\s'    #userid
                       r'\[(.*?)\]\s'    #time
                       r'"(.*?)"\s'    #http request
                       r'(\S+)\s'    #status code
                       r'(\S+)\s'    #size of object returned
                       r'"(.*?)"\s'    #referrer
                       r'"(.*?)"'))    #user-agent

status_dict = {}
depth_dict = {}
user_os_dict = {}
time_dict = {}

#str list of day hours
hours = []
for i in range(0,24):
    if i < 10:
        hours.append('0'+str(i))
    else:
        hours.append(str(i))

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
            
            user_os = None
            #check user agent
            user_agent = log_segments[8]
            user_os_regex = re.compile(r'\((.*?);')
            found = re.search(user_os_regex,user_agent)
            if found:
                user_os = found.group(1)
            else:
                print(line)
            if user_os in user_os_dict:
                user_os_dict[user_os] = user_os_dict[user_os] + 1
            else:
                user_os_dict[user_os] = 1
                status_dict[user_os] = {}
                depth_dict[user_os] = {}
                time_dict[user_os] = {i:0 for i in hours}
                
            #count log hours for each os
            hour = log_segments[3][12:14]
            if user_os in time_dict:
                if hour in time_dict[user_os]:
                    time_dict[user_os][hour] = time_dict[user_os][hour] + 1
                else:
                    time_dict[user_os][hour] = 1
            else:
                time_dict[user_os][hour] = 1
            
            #count status code frequencies for each os
            status_code = log_segments[5]
            if user_os in status_dict:
                if status_code in status_dict[user_os]:
                    status_dict[user_os][status_code] = status_dict[user_os][status_code] + 1
                else:
                    status_dict[user_os][status_code] = 1
            else:
                status_dict[user_os][status_code] = 1
            
            #count http request depths for each os
            http_request = log_segments[4]
            depth = http_request.count('/') - 2
            if user_os in depth_dict:
                if depth in depth_dict[user_os]:
                    depth_dict[user_os][depth] = depth_dict[user_os][depth] + 1
                else:
                    depth_dict[user_os][depth] = 1
            else:
                depth_dict[user_os][depth] = 1

user_os_dict = collections.OrderedDict(sorted(user_os_dict.items()))
status_dict = collections.OrderedDict(sorted(status_dict.items()))
depth_dict = collections.OrderedDict(sorted(depth_dict.items()))

os_list = list(user_os_dict.keys())
nlist = len(os_list)

plt.bar(time_dict[os_list[0]].keys(),time_dict[os_list[0]].values())
for i in range(1,nlist):
    plt.bar(time_dict[os_list[i]].keys(),time_dict[os_list[i]].values(),bottom=list(time_dict[os_list[i-1]].values()))
    
plt.show()
