import sys
import re
import collections
import matplotlib.pyplot as plt

fname = sys.argv[1]
#fname = 'access_logs.txt'
#fname = input('Enter name of log file:')

attacker_ip = sys.argv[2]
#attacker_ip = '112.204.10.15'
#attacker_ip = input('Enter target ip:')

log_regex = re.compile((r'(\d+\.\d+\.\d+\.\d+)\s'     #host ip
                       r'(\S+)\s'    #rfc1413
                       r'(\S+)\s'    #userid
                       r'\[(.*?)\]\s'    #time
                       r'"(.*?)"\s'    #http request
                       r'(\S+)\s'    #status code
                       r'(\S+)\s'    #size of object returned
                       r'"(.*?)"\s'    #referrer
                       r'"(.*?)"'))    #user-agent

status_list = ['1XX','2XX','3XX','4XX','5XX']
status_dict = {i:0 for i in status_list}

depth_dict = {}

#factor to check various ratios of inputs
start = 0
factor = 1

#initialize active_hrs_dict with 0 on all hours
active_hrs_dict = {}
for i in range(0,24):
    num = str(i)
    if i in range(0,10): num = '0'+num
    active_hrs_dict[num] = 0

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
        if log_segments[0] == attacker_ip and start%factor == 0:
            start = start + 1
            
            #count active hour frequencies
            hour = log_segments[3][12:14]
            active_hrs_dict[hour] = active_hrs_dict[hour] + 1
            
            #count status code frequencies
            status_code_full = log_segments[5]
            status_code = status_code_full[0] + 'XX'
            status_dict[status_code] = status_dict[status_code] + 1 
            
            #count the frequencies of all crawl depths
            http_request = log_segments[4]
            depth = http_request.count('/')
            if depth in depth_dict:
                depth_dict[depth] = depth_dict[depth] + 1
            else:
                depth_dict[depth] = 1
        else:
            start = start + 1

plt.subplot(2,2,1)
plt.title('Active Hours')
plt.bar(active_hrs_dict.keys(),active_hrs_dict.values())
plt.xlabel('Time of day')
plt.ylabel('Activity')
for (x,y) in list(active_hrs_dict.items()):
    if y == 0:continue
    plt.text(x,y+0.2,y,ha='center',fontsize=8)

plt.subplot(2,2,2)
plt.title('Ratio of successful responses codes')
plt.bar(status_dict.keys(),status_dict.values())
plt.xlabel('Status codes')
plt.ylabel('Frequencies')
for (x,y) in list(status_dict.items()):
    if y == 0:continue
    plt.text(x,y+0.2,y,ha='center',fontsize=8)

plt.subplot(2,2,3)
plt.title('Ratio of crawl depths')
plt.bar(depth_dict.keys(),depth_dict.values())
plt.xlabel('Crawl depth')
plt.ylabel('Frequency')
for (x,y) in list(depth_dict.items()):
    if y == 0:continue
    plt.text(x,y+0.2,y,ha='center',fontsize=8)

plt.show()
