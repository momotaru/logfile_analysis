import re
import csv
import sys

#txt_fname = sys.argv[1]
txt_fname = 'access_logs.txt'

#csv_fname = sys.argv[2]
csv_fname = 'logfile.csv'

log_regex = re.compile((r'(\d+\.\d+\.\d+\.\d+)\s'     #host ip
                       r'(\S+)\s'    #rfc1413
                       r'(\S+)\s'    #userid
                       r'\[(.*?)\]\s'    #time
                       r'"(.*?)"\s'    #http request
                       r'(\S+)\s'    #status code
                       r'(\S+)\s'    #size of object returned
                       r'"(.*?)"\s'    #referrer
                       r'"(.*?)"'))    #user-agent

header = ['Host IP','RFC1413','User ID','Date/Time','HTTP Request','Status Code','Size','Referrer','User agent']

with open(csv_fname,'w') as infile:
    csv_writer = csv.writer(infile)
    csv_writer.writerow(header)
    with open(txt_fname,'r') as infile:
        nlines = len(list(infile))
        infile.seek(0)
        
        for i in range(0,nlines):
            line = infile.readline()
            log_segments = re.match(log_regex,line).groups()
            csv_writer.writerow(log_segments)
