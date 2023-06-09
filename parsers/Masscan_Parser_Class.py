import re
import logging

W = '\033[0m'
R = '\033[31m'
G = '\033[32m'


reg1 = re.compile('^Timestamp: (?P<Timestamp>\d+)\tHost: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPort: (?P<Port>\d+)\tService: title\tBanner: (?P<Info>.*)$')
reg2 = re.compile('^Timestamp: (?P<Timestamp>\d+)\tHost: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPort: (?P<Port>\d+)\tService: vuln\tBanner: (?P<Info>.*)$')
reg3 = re.compile('^Timestamp: (?P<Timestamp>\d+)\tHost: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPorts: (?P<Port>\d+)/open/tcp////$')
reg4 = re.compile('^Timestamp: (?P<Timestamp>\d+)\tHost: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPort: (?P<Port>\d+)\tService: (?P<Service>\w+)\tBanner: (?P<Banner>.*)$')

reg5 = re.compile('^Host: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPort: (?P<Port>\d+)\tService: title\tBanner: (?P<Info>.*)$')
reg6 = re.compile('^Host: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPort: (?P<Port>\d+)\tService: vuln\tBanner: (?P<Info>.*)$')
reg7 = re.compile('^Host: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPorts: (?P<Port>\d+)/open/tcp////$')
reg8 = re.compile('^Host: (?P<IP>\d+.\d+.\d+.\d+) \(\)\tPort: (?P<Port>\d+)\tService: (?P<Service>\w+)\tBanner: (?P<Banner>.*)$')

class Masscan_Parser(object):
    def __init__(self, file):
        try:
            self.log = open(file,'r')
        except:
            logging.warning(R+'Error opening scan-result file, exiting...'+W)
            exit(1)

        self.insertDB = []


    def parse(self):
        index = 0
        error = 0
        if self.log != None:
            logging.info('Starting output parsing...')
            for line in self.log.readlines():
                index += 1

                if re.match(reg1, line):

                    res = reg1.search(line)
                    timestamp = res.group(1)
                    ip = res.group(2)
                    port = res.group(3)
                    info = res.group(4).strip('\t')
                    self.insertDB.append((index, timestamp, ip, port, ' ', ' ', info, ' '))

                elif re.match(reg2, line):

                    res = reg2.search(line)
                    timestamp = res.group(1)
                    ip = res.group(2)
                    port = res.group(3)
                    info = res.group(4).strip('\t')
                    self.insertDB.append((index, timestamp, ip, port, ' ', ' ', info, ' '))

                elif re.match(reg3, line):

                    res = reg3.search(line)
                    timestamp = res.group(1)
                    ip = res.group(2)
                    port = res.group(3)
                    self.insertDB.append((index, timestamp, ip, port, ' ', ' ', ' ', ' '))

                elif re.match(reg4, line):

                    res = reg4.search(line)
                    timestamp = res.group(1)
                    ip = res.group(2)
                    port = res.group(3)
                    service = res.group(4).strip('\t')
                    banner = res.group(5).strip('\t')
                    self.insertDB.append((index, timestamp, ip, port, service, banner, ' ', ' '))

                elif re.match(reg5, line):

                    res = reg5.search(line)
                    ip = res.group(1)
                    port = res.group(2)
                    info = res.group(3).strip('\t')
                    self.insertDB.append((index, ' ', ip, port, ' ', ' ', info, ' '))

                elif re.match(reg6, line):

                    res = reg6.search(line)
                    ip = res.group(1)
                    port = res.group(2)
                    info = res.group(3).strip('\t')
                    self.insertDB.append((index, ' ', ip, port, ' ', ' ', info, ' '))

                elif re.match(reg7, line):

                    res = reg7.search(line)
                    ip = res.group(1)
                    port = res.group(2)
                    self.insertDB.append((index, ' ', ip, port, ' ', ' ', ' ', ' '))

                elif re.match(reg8, line):

                    res = reg8.search(line)
                    ip = res.group(1)
                    port = res.group(2)
                    service = res.group(3).strip('\t')
                    banner = res.group(4).strip('\t')
                    self.insertDB.append((index, ' ', ip, port, service, banner, ' ', ' '))

                else:
                    error +=1
                    logging.debug('Error line: '+line)

        parsed = index - error
        logging.debug('Total line: ' + str(index) + ' Parsed line: ' + str(parsed) + ' Error line: ' + str(error))
        if len(self.insertDB) > 0:
            logging.info(G+'Parsing process completed!'+W)
            return self.insertDB
        else:
            logging.warning(R+'No Host found in scanning logfile, exiting...'+W)
            exit(1)
