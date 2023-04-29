import argparse
import logging
import os
import pwd

W = '\033[0m'
R = '\033[31m'
G = '\033[32m'

def permissions():
    logging.info('Checking access...')
    if not os.geteuid() == 0:
        logging.warning('Run IoT4rMor as root!!!')
        exit(1)
    logging.info(G+'Permissions Verified'+W)


def back_2_user():
    os.setuid(pwd.getpwuid(os.getuid())[2])

def test_args(arg, key):

    if arg == None:
        return False
    for i in arg[0].split(','):
        if i.upper() == key.upper() or i.upper() == 'ALL':
            return True
    return False


def check_args(args):
    brute_choices=["SSH", "ALL", "TELNET", "FTP", "HTTP", "NONE"]
    if args.bruteforce is not None:
        for a in args.bruteforce[0].split(','):
            if a.upper() not in brute_choices:
                raise ValueError('Invalid Bruteforce choice: %s' % args.bruteforce)

    expl_choices=["DVR", "ROM0", "CISCOPVC", "DLINK", "HUMAX", "TVIP", "NONE", "ALL"]
    if args.exploits is not None:
        for a in args.exploits[0].split(','):
            if a.upper() not in expl_choices:
                raise ValueError('Invalid exploits choice: %s' % args.bruteforce)


    numeric_loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(format='%(levelname)s: %(message)s',
                        level=numeric_loglevel)


def make_report(findings, outfile):
    try:
        out = open(outfile, 'w')
        out.write('IP;Port;Service;Vulnerability;Tool;Info\n')
        for find in findings:
            out.write(find+'\n')
        out.close()
    except Exception:
        logging.warning(R+'Error while making report'+W)


def args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target",
                        help="Target list compatible with masscan range or a file with targets")
    parser.add_argument("-p", "--prefix", default="scan-",
                        help="Prefix for the masscan output files")
    parser.add_argument("-b", "--binary", default="masscan",
                        help="Masscan application path")
    parser.add_argument("-m", "--max-rate", type=int, default=100,
                        help="Masscan max rate in pps")
    parser.add_argument("-w", "--wait-time", type=int, default=30,
                        help="Masscan wait time")
    parser.add_argument("-d", "--out-dir", default="scan-results/",
                        help="Directory for the masscan output files")


    parser.add_argument("-E", "--exploits", action='append', default=None,
                        help="Test some IoT exploits. Choose one or more from 'ALL', 'DVR', 'ROM0', 'CISCOPVC', 'DLINK', 'HUMAX', "
                             "'TVIP'. See the README file for more info")


    parser.add_argument("-B", "--bruteforce", action='append', default=None,
                        help="Test some IoT Bruteforce. Choose one or more from 'ALL', 'SSH', 'FTP', 'HTTP', 'TELNET'. "
                             "See the README file for more info")
    parser.add_argument("-T", "--threads", type=int, default=3,
                        help="How many bruteforcing threads do you want?")


    parser.add_argument("-v", "--loglevel", default="INFO", help="Set log level", choices=[
        "DEBUG",
        "WARNING",
        "INFO"])

    parser.add_argument("-o", "--report-output", default="IoT4rmor-report.csv",
                        help="Name of the report file in CSV format")

    args = parser.parse_args()
    check_args(args)
    return args


def banner():
    os.system('cat src/logo')
    print('\n')
