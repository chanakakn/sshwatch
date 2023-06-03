#!/usr/bin/env python3
import re
import subprocess
import logging
import syslog

MAX_ATTEMPTS = 10  # Maximum permitted attempts

WATCH_FILE = '/var/log/messages'
IPTABLES = '/sbin/iptables'
IPTABLES_SAVE = '/sbin/iptables-save'
IPTABLES_RESTORE = '/sbin/iptables-restore'
CFG_FILE = '/etc/sysconfig/iptables'

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

def block_ip(ip):
    subprocess.run([IPTABLES, '-I', 'block', '-s', ip, '-j', 'DROP'], shell=True)
    subprocess.run([IPTABLES_SAVE, '>', CFG_FILE], shell=True)
    syslog.syslog(syslog.LOG_WARNING, f"IP {ip} has been blocked!")

try:
    with open(WATCH_FILE, 'r') as log_file:
        log_file.seek(0, 2)  # Move to the end of the file

        tries = {}      # Number of attempts per IP
        blocked = set() # Already blocked IPs

        # Restore iptables configuration
        subprocess.run([IPTABLES_RESTORE, '<', CFG_FILE], shell=True)

        # Load currently blocked IPs from iptables list
        block_chain = False
        iptables_output = subprocess.check_output([IPTABLES, '-L', '-v', '-n'])
        iptables_lines = iptables_output.decode().splitlines()

        for line in iptables_lines:
            if line.startswith('Chain block'):
                block_chain = True
            elif block_chain and line.strip() == '':
                break
            elif block_chain:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    blocked.add(match.group(1))

        blk_ips = ', '.join(blocked)
        syslog.syslog(syslog.LOG_WARNING, f"sshwatch.py started. Currently blocked IPs are: {blk_ips}")

        # Watch the messages file
        while True:
            where = log_file.tell()
            line = log_file.readline()
            if not line:
                log_file.seek(where)
            else:
                match = re.search(r'sshd\[\d+\]: Failed password for .+ from (\D+(\d+\.\d+\.\d+\.\d+))', line)
                if match:
                    ip = match.group(2)
                    if ip not in blocked:
                        tries[ip] = tries.get(ip, 0) + 1
                        if tries[ip] == MAX_ATTEMPTS:
                            try:
                                block_ip(ip)
                            except subprocess.CalledProcessError as e:
                                logging.error(f"Error blocking IP {ip}: {e}")
                            except Exception as e:
                                logging.error(f"An unexpected error occurred: {e}")

except FileNotFoundError as e:
    logging.error(f"File not found: {e}")
except PermissionError as e:
    logging.error(f"Permission denied: {e}")
except Exception as e:
    logging.error(f"An unexpected error occurred: {e}")
