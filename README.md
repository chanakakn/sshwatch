# sshwatch

This script watches the system log file for dictionary sshd attacks and 
automaticaly block the attacker ip after specified number of attempts
before first use: 
 1. create a new iptables chain "block" : iptables -N block
 2. insert a rule in the input chain to send all input packages to "block":
    iptables -I INPUT -i eth0 -j block
 3. save your current iptables configuration: iptables-save > /etc/sysconfig/iptables
