# Virtual-mail-on-Linux
Setting up and securing virtual mail on Linux

VIRTUAL MAIL SYSTEM

Virtual Mail System Components 
Postfix (Mail/SMTP Server, MTA) 
STARTTLS used for encryption 
SMTP AUTH (SASL) used for authentication 

Dovecot (IMAP/POP3 Server, MDA) 
(SSL/TLS) used for encryption 

MySql 
stores the domains and the virtual users 

Spam Filter (Rspamd/SpamAssassin)

Mail and DNS Requirements: 

1. An A record, to point the system’s FQDN to the mail server IPv4 address. mail.crystalmind.academy. IN A 206.81.X.X 

Command dig -t a mail.x.x

2. An MX record for the domain. 

@ IN MX 10 mail.crystalmind.academy. mail IN A 206.81.X.X 

Command dig -t mx mail.x.x

3. An SPF record for the domain 

crystalmind.academy. IN TXT "v=spf1 mx ~all" 

Command dig -t txt mail.x.x

4. A PTR Record (Reverse DNS)

Command dig -x ip_address

Command hostnamectl shows all parameters for the hostname

To change hostname hostnamectl set-hostname [host_name]

Edit the vi /etc/hosts and replace the hostname

Checking pre-requisite

Systemctl status bind9

Dig -t mx [mail address}

Dig -x ipaddress of server

Systemctl status mysql

Ls -l /etc/letsencrypt/live/webaddress

1. Installing Software Packages

apt update && apt install postfix postfix-mysql postfix-doc dovecot-common dovecot-imapd dovecot-pop3d libsasl2-2 libsasl2-modules libsasl2-modules-sql sasl2-bin libpam-mysql mailutils dovecot-mysql dovecot-sieve dovecot-managesieved


2. Configuring MySql and Connect it With Postfix

mysql -u root

mysql> CREATE DATABASE mail;

mysql> USE mail;

mysql> CREATE USER 'mail_admin'@'localhost' IDENTIFIED BY 'mail_admin_password';  

mysql> GRANT SELECT, INSERT, UPDATE, DELETE ON mail.* TO 'mail_admin'@'localhost';

mysql> FLUSH PRIVILEGES;

mysql> CREATE TABLE domains (domain varchar(50) NOT NULL, PRIMARY KEY (domain));

mysql> CREATE TABLE users (email varchar(80) NOT NULL, password varchar(128) NOT NULL, PRIMARY KEY (email));

mysql> CREATE TABLE forwardings (source varchar(80) NOT NULL, destination TEXT NOT NULL, PRIMARY KEY (source));

mysql> exit


3. Configuring Postfix to communicate with MySql

a) vim /etc/postfix/mysql_virtual_domains.cf 

user = mail_admin

password = mail_admin_password

dbname = mail

query = SELECT domain FROM domains WHERE domain='%s'

hosts = 127.0.0.1

b) vim /etc/postfix/mysql_virtual_forwardings.cf

user = mail_admin

password = mail_admin_password

dbname = mail

query = SELECT destination FROM forwardings WHERE source='%s'

hosts = 127.0.0.1

c) vim /etc/postfix/mysql_virtual_mailboxes.cf

user = mail_admin

password = mail_admin_password

dbname = mail

query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM users WHERE email='%s'

hosts = 127.0.0.1


d) vim /etc/postfix/mysql_virtual_email2email.cf 

user = mail_admin

password = mail_admin_password

dbname = mail

query = SELECT email FROM users WHERE email='%s'

hosts = 127.0.0.1

e) Setting the ownership and permissions

chmod o-rwx /etc/postfix/mysql_virtual_*

chown root.postfix /etc/postfix/mysql_virtual_*



4. Creating a user and group for mail handling

groupadd -g 5000 vmail

useradd -g vmail -u 5000 -d /var/vmail -m vmail


5. Configuring postfix

postconf -e "myhostname = mail.crystalmind.academy"

postconf -e "mydestination = mail.crystalmind.academy, localhost, localhost.localdomain"

postconf -e "mynetworks = 127.0.0.0/8"

postconf -e "message_size_limit = 31457280"

postconf -e "virtual_alias_domains ="

postconf -e "virtual_alias_maps = proxy:mysql:/etc/postfix/mysql_virtual_forwardings.cf, mysql:/etc/postfix/mysql_virtual_email2email.cf"

postconf -e "virtual_mailbox_domains = proxy:mysql:/etc/postfix/mysql_virtual_domains.cf"

postconf -e "virtual_mailbox_maps = proxy:mysql:/etc/postfix/mysql_virtual_mailboxes.cf"

postconf -e "virtual_mailbox_base = /var/vmail"

postconf -e "virtual_uid_maps = static:5000"

postconf -e "virtual_gid_maps = static:5000"

postconf -e "smtpd_sasl_auth_enable = yes"

postconf -e "broken_sasl_auth_clients = yes"

postconf -e "smtpd_sasl_authenticated_header = yes"

postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"

postconf -e "smtpd_use_tls = yes"

postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/crystalmind.academy/fullchain.pem"

postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/crystalmind.academy/privkey.pem"

postconf -e "virtual_transport=dovecot"

postconf -e 'proxy_read_maps = $local_recipient_maps $mydestination $virtual_alias_maps $virtual_alias_domains $virtual_mailbox_maps 

$virtual_mailbox_domains $relay_recipient_maps $relay_domains $canonical_maps $sender_canonical_maps $recipient_canonical_maps $relocated_maps 

$transport_maps $mynetworks $virtual_mailbox_limit_maps'

SMTP AUTH (SASLAUTHD with PAM and MySql) 

The original SMTP did not provide any form of authentication. 

SMTP Authentication (SMTP AUTH) is an extension of the SMTP whereby a client may log in using an authentication mechanism supported by the server. 

SMTP AUTH is implemented by something called SASL (Simple Authentication and Security Layer). 

The SASL implementation for Postfix uses either a library called Cyrus SASL or Dovecot SASL. Check support: postconf -a 

The application that handles SASL is called SASL Authentication Daemon or saslauthd. 

PAM (Pluggable Authentication Modules) provides authentication for saslauthd. It practically says how to access the MySql backend.

6. Configuring SMTP AUTH (SASLAUTHD and MySql)

a) Creating a directory where saslauthd will save its information:  

mkdir -p /var/spool/postfix/var/run/saslauthd

b) Editing the configuration file of saslauthd: vim /etc/default/saslauthd

START=yes

DESC="SASL Authentication Daemon"

NAME="saslauthd"

MECHANISMS="pam"

MECH_OPTIONS=""

THREADS=5

OPTIONS="-c -m /var/spool/postfix/var/run/saslauthd -r"

c) Creating a new file: vim /etc/pam.d/smtp

auth required pam_mysql.so user=mail_admin passwd=mail_admin_password host=127.0.0.1 db=mail table=users usercolumn=email passwdcolumn=password crypt=3
account sufficient pam_mysql.so user=mail_admin passwd=mail_admin_password host=127.0.0.1 db=mail table=users usercolumn=email passwdcolumn=password crypt=3

d) vim /etc/postfix/sasl/smtpd.conf

pwcheck_method: saslauthd 

mech_list: plain login 

log_level: 4

e) Setting the permissions

chmod o-rwx /etc/pam.d/smtp

chmod o-rwx /etc/postfix/sasl/smtpd.conf

f) Adding the postfix user to the sasl group for group access permissions: 

usermod  -aG sasl postfix

g) Restarting the services:

systemctl restart postfix

systemctl restart saslauthd


7. Configuring Dovecot (POP3/IMAP)

a) At the end of /etc/postfix/master.cf add:

dovecot   unix  -       n       n       -       -       pipe

flags=DRhu user=vmail:vmail argv=/usr/lib/dovecot/deliver -d ${recipient}

b) Edit Dovecot config file: vim /etc/dovecot/dovecot.conf

log_timestamp = "%Y-%m-%d %H:%M:%S "

mail_location = maildir:/var/vmail/%d/%n/Maildir

managesieve_notify_capability = mailto

managesieve_sieve_capability = fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date

namespace {
  inbox = yes
  location = 
  prefix = INBOX.
  separator = .
  type = private
}

passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}

protocols = imap pop3

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }

unix_listener auth-master {
    mode = 0600
    user = vmail
  }

user = root
}

userdb {
  args = uid=5000 gid=5000 home=/var/vmail/%d/%n allow_all_users=yes
  driver = static
}

protocol lda {
  auth_socket_path = /var/run/dovecot/auth-master
  log_path = /var/vmail/dovecot-deliver.log
  mail_plugins = sieve
  postmaster_address = postmaster@example.com
}

protocol pop3 {
  pop3_uidl_format = %08Xu%08Xv
}

service stats {
  unix_listener stats-reader {
    user = dovecot
    group = vmail
    mode = 0660
  }

unix_listener stats-writer {
    user = dovecot
    group = vmail
    mode = 0660
  }
}

ssl = yes

ssl_cert = </etc/letsencrypt/live/crystalmind.academy/fullchain.pem

ssl_key = </etc/letsencrypt/live/crystalmind.academy/privkey.pem

c) vim /etc/dovecot/dovecot-sql.conf

driver = mysql

connect = host=127.0.0.1 dbname=mail user=mail_admin password=mail_admin_password

default_pass_scheme = PLAIN-MD5

password_query = SELECT email as user, password FROM users WHERE email='%u';

d) Restart Dovecot

systemctl restart dovecot


8. Adding Domains and Virtual Users. 

mysql -u root

msyql>USE mail;

mysql>INSERT INTO domains (domain) VALUES ('crystalmind.academy');

mysql>insert into users(email,password) values('u1@crystalmind.academy', md5('pass123'));

mysql>insert into users(email,password) values('u2@crystalmind.academy', md5('pass123'));

mysql>quit;


9. Testing the Mail System.

Set up a Mail client like Mozilla Thunderbird, send and receive mail to both local and external accounts.

Troubleshooting mail system

Ping mail server

nmap -p 25 [mailserver] -Pn /telnet mailserver

nmap -p 465 mailserver] -Pn

Tail -f /var/log/mail.log





INSTALLING AMAVISD/CLAMAV AND POSTFIX INTEGRATION ##

All commands are run as root 

1. Installing Amavis

apt update && apt install amavisd-new

Note: if there's an error set $myhostname in /etc/amavis/conf.d/05-node_id

2. Installing required packages for scanning attachments

apt install arj bzip2 cabextract cpio rpm2cpio file gzip lhasa nomarch pax rar unrar p7zip-full unzip zip lrzip lzip liblz4-tool lzop unrar-free

3. Configuring Postfix (/etc/postfix/main.cf)

postconf -e 'content_filter = smtp-amavis:[127.0.0.1]:10024'

postconf -e 'smtpd_proxy_options = speed_adjust'

4. Add to the end of /etc/postfix/master.cf

smtp-amavis   unix   -   -   n   -   2   smtp
    -o syslog_name=postfix/amavis
    -o smtp_data_done_timeout=1200
    -o smtp_send_xforward_command=yes
    -o disable_dns_lookups=yes
    -o max_use=20
    -o smtp_tls_security_level=none


127.0.0.1:10025   inet   n    -     n     -     -    smtpd
    -o syslog_name=postfix/10025
    -o content_filter=
    -o mynetworks_style=host
    -o mynetworks=127.0.0.0/8
    -o local_recipient_maps=
    -o relay_recipient_maps=
    -o strict_rfc821_envelopes=yes
    -o smtp_tls_security_level=none
    -o smtpd_tls_security_level=none
    -o smtpd_restriction_classes=
    -o smtpd_delay_reject=no
    -o smtpd_client_restrictions=permit_mynetworks,reject
    -o smtpd_helo_restrictions=
    -o smtpd_sender_restrictions=
    -o smtpd_recipient_restrictions=permit_mynetworks,reject
    -o smtpd_end_of_data_restrictions=
    -o smtpd_error_sleep_time=0
    -o smtpd_soft_error_limit=1001
    -o smtpd_hard_error_limit=1000
    -o smtpd_client_connection_count_limit=0
    -o smtpd_client_connection_rate_limit=0
    -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks,no_address_mappings

5. Installing ClamAV

apt install clamav clamav-daemon

6. Turning on virus-checking in Amavis.

In /etc/amavis/conf.d/15-content_filter_mode

Uncomment:

@bypass_virus_checks_maps = (
  	\%bypass_virus_checks, \@bypass_virus_checks_acl, \$bypass_virus_checks_re);

7. Restarting Amavis and ClamAv

systemctl restart amavis; systemctl restart clamav-daemon


POSTFIX RESTRICTION

smtpd_helo_required = yes

smtpd_helo_restrictions =
  permit_mynetworks,

permit_sasl_authenticated,
  reject_invalid_helo_hostname,
  reject_non_fqdn_helo_hostname,
  reject_unknown_helo_hostname,
  permit

smtpd_sender_restrictions =
  permit_mynetworks,
  permit_sasl_authenticated,
  reject_unknown_sender_domain,
  reject_non_fqdn_sender,
  reject_unknown_reverse_client_hostname,
  reject_unknown_client_hostname,  #could trigger false-positives
  permit

smtpd_recipient_restrictions =
  permit_mynetworks,
  permit_sasl_authenticated,
  reject_unauth_destination,
  reject_unauth_pipelining,
  reject_unknown_recipient_domain,
  reject_non_fqdn_recipient,
  check_client_access hash:/etc/postfix/rbl_override,
  reject_rhsbl_helo dbl.spamhaus.org,
  reject_rhsbl_reverse_client dbl.spamhaus.org,
  reject_rhsbl_sender dbl.spamhaus.org,
  reject_rbl_client zen.spamhaus.org,
  permit


INSTALLING RSPAMD AND POSTFIX INTEGRATION

All commands are run as root 

1. Installing Redis as storage for non-volatile data and as a cache for volatile data
apt update && apt install redis-server

2. Adding the repository GPG key 

wget -O- https://rspamd.com/apt-stable/gpg.key | sudo apt-key add -

3. Enabling the Rspamd repository

echo "deb http://rspamd.com/apt-stable/ $(lsb_release -cs) main" | sudo tee -a /etc/apt/sources.list.d/rspamd.list

4. Installing Rspamd

apt update && apt install Rspamd

5. Configuring the Rspamd normal worker to listen only on localhost interface

vim /etc/rspamd/local.d/worker-normal.inc
    bind_socket = "127.0.0.1:11333";

6. Enabling the milter protocol to communicate with postfix:

vim /etc/rspamd/local.d/worker-proxy.inc
    bind_socket = "127.0.0.1:11332";
    milter = yes;
    timeout = 120s;
    upstream "local" {
    default = yes;
    self_scan = yes;
    }

7. Configure postfix to use Rspamd

postconf -e "milter_protocol = 6"

postconf -e "milter_mail_macros = i {mail_addr} {client_addr} {client_name} {auth_authen}"

postconf -e "milter_default_action = accept"

postconf -e "smtpd_milters = inet:127.0.0.1:11332"

postconf -e "non_smtpd_milters = inet:127.0.0.1:11332"

8. Restarting Rspamd and Postfix

systemctl restart rspamd; systemctl restart postfix

