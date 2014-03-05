# OpenVAS Vulnerability Test
# $Id: find_service1.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Identify unknown services with GET
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "This plugin performs service detection.

Description :

This plugin is a complement of find_service.nasl. It sends a GET
request to the remaining unknown services and tries to identify 
them.";

if(description)
{
 script_id(17975);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Identify unknown services with GET";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Sends 'GET' to unknown services and look at the answer";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Service detection");
 script_dependencies("find_service.nasl", "cifs445.nasl");
# Do *not* add a port dependency  on "Services/unknown"
# Some scripts must run after this script even if there are no
# unknown services
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if ( ! service_is_unknown (port: port)) exit(0);

# If the service displays a banner on connection, find_service.c does not
# send a GET request. However, if a GET request was sent and the service
# remains silent, the get_http KB entry is void

r0 = get_kb_item('FindService/tcp/'+port+'/spontaneous');	# Banner?
get_sent = 1;
if (strlen(r0) > 0)	# We have a spontaneous banner
{
 get_sent = 0;	# spontaneous banner => no GET request was sent by find_service

######## Updates for "spontaneous" banners ########

if (r0 =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+')
{
 debug_print('Fake IDENTD found on port ', port, '\n');
 register_service(port: port, proto: 'fake-identd');
 set_kb_item(name: 'fake_identd/'+port, value: TRUE);
 exit(0);
}

if (match(string: r0, pattern: 'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *'))
{
 report_service(port: port, svc: 'smsc');
 exit(0);
}

# 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
# 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
# 20: 0a . 

if (ereg(pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:r))
{
 report_service(port: port, svc: 'daytime');
 exit(0);
}

# Possible outputs:
# |/dev/hdh|Maxtor 6Y160P0|38|C|
# |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
if (r0 =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}

if (match(string: r0, pattern: '220 *FTP Server ready\r\n'))
{
 report_service(port: port, svc: 'ftp');
 exit(0);
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65  "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
if (match(string: r0, pattern: '"IMPLEMENTATION" "Cyrus timsieved v*"*"SASL"*'))
{
 register_service(port: port, proto: 'sieve');
 security_note(port: port, data: 'Sieve mail filter daemon seems to be running on this port');
 exit(0);
}

# I'm not sure it should go here or in find_service2...
if (match(string: r0, pattern: '220 Axis Developer Board*'))
{
 report_service(port: port, svc: 'axis-developer-board');
 exit(0);
}

if (match(string: r0, pattern: '  \x5f\x5f\x5f           *Copyright (C) 1999, 2000, 2001, 2002 Eggheads Development Team'))
{
 report_service(port: port, svc: 'eggdrop');
 exit(0);
}

# Music Player Daemon from www.musicpd.org
if (ereg(string: r0, pattern: '^OK MPD [0-9.]+\n'))
{
 report_service(port: port, svc: 'mpd');
 exit(0);
}

if (egrep(pattern:"^OK WorkgroupShare.*server ready", string:r0))
{
 report_service(port:port, svc:"WorkgroupShare");
 exit(0);
}

# Eudora Internet Mail Server ACAP server.
if ("* Eudora-SET (IMPLEMENTATION Eudora Internet Mail Server" >< r0)
{
 report_service(port: port, svc: 'acap');
 exit(0);
}

# Sophos Remote Messaging / Management Server
if ("IOR:010000002600000049444c3a536f70686f734d6573736167696e672f4d657373616765526f75746572" >< r0)
{
 report_service(port: port, svc: 'sophos_rms');
 exit(0);
}

if (r0 =~ '^\\* *BYE ')
{
  report_service(port: port, svc: 'imap', banner: r0);
  security_note(port: port, data: 'The IMAP server rejects connection from our host. We cannot test it');
  exit(0);
}

# General case should be handled by find_service_3digits
if (match(string: r0, pattern: '200 CommuniGatePro PWD Server * ready*'))
{
 report_service(port: port, svc: 'pop3pw');
 exit(0);
}


# Should be handled by find_service already
if (r0 =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}

#
# Keep qotd at the end of the list, as it may generate false detection
#

if (r0 =~ '^"[^"]+"[ \t\r\n]+[A-Za-z -]+[ \t\r\n]+\\([0-9]+(-[0-9]+)?\\)[ \t\r\n]+$')
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd seems to be running on this port");
  exit(0);
}


}	# else: no spontaneous banner

###################################################

k = 'FindService/tcp/'+port+'/get_http';
r = get_kb_item(k+'Hex');
if (strlen(r) > 0) r = hex2raw(s: r);
else r = get_kb_item(k);

r_len = strlen(r);
if (r_len == 0)
{
 if (get_sent			# Service did not anwer to GET
     && ! thorough_tests)	# We try again in "thorough tests"
  exit(0);

 soc = open_sock_tcp(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
 r = recv(socket:soc, length:4096);
 close(soc);
 r_len = strlen(r);
 if (r_len == 0)
 {
   debug_print('Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n');
   exit(0);
 }
 set_kb_item(name: k, value: r);
 if ('\0' >< r) set_kb_item(name: k + 'Hex', value: hexstr(r));
}

# aka HTTP/0.9
if (r =~ '^[ \t\r\n]*<HTML>.*</HTML>')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0);
}

if (r == '[TS]\r\n')
{
 report_service(port: port, svc: 'teamspeak-tcpquery', banner: r);
 exit(0);
}

if (r == 'gethostbyaddr: Error 0\n')
{
 register_service(port:port, proto:"veritas-netbackup-client");
 security_note(port:port, data:"Veritas NetBackup Client Service is running on this port");
 exit(0);
}

if ("GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r)
{
 report_service(port: port, svc: 'auth', banner: r);
 exit(0);
}

if ('Host' >< r && 'is not allowed to connect to this MySQL server' >< r)
{
 register_service(port: port, proto: 'mysql');	# or wrapped?
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but it
rejects connection from the openvas scanner.");
  exit(0);
}

# The full message is:
# Host '10.10.10.10' is blocked because of many connection errors. Unblock with 'mysqladmin flush-hosts'
if ('Host' >< r && ' is blocked ' >< r && 'mysqladmin flush-hosts' >< r)
{
 register_service(port: port, proto: 'mysql');
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but the 
OpenVAS scanner IP has been blacklisted.
Run 'mysqladmin flush-hosts' if you want complete tests.");
  exit(0);
}

# JNB30........
# .4....I.n.v.a.l.i.d. .r.e.q.u.e.s.t.:. . .i.n.v.a.l.i.d. .j.n.b.b.i.n.a.r.y.
# [...]
if (r =~ "^JNB30" && ord(r[5]) == 14 && ord(r[6] == 3))
{
   register_service(port:port, proto:"jnbproxy");
   security_note(port:port, data:"ColdFusion jnbproxy is running on this port.");
   exit(0);
}

if ( "Asterisk Call Manager" >< r )
{
 register_service(port: port, proto: 'asterisk');
 security_note(port: port, data: "An Asterisk Call Manager server is running on this port.");
  exit(0);
}

# Taken from find_service2
if (r_len == 3 && (r[2] == '\x10'||	# same test as find_service
                   r[2] == '\x0b') ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' )
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "A MSDTC server seems to be running on this port");
  exit(0);
}

# It seems that MS DTC banner is longer that 3 bytes, when we properly handle
# null bytes
# For example:
# 00: 90 a2 0a 00 80 94 .. 
if ((r_len == 5 || r_len == 6) && r[3] == '\0' && 
     r[0] != '\0' && r[1] != '\0' && r[2] != '\0')
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "A MSDTC server seems to be running on this port");
  exit(0);
}

if (r == '\x01Permission denied' || 
   ( "lpd " >< r && "Print-services" >< r )  )
{
  report_service(port: port, svc: 'lpd');
  security_note(port: port, data: 'An LPD server is running on this port');
  exit(0);
}

#### Double check: all this should be handled by find_service.nasl ####

if (r == 'GET / HTTP/1.0\r\n\r\n')
{
 report_service(port: port, svc: 'echo', banner: r);
 exit(0);
}

# Should we excluded port=5000...? (see find_service.c)
if (r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0); 
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if (r =~ '^[0-9][0-9][0-9]-?[ \t]')
{
 debug_print('"3 digits" found on port ', port, ' in response to GET\n');
 register_service(port: port, proto: 'three_digits');
 exit(0); 
}

if (r =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}

if (match(string: r, pattern: "Language received from client:*Setlocale:*"))
{
  report_service(port: port, svc: "websm");
  exit(0);
}

#### Some spontaneous banners are coming slowly, so they are wronly 
#### registered as answers to GET
 
if (r =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}
