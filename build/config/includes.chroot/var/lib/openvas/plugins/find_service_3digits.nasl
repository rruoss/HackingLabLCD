# OpenVAS Vulnerability Test
# $Id: find_service_3digits.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Identifies services like FTP, SMTP, NNTP...
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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

This plugin is a complement of find_service.nasl. It attempts to 
identify services that return 3 ASCII digits codes (ie: FTP, SMTP, NNTP, ...)";

if(description)
{
 script_id(14773);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Identifies services like FTP, SMTP, NNTP...";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Identifies services that return 3 ASCII digits codes";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 script_family("Service detection");
 script_dependencies("find_service.nasl"); # cifs445.nasl 

 # "rpcinfo.nasl", "dcetest.nasl"

# Do *not* add a port dependency  on "Services/three_digits"
# find_service2 must run after this script even if there are no
# '3 digits' services

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/three_digits");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port: port)) exit(0);	

if (thorough_tests) retry = 3;
else retry = 1;

function read_answer(socket)
{
  local_var	r, answer, i;

  repeat
  {
   for (i = 0; i <= retry; i ++)
   {
    r = recv_line(socket: socket, length: 4096);
    if (strlen(r) > 0) break;
   }
   answer += r;
  }
  until (! r || r =~ '^[0-9]{3}[^-]' || strlen(answer) > 1000000);
  return answer;
}

soc = open_sock_tcp(port);
if (! soc) exit(0);
banner = read_answer(socket: soc);

if (banner)
  replace_kb_item(name: "FindService/tcp/"+port+"/spontaneous", value: banner);
else
  debug_print('Banner is void on port ', port, ' \n');

# 500 = Unknown command
# 502 = Command not implemented

# If HELP works, it is simpler than anything else
send(socket: soc, data: 'HELP\r\n');
help = read_answer(socket: soc);
if (help)
{
  replace_kb_item(name: "FindService/tcp/"+port+"/help", value: help);
  if (! banner) banner = help; # Not normal, but better than nothing
}    

if (help !~ '^50[0-9]')
{
 if ("ARTICLE" >< help || "NEWGROUPS" >< help || "XHDR" >< help || "XOVER" >< help)
 {
  report_service(port:port, svc: 'nntp', banner: banner);
  exit(0);
 }
 # nb: this must come before FTP recognition.
 if (
  egrep(string:banner, pattern:"^220.*HylaFAX .*Version.*") ||
  egrep(string:help,   pattern:"^220.*HylaFAX .*Version.*")
 )
 {
  report_service(port: port, svc: 'hylafax', banner: banner);
  exit(0);
 }
# nb: this must come before FTP recognition.
 if(egrep(pattern:"^101", string: banner) &&
   (egrep(pattern:"[a-zA-Z]+broker", string: banner,icase:TRUE) ||
    egrep(pattern:"portmapper tcp PORTMAPPER", string:banner))) 
 {
    # iMQ Broker Rendezvous(imqbrokerd) 
    register_service(port: port, proto: "imqbrokerd");
    security_note(port:port,data:string("A Message Queue broker is running at this port.\n"));
    exit(0);
 }  
 if ("PORT" >< help || "PASV" >< help)
 {
  report_service(port:port, svc: 'ftp', banner: banner); 
  exit(0);
 }
 # Code from find_service2.nasl
 if (help =~ '^220 .* SNPP ' || egrep(string: help, pattern: '^214 .*PAGE'))
 {
   report_service(port: port, svc: 'snpp', banner: banner);
   exit(0);
 }
 if (egrep(string: help, pattern: '^214-? ') && 'MDMFMT' >< help)
 {
  report_service(port: port, svc: 'hylafax-ftp', banner: banner);
  exit(0);
 }
}

send(socket: soc, data: 'HELO mail.openvas.org\r\n');
helo = read_answer(socket: soc);

if ( egrep(string: helo, pattern: '^250'))
{
 report_service(port:port, svc: 'smtp', banner: banner);
 exit(0);
}


send(socket: soc, data: 'DATE\r\n');
date = read_answer(socket: soc);
if (date =~ '^111[ \t]+2[0-9]{3}[01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]')
{
 report_service(port: port, svc: 'nntp', banner: banner);
 exit(0);
}

ftp_commands = make_list("CWD", "SYST", "PORT", "PASV");
ko = 0;
foreach cmd (ftp_commands)
{
  send(socket: soc, data: cmd + '\r\n');
  r = read_answer(socket: soc);
  if (egrep(string: r, pattern: '^50[0-9]')) ko ++;
  debug_print('Answer to ', cmd, ': ', r);
  if (cmd == "SYST")
  {
# We store the result of SYST just in case. Most (>99%) FTP servers answer 
# "Unix Type: L8" so this is not very informative
   v = eregmatch(string: r, pattern: '^2[0-9][0-9] +(.*)[ \t\r\n]*$');
   if (! isnull(v))
    set_kb_item(name: 'ftp/'+port+'/syst', value: v[1]);
  }
}
if (! ko)
{
  report_service(port: port, svc: 'ftp', banner: banner);
  exit(0);
}

# Code from find_service2.nasl:
# SNPP, HylaFAX FTP, HylaFAX SPP, agobot.fo, IRC bots, WinSock server,
# Note: this code must remain in find_service2.nasl until we think that
# all find_service.nasl are up to date
#

if (egrep(pattern:"^220 Bot Server", string: help) ||
     raw_string(0xb0, 0x3e, 0xc3, 0x77, 0x4d, 0x5a, 0x90) >< help)
{
 report_service(port:port, svc:"agobot.fo", banner: banner);
 exit(0);
}
if ("500 P-Error" >< help && "220 Hello" >< help)	# or banner?
{
 report_service(port:port, svc:'unknown_irc_bot', banner: banner);
 exit(0);
}
if ("220 WinSock" >< help)	# or banner?
{
 report_service(port:port, svc:'winsock', banner: banner);
 exit(0);
}

# Try poppasswd
if (egrep(pattern:"^200 .* (PWD Server|poppassd)", string:banner)) {
  register_service(port:port, proto:"pop3pw");
  exit(0);
}
if (substr(banner, 0, 3) == '200 ')
{
 close(soc);
 soc = open_sock_tcp(port);
 if (soc)
 {
  banner = read_answer(socket: soc);
  send(socket: soc, data:string("USER openvas\r\n")); 
  r = read_answer(socket: soc);
  if (strlen(r) > 3 && substr(r, 0, 3) == '200 ')
  {
   send(socket: soc, data:string("PASS ", rand(), "openvas\r\n")); 
   r = read_answer(socket: soc);
   if (strlen(r) > 3 && substr(r, 0, 3) == '500 ')
   {
    register_service(port: port, proto: 'pop3pw');
    close(soc);
    exit(0);
   }
  }
  close(soc);
 }
}

# Give it to find_service2 & others
register_service(port: port, proto: 'unknown');
set_unknown_banner(port: port, banner: banner);

if (report_paranoia > 0)
{
 security_warning(port: port, data: 
'Although this service answers with 3 digit ASCII codes
like FTP, SMTP or NNTP servers, OpenVAS was unable to identify it.

This is highly suspicious and might be a backdoor; in this case, 
your system is compromised and a cracker can control it remotely.

** If you know what it is, consider this message as a false alert
** and please report it to the OpenVAS team.

Solution : disinfect or reinstall your operating system');
}
