# OpenVAS Vulnerability Test
# $Id: dont_scan_printers.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Do not scan printers
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 by Michel Arboi
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
tag_solution = "If you want to scan the remote host, uncheck the 'Exclude printers from scan' option
and re-scan it.

CVSS Base Score : 0 (AV:L/AC:H/Au:R/C:N/A:N/I:N/B:N)";

tag_summary = "The host seems to be a printer. The scan has been disabled against this host.

Description :

Many printers react very badly to a network scan. Some of them will crash, 
while others will print a number of pages. This usually disrupt office work
and is usually a nuisance. As a result, the scan has been disabled against this
host.";


if(description)
{
 script_id(11933);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Do not scan printers";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Exclude AppSocket & socketAPI printers from scan";
 script_summary(summary);

 script_category(ACT_SETTINGS);

 script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"yes");

 script_copyright("This script is Copyright (C) 2003 by Michel Arboi");
 family = "Settings";	
# Or maybe a "scan option" family?
 script_family(family);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}


include("ftp_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("global_settings.inc");
include("openvas-https.inc");

pref= script_get_preference("Exclude printers from scan");
if (!pref || pref == "no") exit(0);
# First try UDP AppSocket

if ( get_kb_item("Host/scanned")  == 0 ) exit(0);

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);

  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " answers to UDP AppSocket\n");
    log_message(port: 0);
    exit(0);
  }
}

port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if("JD FTP Server Ready" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs JD FTP server\n");
    log_message(port: 0);
    exit(0);
 }
 else if ("220 Dell Laser Printer " >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Dell FTP server\n");
    log_message(port: 0);
    exit(0);
 }
}

port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("HP JetDirect" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
   if (debug_level) display(get_host_ip(), " runs HP JetDirect Telnet server\n");
    log_message(port: 0);
    exit(0);
 }
}
# Xerox DocuPrint
port = 2002;
if ( get_port_state(port) )
{
 soc = open_sock_tcp(port);
 if ( soc )
 {
  banner = recv(socket:soc, length:23);
  close(soc);
  if ( banner && 'Please enter a password' >< banner ) {
    	set_kb_item(name: "Host/dead", value: TRUE);
    	log_message(port: 0);
	exit(0);
	}
 }
}



# Patch by Laurent Facq
ports = make_list(80, 280, 631, 443);
foreach port (ports)
{
 if(get_port_state(port))
 {
  if(port == 443) {
    banner = https_req_get(port:port, request:string("GET / HTTP/1.0\r\n\r\n"));
  } else {
    banner = http_send_recv(port:port, data:string("GET / HTTP/1.0\r\n\r\n"));
  }
  
  if("Dell Laser Printer " >< banner )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Dell web server\n");
     log_message(port: 0);
     exit(0);
  }
  else if("<title>Hewlett Packard</title>" >< banner ||
          egrep(pattern:"<title>.*LaserJet.*</title>", string:banner,  icase:TRUE) ||
          ("server: hp-chai" >< tolower(banner)) ||
          ("Server: Virata-EmWeb/" >< banner && ("HP" >< banner || "printer" >< banner))
          )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs HP web server\n");
     log_message(port: 0);
     exit(0);
  }
  else if ( banner && "Server: Xerox_MicroServer/Xerox" >< banner )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs a Xerox web server\n");
    log_message(port: 0);
    exit(0);
  }
 }
}


# open ports?
ports = get_kb_list("Ports/tcp/*");
# Host is dead, or all ports closed, or unscanned => cannot decide
if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4981.htm
appsocket = 0;


foreach p (keys(ports))
{
  p = int(p - "Ports/tcp/");
  if (	   p == 35		# AppSocket for QMS
	|| p == 2000		# Xerox
	|| p == 2501		# AppSocket for Xerox
	|| (p >= 3001 && p <= 3005)	# Lantronix - several ports
	|| (p >= 9100 && p <= 9300)	# AppSocket - several ports
#        || p == 10000 		# Lexmark
	|| p == 10001)		# Xerox - programmable :-(
    appsocket = 1;
# Look for common non-printer ports
	 else if (
          p != 21              # FTP
       && p != 23              # telnet
       && p != 79
       && p != 80              # www
       && p != 139 && p!= 445  # SMB
       && p != 280             # http-mgmt
       && p != 443
       && p != 515             # lpd
       && p != 631 	       # IPP
       && p != 8000 
       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers    
	exit(0);

}


# OK, this might well be an AppSocket printer
if (appsocket)
{
  log_message(0);
  if (debug_level) display(get_host_ip(), " looks like an AppSocket printer\n");
  set_kb_item(name: "Host/dead", value: TRUE);
}
