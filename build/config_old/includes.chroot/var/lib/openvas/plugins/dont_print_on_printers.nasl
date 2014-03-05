# OpenVAS Vulnerability Test
# $Id: dont_print_on_printers.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Dont print on AppSocket & socketAPI printers
#
# Authors:
# Laurent Facq <facq@u-bordeaux.fr> 05/2004
# 99% based on dont_scan_printers by Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 by Laurent Facq
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
tag_summary = "The host seems to be an AppSocket or socketAPI printer. 
Scanning it will waste paper. So port 9100 wont be scanned.";

## after suggesting a way to avoid paper wasting, i happilly saw appearing a new plugin 'dont_scan_printers'
## but i rapidly saw also that when safe_checks is off (what i use) - HP printers continue to
## print wasted pages under openvas assault.

## as far as i know/understand, the really (well, the most) annoying thing (for me) is that 
## "jetdirect" print all what it receive on port 9100/tcp
## so find_services* will flood this port until out of paper :)

## what i do in this script is to mark this port 9100 as known (using  register_service)
## to avoid this discovery flood by find_services*

## so, when safe_check is off, my campus printers will no more waste paper :)
## nor when its on because dont_scan_printers will do the job in this case.

## the only draw back, in a security point of view, is that of course, you can fool
## openvas to not really scan 9100 port... buf said.

## the http code (port 80 and 280) i wrote here could be added to the original 'dont_scan_printers' code
## because i saw that my HP 4000N was not detected as a HP jet printer (no telnet, no ftp, but http)

## well, i only 99% understood the end of the original script (treating the case of a lot of open ports...), 
## but i kept it in case it could do a good job.

if(description)
{
 script_id(12241); 
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Dont print on AppSocket & socketAPI printers";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 summary = "Exclude port 9100 on AppSocket & socketAPI printers from scan";
 script_summary(summary);

 script_category(ACT_SETTINGS);

# script_add_preference(name:"Exclude 9100 printers port from scan", type:"checkbox", value:"no");

 script_copyright("This script is Copyright (C) 2004 by Laurent Facq");
 family = "Settings";	
# Or maybe a "scan option" family?
 script_family(family);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("ftp_func.inc");
include("telnet_func.inc");

include("misc_func.inc");
include("http_func.inc");


# pref= script_get_preference("Exclude 9100 printers port from scan");
# if (!pref || pref == "no") exit(0);

#### only usefull if safe_check not wanted (dont_scan_printers will do the job in this other case)
if (safe_checks()) exit(0);
####

# First try UDP AppSocket

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);

  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
  {
    # set_kb_item(name: "Host/dead", value: TRUE);
    security_note(port: 0);

    register_service(port: 9100, proto: "ignore-this-printer-port");

    exit(0);
  }
}

port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if("JD FTP Server Ready" >< banner)
 {
     #    set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0);
     
     register_service(port: 9100, proto: "ignore-this-printer-port");
     
     exit(0);
 }
}

port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("HP JetDirect" >< banner)
 {
     #set_kb_item(name: "Host/dead", value: TRUE);

     register_service(port: 9100, proto: "ignore-this-printer-port");

    security_note(port: 0);
    exit(0);
 }
}


ports = make_list(80, 280);
foreach port (ports)
{
 if(get_port_state(port))
 {
  banner = http_send_recv(port:port, data:string("GET / HTTP/1.0\r\n\r\n"));
  if("<title>Hewlett Packard</title>" >< banner)
  {
     #    set_kb_item(name: "Host/dead", value: TRUE);
     security_note(port: 0);
     
     register_service(port: 9100, proto: "ignore-this-printer-port");
     
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
        || p == 10000 		# Lexmark
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
  security_note(0);

  register_service(port: 9100, proto: "ignore-this-printer-port");

  #set_kb_item(name: "Host/dead", value: TRUE);
}
