# OpenVAS Vulnerability Test
# $Id: Black_JumboDog_FTP_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: BlackJumboDog FTP server multiple command overflow
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote host is running BlackJumboDog FTP server.

This FTP server fails to properly check the length of parameters 
in multiple FTP commands, most significant of which is USER, 
resulting in a stack overflow. 

With a specially crafted request, an attacker can execute arbitrary code 
resulting in a loss of integrity, and/or availability.";

tag_solution = "Upgrade to version 3.6.2 or newer";

if(description)
{
 script_id(14256);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1439");
 script_bugtraq_id(10834);
 script_xref(name:"OSVDB", value:"8273");
 
 name = "BlackJumboDog FTP server multiple command overflow";

script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Determines the version of BlackJumboDog";

 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK);

 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "FTP";
 script_family(family);
 
 script_dependencies("find_service2.nasl");
 script_require_ports(21, "Services/ftp");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);
	
#220 FTP ( BlackJumboDog(-RAS) Version 3.6.1 ) ready
#220 FTP ( BlackJumboDog Version 3.6.1 ) ready

if( "BlackJumboDog" >< banner ) 
{
  if (safe_checks())
  {
	if ( egrep(pattern:"^220 .*BlackJumboDog.* Version 3\.([0-5]\.[0-9]+|6\.[01])", string:banner ) )
	security_hole(port);
  }
  else
  {
       req1 = string("USER ", crap(300), "\r\n");
       soc=open_sock_tcp(port);
 	if ( ! soc ) exit(0);
       send(socket:soc, data:req1);    
       close(soc);
       sleep(1);
       soc2 = open_sock_tcp(port);
	if (! soc2 || ! ftp_recv_line(socket:soc))
       {
	  security_hole(port);
	}
	else close(soc2);
	exit(0);
  }
}
