# OpenVAS Vulnerability Test
# $Id: platinum_ftp.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Platinum FTP Server
#
# Authors:
# Douglas Minderhout <dminderhout@layer3com.com>
# Based on a previous script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2003 Douglas Minderhout
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
tag_summary = "Platinum FTP server for Win32 has several vulnerabilities in 
the way it checks the format of command strings passed to it. 
This leads to the following vulnerabilities in the server:

The 'dir' command can be used to examine the filesystem of the machine and
gather further information about the host by using relative directory listings 
(I.E. '../../../' or '\..\..\..').

The 'delete' command can be used to delete any file on the server that the
Platinum FTP server has permissions to.

Issuing the command  'cd @/..@/..' will cause the 
Platinum FTP server to crash and consume all available CPU time on 
the server.

*** Warning : OpenVAS solely relied on the banner of this server, so
*** this may be a false positive";

tag_solution = "see http://www.platinumftp.com/platinumftpserver.php";

# Thanks to: H D Moore
# Ref: 
# Message-ID: <1043650912.3e34d960788ac@webmail.web-sale.dk>
# Date: Mon, 27 Jan 2003 08:01:52 +0100
# Subject: [VulnWatch] Multiple vulnerabilities found in PlatinumFTPserver V1.0.7

if(description){
 script_id(11200);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 
 name = "Platinum FTP Server";
 
 script_name(name);
	     
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
		    
 
 script_summary("Checks if the remote ftp server is a vulnerable version of Platinum FTP");

 script_category(ACT_GATHER_INFO);
 script_family("FTP");
 script_copyright("This script is Copyright (C) 2003 Douglas Minderhout");
		  
 script_dependencies("find_service.nasl");
 script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(!get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);
if(banner) {
	if(egrep(pattern:"^220.*PlatinumFTPserver V1\.0\.[0-7][^0-9].*$",string:banner)) {
 		
  		security_hole(port);
   	}
}
