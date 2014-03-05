# OpenVAS Vulnerability Test
# $Id: multiple_ftpd_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Multiple WarFTPd DoS
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2000 StrongHoldNET
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
tag_summary = "The remote WarFTPd server is running a 1.71 version.

It is possible for a remote user to cause a denial of
service on a host running Serv-U FTP Server, G6 FTP Server
or WarFTPd Server. Repeatedly submitting an 'a:/' GET or
RETR request, appended with arbitrary data,
will cause the CPU usage to spike to 100%.

Reference: http://www.securityfocus.com/bid/2698";

tag_solution = "upgrade to the latest version of WarFTPd";

if(description)
{
 script_id(10822);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2698);
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Multiple WarFTPd DoS";
 
 script_name(name);
             
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

                 
 script_description(desc);
                    
 
 script_summary("Checks if the version of the remote warftpd");
 script_category(ACT_GATHER_INFO);
 script_family("FTP");

 
 script_copyright("This script is Copyright (C) 2000 StrongHoldNET");
                  
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nasl");
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

if(! get_port_state(port)) exit(0);

banner = get_ftp_banner(port: port);

 if(("WarFTPd 1.71" >< banner))
   security_hole(port);

