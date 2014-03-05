# OpenVAS Vulnerability Test
# $Id: cifs445.nasl 41 2013-11-04 19:00:12Z jan $
# Description: SMB on port 445
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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
tag_summary = "This script detects wether port 445 and 139 are open and
if thet are running SMB servers.";

if(description)
{
 script_id(11011);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "SMB on port 445";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;



 script_description(desc);
 
 summary = "Checks for openness of port 445";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2002 Renaud Deraison");

 family = "Windows";

 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(139, 445);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("smb_nt.inc");
include("misc_func.inc");

flag = 0;

if(get_port_state(445))
{
 soc = open_sock_tcp(445);
 if(soc){
 r = smb_neg_prot(soc:soc);
 close(soc);
 if(r){
 	register_service(port:445, proto:"cifs");
	log_message(port:445, data:"A CIFS server is running on this port");
	set_kb_item(name:"SMB/transport", value:445);
	flag = 1;
      }
   }
}


if(get_port_state(139))
{
  soc = open_sock_tcp(139);
  if(soc){
	nb_remote = netbios_name(orig:string("OpenVAS", rand()));
 	nb_local  = netbios_redirector_name();
 	session_request = raw_string(0x81, 0x00, 0x00, 0x44) + 
		  raw_string(0x20) + 
		  nb_remote +
		  raw_string(0x00, 0x20)    + 
		  nb_local  + 
		  raw_string(0x00);
	send(socket:soc, data:session_request);
	r = recv(socket:soc, length:4);
	close(soc);
	if(r && (ord(r[0]) == 0x82 || ord(r[0]) == 0x83)) {
		register_service(port:139, proto:"smb");
		log_message(port:139, data:"An SMB server is running on this port");	
    		if(!flag)set_kb_item(name:"SMB/transport", value:139);
		}
	}
}

