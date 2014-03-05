###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nec_enterprise_server_53493.nasl 12 2013-10-27 11:15:33Z jan $
#
# NEC Enterprise Server Backdoor Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "NEC Enterprise Server is prone to an unauthorized-access vulnerability
due to a backdoor in all versions of the application.

Attackers can exploit this issue to gain unauthorized access to the
affected application. This may aid in further attacks.";


if (description)
{
 script_id(103498);
 script_bugtraq_id(53493);
 script_version ("$Revision: 12 $");

 script_name("NEC Enterprise Server Backdoor Unauthorized Access Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53493");
 script_xref(name : "URL" , value : "http://www.nec.com.sg/index.php?q=products/enterprise-servers");

 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-21 10:41:21 +0200 (Thu, 21 Jun 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(5001);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("telnet_func.inc");

port = 5001;

soc = open_sock_tcp(port);
if(!soc)exit(0);

r = telnet_negotiate(socket:soc);

if("Integrated Service Processor" >!< r) exit(0);

send(socket:soc, data:'spfw\n');
recv = recv(socket:soc, length:512);

if("iSP password" >!< recv)exit(0);

send(socket:soc, data:'nec\n');
recv = recv(socket:soc, length:512);

close(soc);

if("Welcome to Integrated Service Processor" >< recv && "iSP FW version" >< recv) {
  security_hole(port:port);
  exit(0);
}  

exit(0);
