###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grandstream_hardcoded_telnet_account.nasl 11 2013-10-27 10:12:02Z jan $
#
# Grandstream Devices Backdoor in Telnet Protocol
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "The remote Grandstream device has the default telnet user and password '!#/'.";


tag_solution = "Ask the Vendor for a solution.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103737";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_cve_id("CVE-2013-3542","CVE-2013-3962","CVE-2013-3963");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Grandstream Devices Backdoor in Telnet Protocol");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value: "http://seclists.org/fulldisclosure/2013/Jun/84");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-11 14:29:08 +0200 (Wed, 12. Jun 2013)");
 script_description(desc);
 script_summary("Determine if the remote Grandstream device has a hardcoded user/password");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("telnetserver_detect_type_nd_version.nasl");
 script_require_ports(23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("telnet_func.inc");

port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = recv(socket:soc, length:512);

if("grandstream" >!< buf || "Username" >!< buf)exit(0);

up = '!#/';

send(socket:soc, data: up + '\r\n');
ret = recv(socket:soc, length:512);

if("Password" >!< ret)exit(0);

send(socket:soc, data: up + '\r\n');
ret = recv(socket:soc, length:512);

close(soc);

if("Grandstream>" >< ret) {

  security_hole(port:port);
  exit(0);

}

exit(0);
