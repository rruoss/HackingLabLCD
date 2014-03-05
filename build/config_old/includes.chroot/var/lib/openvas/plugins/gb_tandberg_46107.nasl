###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tandberg_46107.nasl 12 2013-10-27 11:15:33Z jan $
#
# Cisco TANDBERG C Series and E/EX Series Default Credentials Authentication Bypass Vulnerability
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
tag_summary = "Cisco TANDBERG C Series Endpoints and E/EX Series Personal Video
devices are prone to a remote authentication-bypass vulnerability.

An attacker can exploit this issue to gain unauthorized root access to
the affected devices. Successful exploits will result in the complete
compromise of the affected device.";

tag_solution = "The vendor has released an advisory along with fixes. Please see the
referenced advisory for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103606";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(46107);
 script_cve_id("CVE-2011-0354");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Cisco TANDBERG C Series and E/EX Series Default Credentials Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/46107");
 script_xref(name : "URL" , value : "http://www.cisco.com/en/US/products/ps11422/products_security_advisory09186a0080b69541.shtml");
 script_xref(name : "URL" , value : "http://www.tandberg.com/support/video-conferencing-software-download.jsp?t=2");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/516126");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/436854");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-14 11:19:49 +0100 (Wed, 14 Nov 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login as root with no password");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ssh_func.inc");

port = get_kb_item("Services/ssh");
if(!port)port = 22;

if(!get_port_state(port))exit(0);

sock = open_sock_tcp(port);
if(!sock)exit(0);

login = ssh_login(socket:sock, login:"root", password:""); 

if(login == 0) {

  cmd = ssh_cmd(socket:sock,cmd:"ls -l /apps/bin/tandberg");
  close(sock);

  if(eregmatch(pattern:"-rwx.*root.*/apps/bin/tandberg", string:cmd)) {
    security_hole(port:port);
    exit(0);
  }  

}  

if(sock)close(sock);

exit(0);
