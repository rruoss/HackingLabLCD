###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_quantum_ethernet_module_hardcoded_credentials_51046.nasl 13 2013-10-27 12:16:33Z jan $
#
# Schneider Electric Quantum Ethernet Module Hardcoded Credentials Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Schneider Electric Quantum Ethernet Module is prone to an authentication-
bypass vulnerability.

Attackers can exploit this issue to gain access to the Telnet port
service, Windriver Debug port service, and FTP service. Attackers can
exploit this vulnerability to execute arbitrary code within the
context of the vulnerable device.";

tag_solution = "Updates are available. Please see the references for more information.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_id(103363);
 script_bugtraq_id(51046);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Schneider Electric Quantum Ethernet Module Hardcoded Credentials Authentication Bypass Vulnerability");

 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-14 10:13:05 +0100 (Wed, 14 Dec 2011)");
 script_description(desc);
 script_summary("Determine if Schneider Electric Quantum Ethernet Module is prone to an authentication-bypass vulnerability.");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51046");
 script_xref(name : "URL" , value : "http://www.schneider-electric.com/site/home/index.cfm/ww/?selectCountry=true");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-346-01.pdf");
 script_xref(name : "URL" , value : "http://reversemode.com/index.php?option=com_content&amp;task=view&amp;id=80&amp;Itemid=1");
 exit(0);
}

include("telnet_func.inc");

port = 23;

if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port);

if("VxWorks" >!< banner) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
close(soc);

credentials = make_array("pcfactory","pcfactory",
			 "loader","fwdownload",
			 "ntpupdate","ntpupdate",
			 "sysdiag","factorycast@schneider",
			 "test","testingpw",
			 "USER","USER",
			 "USER","USERUSER",
			 "webserver","webpages",
			 "fdrusers","sresurdf",
			 "nic2212","poiuypoiuy",
			 "nimrohs2212","qwertyqwerty",
			 "nip2212","fcsdfcsd",
			 "ftpuser","ftpuser",
			 "noe77111_v500","RcSyyebczS",
			 "AUTCSE","RybQRceeSd",
			 "AUT_CSE","cQdd9debez",
			 "target","RcQbRbzRyc"
			 );

foreach credential (keys(credentials)) {

  soc = open_sock_tcp(port);
  if(!soc) continue;

  send(socket:soc,data:string(credential,"\r\n"));
  answer = recv(socket:soc, length:4096);

  send(socket:soc, data:string(credentials[credential],"\r\n"));
  answer = recv(socket:soc, length:4096);

  if("->" >!< answer) {
    close(soc);
    continue;
  }  

  send(socket:soc, data:string("version\r\n"));
  answer = recv(socket:soc, length:4096);

  if( answer =~ "VxWorks.*Version" && answer =~ "Boot line:" && answer =~ "Kernel:") {

    report = string("\n\nIt was possible to login via telnet into the remote host using the following\nUsername/Password combination:\n\n",credential,":",credentials[credential],"\n\nWhich produces the following output for the 'version' command:\n\n",answer,"\n");
    desc = desc + report;

    security_hole(port:port,data:desc);
    close(soc);
    exit(0);
  }  

  close(soc);

}

exit(0);

