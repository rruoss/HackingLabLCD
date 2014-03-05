###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamspeak_40918.nasl 14 2013-10-27 12:33:37Z jan $
#
# Teamspeak Versions Prior to 3.0.0-beta25 Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "Teamspeak is prone to multiple remote vulnerabilities,
including:

1. A security-pass vulnerability
2. A denial-of-service vulnerability
3. Multiple denial-of-service vulnerabilities due to a NULL-pointer
   dereference condition.

An attacker can exploit these issues to execute arbitrary commands
within the context of the affected application, bypass certain
security restrictions and crash the affected application. Other
attacks are also possible.

Versions prior to TeamSpeak 3.0.0-beta25 are vulnerable.";


if (description)
{
 script_id(100682);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)");
 script_bugtraq_id(40918);

 script_name("Teamspeak Versions Prior to 3.0.0-beta25 Multiple Remote Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40918");
 script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/teamspeakrack-adv.txt");
 script_xref(name : "URL" , value : "http://forum.teamspeak.com/showthread.php?t=55646");
 script_xref(name : "URL" , value : "http://forum.teamspeak.com/showthread.php?t=55643");
 script_xref(name : "URL" , value : "http://www.goteamspeak.com/");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Teamspeak version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_teamspeak_detect.nasl");
 script_require_ports(10011);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = 10011;
if(!get_port_state(port))exit(0);

if(!version = get_kb_item(string("teamspeak/",port)))exit(0);

if("build" >< version) {
  vers = eregmatch(pattern:"([^ ]+)", string: version);
  vers = vers[1];
} else {
  vers = version;
}  

if(isnull(vers))exit(0);
if("-beta" >< vers) {
  vers = str_replace(string:vers, find:string("-beta"), replace:".");
}  

if(version_is_less(version: vers, test_version:"3.0.0.25")) {
  security_hole(port:port);
  exit(0);
}   

exit(0);
