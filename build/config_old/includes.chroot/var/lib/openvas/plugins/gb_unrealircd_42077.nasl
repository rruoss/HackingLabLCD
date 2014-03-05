###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unrealircd_42077.nasl 14 2013-10-27 12:33:37Z jan $
#
# UnrealIRCd User Authentication Buffer Overflow Vulnerability
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
tag_summary = "UnrealIRCd is prone to a buffer-overflow vulnerability.

Successful exploits will allow remote attackers to execute arbitrary
code within the context of the affected application. Failed exploit
attempts will result in a denial-of-service condition.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_id(100856);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-15 13:28:27 +0200 (Fri, 15 Oct 2010)");
 script_bugtraq_id(42077);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4893");

 script_name("UnrealIRCd User Authentication Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42077");
 script_xref(name : "URL" , value : "http://www.unrealircd.com/txt/unrealsecadvisory.20090413.txt");
 script_xref(name : "URL" , value : "http://unrealircd.com/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed UnrealIRCd version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Buffer overflow");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("ircd.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");

port = get_kb_item("Services/irc");
if (!port){
  port = 6667;
}

if(!get_port_state(port)){
   exit(0);
}

banner = get_kb_item(string("irc/banner/", port));

if(isnull(banner)){
  exit(0);
}

if("unreal" >< tolower(banner))
{
  ver = eregmatch(pattern:"[u|U]nreal([0-9.]+)", string:banner);
  if(ver[1] =~ "^3\.2") {
    if(version_is_less(version: ver[1], test_version: "3.2.8.1") ){
      security_hole(port:port);
    }
  }
}
