###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zervit_40132.nasl 14 2013-10-27 12:33:37Z jan $
#
# Zervit HTTP Server Source Code Information Disclosure Vulnerability
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
tag_summary = "Zervit is prone to a vulnerability that lets attackers access source
code files.

An attacker can exploit this vulnerability to retrieve certain files
from the vulnerable computer in the context of the webserver process.
Information obtained may aid in further attacks.

Zervit 0.4 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100637);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
 script_bugtraq_id(40132);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Zervit HTTP Server Source Code Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40132");
 script_xref(name : "URL" , value : "http://zervit.sourceforge.net/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Zervit is prone to a Source Code Information Disclosure Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: Zervit" >!< banner)exit(0);

version = eregmatch(pattern:"Server: Zervit ([0-9.]+)", string: banner);

if(isnull(version[1]))exit(0);
vers = version[1];

if(!isnull(vers)) {

 if(version_is_equal(version: vers, test_version: "0.4")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
