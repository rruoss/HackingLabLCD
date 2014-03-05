###############################################################################
# OpenVAS Vulnerability Test
# $Id: zeus_webserver_37829.nasl 14 2013-10-27 12:33:37Z jan $
#
# Zeus Web Server 'SSL2_CLIENT_HELLO' Remote Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "Zeus Web Server is prone to a buffer-overflow vulnerability because
the application fails to perform adequate boundary checks on user-
supplied data.

Attackers can exploit this issue to execute arbitrary code within the
context of the affected application. Failed exploit attempts will
result in a denial-of-service condition.

Versions prior to Zeus Web Server 4.3r5 are vulnerable.";


if (description)
{
 script_id(100452);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-20 10:52:14 +0100 (Wed, 20 Jan 2010)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-0359");
 script_bugtraq_id(37829);
 script_tag(name:"risk_factor", value:"Critical");

 script_name("Zeus Web Server 'SSL2_CLIENT_HELLO' Remote Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37829");
 script_xref(name : "URL" , value : "http://www.intevydis.com/");
 script_xref(name : "URL" , value : "http://www.zeus.co.uk");

 script_description(desc);
 script_summary("Determine if Zeus Web Server version is < 4.3");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Server: Zeus/" >!< banner)exit(0);

version = eregmatch(pattern: "Server: Zeus/([0-9.]+[r0-9]*)",string: banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version: "4.3r5")) {
  security_hole(port:port);
  exit(0); 
}

exit(0);
