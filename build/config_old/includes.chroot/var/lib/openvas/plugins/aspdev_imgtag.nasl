# OpenVAS Vulnerability Test
# $Id: aspdev_imgtag.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ASP-DEv XM Forum IMG Tag Script Injection Vulnerability
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web server contains an ASP script which is vulnerable to a
cross site scripting issue.

Description :

The remote host appears to be running the ASP-DEV XM Forum.

There is a flaw in the remote software which may allow anyone
to inject arbitrary HTML and script code through the BBCode IMG tag
to be executed in a user's browser within the context of the affected
web site.";

tag_solution = "Unknown at this time.";

# Fixed by Tenable:
#  - Improved description
#  - Adjusted version regex.
#  - Streamlined code.

if(description)
{
 script_id(18357);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1008");
 script_bugtraq_id(12958);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "ASP-DEv XM Forum IMG Tag Script Injection Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "ASP-DEV XM Forum IMG Tag Script Injection Vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_family("Web application abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_asp(port:port)) exit(0);

function check(url)
{
 req = http_get(item:url +"/default.asp", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);
 if ( res =~ '<a href="http://www\\.asp-dev\\.com">Powered by ASP-DEv XM Forums RC [123]<' )
 {
        security_warning(port);
        exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}

