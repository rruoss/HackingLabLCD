# OpenVAS Vulnerability Test
# $Id: odbc_tools_check.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ODBC tools check
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2002 David Kyger
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
tag_summary = "ODBC tools are present on the remote host.

ODBC tools could allow a malicious user to hijack and redirect ODBC traffic, 
obtain SQL user names and passwords or write files to the local drive of a 
vulnerable server.

Example: http://target/scripts/tools/getdrvrs.exe";

tag_solution = "Remove ODBC tools from the /scripts/tools directory.";

if(description)
{
  script_id(11872);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
# script_bugtraq_id();
# script_cve_id("");
 name = "ODBC tools check ";
 script_name(name);
 
 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;


 script_description(desc);
 
 summary = "Checks for the presence of ODBC tools";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2002 David Kyger");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);



flag = 0;

warning = string("
Many Web servers ship with default CGI scripts which allow for ODBC access
and configuration. Some of these test ODBC tools are present on the remote 
web server.

These tools could allow a malicious user to hijack and redirect ODBC 
traffic, obtain SQL user names and passwords or write files to the 
local drive of a vulnerable server.

Example: http://target/scripts/tools/getdrvrs.exe

The following ODBC tools were found on the server:");




port = get_http_port(default:80);

if(get_port_state(port)) {

   fl[0] = "/scripts/tools/getdrvrs.exe";
   fl[1] = "/scripts/tools/dsnform.exe";
 
   for(i=0;fl[i];i=i+1) 
   { 
    if(is_cgi_installed_ka(item:fl[i], port:port)) 
	{
        warning = warning + string("\n", fl[i]); 
        flag = 1;
        }
   }
    if (flag > 0) {
	warning += string("Solution : Remove the specified ODBC tools from the /scripts/tools directory.\n");
        security_hole(port:port, data:warning);
        } else {
          exit(0);
        }
}


