# OpenVAS Vulnerability Test
# $Id: phpgroupware_html_injection2.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PhpGroupWare index.php HTML injection vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host seems to be running PhpGroupWare, a multi-user groupware 
suite written in PHP.

This version has been reported prone to HTML injection vulnerabilities
through 'index.php'.  These issues present themself due to a lack of
sufficient input validation performed on form fields used by
PHPGroupWare modules. 

A malicious attacker may inject arbitrary HTML and script code using
these form fields that may be incorporated into dynamically generated
web content.";

tag_solution = "Update to version 0.9.16 RC3 or newer";

# Ref: Cedric Cochin <cco@netvigilance.com>

if(description)
{
 script_id(16138);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2574");
 script_bugtraq_id(12082);
 script_xref(name:"OSVDB", value:"7599");
 script_xref(name:"OSVDB", value:"7600");
 script_xref(name:"OSVDB", value:"7601");
 script_xref(name:"OSVDB", value:"7602");
 script_xref(name:"OSVDB", value:"7603");
 script_xref(name:"OSVDB", value:"7604");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "PhpGroupWare index.php HTML injection vulnerabilities";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";
 script_description(desc);
 
 summary = "Checks for PhpGroupWare version";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.phpgroupware.org/");
 exit(0);
}

#
# the code
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/phpsysinfo/inc/hook_admin.inc.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);

 if(egrep(pattern:".*Fatal error.* in <b>/.*", string:res)){
        security_warning(port);
        exit(0);
 }
}
