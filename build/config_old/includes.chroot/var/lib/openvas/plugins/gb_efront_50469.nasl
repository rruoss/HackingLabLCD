###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_efront_50469.nasl 13 2013-10-27 12:16:33Z jan $
#
# eFront Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "eFront is prone to multiple cross-site scripting vulnerabilities
because the software fails to sufficiently sanitize user-
supplied input

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

eFront 3.6.10 build 11944 is vulnerable; other versions may also
be affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(103324);
 script_bugtraq_id(50469);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("eFront Multiple Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50469");
 script_xref(name : "URL" , value : "http://www.efrontlearning.net/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520351");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-02 08:00:00 +0100 (Mon, 02 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed eFront is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("secpod_efront_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"eFront"))exit(0);

url = string(dir, "/www/index.php?ctg=lesson_info&lessons_ID=2&course=%27%20onmouseover=%27alert(/openvas-xss-test/)%27;"); 

if(http_vuln_check(port:port, url:url,pattern:"' onmouseover='alert\(/openvas-xss-test/\)';'>Information for",check_header:TRUE)) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);

