###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_calibre_45532.nasl 13 2013-10-27 12:16:33Z jan $
#
# Calibre Cross Site Scripting and Directory Traversal Vulnerabilities
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
tag_summary = "Calibre is prone to a cross-site scripting vulnerability and a directory-
traversal vulnerability because it fails to sufficiently sanitize user-
supplied input.

Exploiting these issues will allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, and to view arbitrary local files and directories
within the context of the webserver. This may let the attacker steal
cookie-based authentication credentials and other harvested
information may aid in launching further attacks.

Calibre 0.7.34 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103011);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
 script_bugtraq_id(45532);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Calibre Cross Site Scripting and Directory Traversal Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45532");
 script_xref(name : "URL" , value : "http://www.waraxe.us/advisory-77.html");
 script_xref(name : "URL" , value : "http://calibre-ebook.com/");

 script_description(desc);
 script_summary("Determine if installed Calibre is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/static/",crap(data:"../",length:3*9),files[file],".");  

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}
exit(0);
