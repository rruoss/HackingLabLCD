###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiki_43507.nasl 14 2013-10-27 12:33:37Z jan $
#
# Tiki Wiki CMS Groupware Local File Include and Cross Site Scripting Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Tiki Wiki CMS Groupware is prone to a local file-include vulnerability
and a cross-site scripting vulnerability because it fails to properly
sanitize user-supplied input.

An attacker can exploit the local file-include vulnerability using
directory-traversal strings to view and execute local files within
the context of the webserver process. Information harvested may aid
in further attacks.

The attacker may leverage the cross-site scripting issue to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may let the attacker steal cookie-
based authentication credentials and launch other attacks.

Tiki Wiki CMS Groupware 5.2 is vulnerable; other versions may also
be affected.";


SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100825";
CPE = "cpe:/a:tikiwiki:tikiwiki";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-28 17:11:37 +0200 (Tue, 28 Sep 2010)");
 script_bugtraq_id(43507);

 script_name("Tiki Wiki CMS Groupware Local File Include and Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43507");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Tiki.Wiki.CMS.Groupware.5.2.Local.File.Inclusion/46");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Tiki.Wiki.CMS.Groupware.5.2.Reflected.Cross-site.Scripting/44");
 script_xref(name : "URL" , value : "http://www.tiki.org");

 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if Tiki Wiki CMS Groupware is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_tikiwiki_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("TikiWiki/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  url =  string(dir,"/tiki-edit_wiki_section.php?type=%22%3E%3Cscript%3Ealert(%27openvas-xss-test%27)%3C/script%3E");

  if(http_vuln_check(port:port,url:url,pattern:"<script>alert\('openvas-xss-test'\)</script>",bodyonly:TRUE)) {

    security_hole(port:port);
    exit(0);

  }  

}

exit(0);
