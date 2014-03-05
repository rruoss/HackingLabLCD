###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_labwiki_50608.nasl 13 2013-10-27 12:16:33Z jan $
#
# LabWiki Multiple Cross Site Scripting And Arbitrary File Upload Vulnerabilities
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
tag_summary = "LabWiki is prone to multiple cross-site scripting and arbitrary file
upload vulnerabilities because the software fails to sufficiently
sanitize user-supplied input

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site and to upload arbitrary files and execute arbitrary code with
administrative privileges. This may allow the attacker to steal cookie-
based authentication credentials and to launch other attacks.

LabWiki 1.1 and prior are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(103330);
 script_bugtraq_id(50608);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
 script_name("LabWiki Multiple Cross Site Scripting And Arbitrary File Upload Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50608");
 script_xref(name : "URL" , value : "http://www.bioinformatics.org/phplabware/labwiki/");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-15 09:50:33 +0100 (Tue, 15 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed LabWiki is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/LabWiki","/labwiki","/wiki",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir,'/index.php?from=";></><script>alert(/openvas-xss-test/)</script>&help=true&page=What_is_wiki'); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE)) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

