###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_41269.nasl 14 2013-10-27 12:33:37Z jan $
#
# Splunk Cross Site Scripting and Directory Traversal Vulnerabilities
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
tag_summary = "Splunk is prone to multiple cross-site scripting vulnerabilities and
multiple directory-traversal vulnerabilities because it fails to
sufficiently sanitize user-supplied input.

Exploiting these issues will allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site, and to view arbitrary local files and directories
within the context of the webserver. This may let the attacker steal
cookie-based authentication credentials and other harvested
information may aid in launching further attacks.";


if (description)
{
 script_id(100694);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)");
 script_bugtraq_id(41269);

 script_name("Splunk Cross Site Scripting and Directory Traversal Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41269");
 script_xref(name : "URL" , value : "http://www.splunk.com/view/SP-CAAAFGD#31067");
 script_xref(name : "URL" , value : "http://www.splunk.com/");

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed Splunk version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_splunk_detect.nasl");
 script_require_ports("Services/www", 8000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

vers = get_kb_item(string("www/", port, "/splunk"));

if(!isnull(vers)) {

  if(version_in_range(version: vers, test_version: "4.0", test_version2:"4.0.10") ||
     version_in_range(version: vers, test_version: "4.1", test_version2:"4.1.1")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
