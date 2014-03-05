###############################################################################
# OpenVAS Vulnerability Test
# $Id: bugzilla_35916.nasl 15 2013-10-27 12:49:54Z jan $
#
# Bugzilla 'show_bug.cgi' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Bugzilla is prone to an information-disclosure vulnerability.

Successful exploits will allow authenticated attackers to obtain
potentially sensitive information that may aid in further attacks.

The following are vulnerable:

Bugzilla 3.3.4, 3.4rc1, and 3.4.";


tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100263);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-28 10:47:21 +0200 (Fri, 28 Aug 2009)");
 script_bugtraq_id(35916);
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Bugzilla 'show_bug.cgi' Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35916");
 script_xref(name : "URL" , value : "http://www.bugzilla.org");
 script_xref(name : "URL" , value : "http://www.bugzilla.org/security/3.4/");

 script_description(desc);
 script_summary("Determine if Bugzilla version is <=3.3.4 and/or <3.4.1");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("bugzilla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(Ver = get_kb_item(string("www/", port, "/bugzilla/version"))) {
  if(version_in_range(version:Ver, test_version:"3.3", test_version2:"3.3.4") ||
     version_in_range(version:Ver, test_version:"3.4", test_version2:"3.4.0")){
     security_warning(port:port);
  }
}
