###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ViewVC_39053.nasl 14 2013-10-27 12:33:37Z jan $
#
# ViewVC Regular Expression Search Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "ViewVC is prone to a cross-site scripting vulnerability because the
application fails to sufficiently sanitize user-supplied data.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site and steal cookie-based authentication credentials. Other attacks
are also possible.

Versions prior to ViewVC 1.1.5 and 1.0.11 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100562);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-31 12:56:41 +0200 (Wed, 31 Mar 2010)");
 script_bugtraq_id(39053);
 script_cve_id("CVE-2010-0132");

 script_name("ViewVC Regular Expression Search Cross Site Scripting Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39053");
 script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-26/");
 script_xref(name : "URL" , value : "http://viewvc.tigris.org/source/browse/viewvc/trunk/CHANGES?rev=HEAD");
 script_xref(name : "URL" , value : "http://viewvc.org/");
 script_xref(name : "URL" , value : "http://viewvc.tigris.org/");

 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed ViewVC version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("viewvc_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"viewvc")) {

  if(version_in_range(version: vers, test_version: "1.1", test_version2: "1.1.4") ||
     version_is_less(version: vers, test_version: "1.0.11") ) {
       security_warning(port:port);
       exit(0);
  }

}

exit(0);
