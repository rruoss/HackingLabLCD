###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netmri_50646.nasl 12 2013-10-27 11:15:33Z jan $
#
# Infoblox NetMRI Admin Login Page Multiple Cross Site Scripting Vulnerabilities
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
tag_summary = "Infoblox NetMRI is prone to multiple cross-site scripting
vulnerabilities because it fails to properly sanitize user-supplied
input before using it in dynamically generated content.

An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

Infoblox NetMRI versions 6.2.1, 6.1.2, and 6.0.2.42 are vulnerable;
other versions may also be affected.";

tag_solution = "Reportedly the vendor has released an update to fix the issue.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103576";
CPE = "cpe:/a:infoblox:netmri";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(50646);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 12 $");

 script_name("Infoblox NetMRI Admin Login Page Multiple Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50646");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Nov/158");
 script_xref(name : "URL" , value : "http://www.infoblox.com/en/products/netmri.html");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-25 12:37:48 +0200 (Tue, 25 Sep 2012)");
 script_description(desc);
 script_summary("Determine if installed NetMRI version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_netmri_detect.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("netMRI/installed");
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

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(vers =  get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {

  if(version_is_equal(version: vers, test_version: "6.2.1") ||
     version_is_equal(version: vers, test_version: "6.1.2") ||
     version_is_equal(version: vers, test_version: "6.0.2.42")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);
