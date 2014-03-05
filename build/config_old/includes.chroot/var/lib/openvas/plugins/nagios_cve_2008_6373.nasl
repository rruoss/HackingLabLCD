###############################################################################
# OpenVAS Vulnerability Test
# $Id: nagios_cve_2008_6373.nasl 15 2013-10-27 12:49:54Z jan $
#
# Nagios External Commands and Adaptive Commands Unspecified
# Vulnerability 
#
# Authors
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
tag_summary = "Nagios is prone to an unspecified vulnerability related to the CGI
  submission of external commands and the processing of adaptive
  commands.

  Very little information is known about this issue. We will update
  this BID as soon as more information becomes available.

  The issue affects versions prior to Nagios 3.0.6.";

tag_solution = "The vendor has released updates. Please see http://www.nagios.org/
  for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100188";
CPE = "cpe:/a:nagios:nagios";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-06 14:55:27 +0200 (Wed, 06 May 2009)");
 script_bugtraq_id(32611);
 script_cve_id("CVE-2008-6373");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Nagios External Commands and Adaptive Commands Unspecified Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Check if the Version of Nagios is < 3.0.6");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("nagios_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("nagios/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32611");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "3.0.6")) {
      security_warning(port:port);
      exit(0);
  }  

}

exit(0);
