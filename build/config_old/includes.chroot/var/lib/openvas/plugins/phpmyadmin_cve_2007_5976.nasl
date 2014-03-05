###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpmyadmin_cve_2007_5976.nasl 15 2013-10-27 12:49:54Z jan $
#
# phpMyAdmin DB_Create.PHP Multiple Input Validation Vulnerabilities
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
tag_summary = "phpMyAdmin is prone to multiple input-validation vulnerabilities, including a
  cross-site scripting and a SQL-injection issue.

  A successful exploit may allow an attacker to steal cookie-based
  authentication credentials, compromise the application, access or modify data,
  or exploit latent vulnerabilities in the underlying database.

  These issues affect versions prior to phpMyAdmin 2.11.2.1.";

tag_solution = "Vendor updates are available. Please see http://www.phpmyadmin.net for more
  Information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100067";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-21 10:04:15 +0100 (Sat, 21 Mar 2009)");
 script_bugtraq_id(26512);
 script_cve_id("CVE-2007-5976","CVE-2007-5977");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("phpMyAdmin DB_Create.PHP Multiple Input Validation Vulnerabilities");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if phpMyAdmin is vulnerable to Multiple Input Validation Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("phpMyAdmin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/26512");
 exit(0);
}


 include("http_func.inc");
 include("version_func.inc");
 include("host_details.inc");

 if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

 if(!get_port_state(port))exit(0);

 if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

 if (version_is_less_equal(version:version, test_version:"2.11.1") ) { 
      security_hole(port:port);
      exit(0);
  }

exit(0);
