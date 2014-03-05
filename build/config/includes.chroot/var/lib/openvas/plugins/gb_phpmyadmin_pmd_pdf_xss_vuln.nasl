###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_pmd_pdf_xss_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# phpMyAdmin pmd_pdf.php Cross Site Scripting Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Allows execution of arbitrary HTML and script code, and steal cookie-based
  authentication credentials.
  Impact Level: System";
tag_affected = "phpMyAdmin phpMyAdmin versions 3.0.1 and prior on all running platform.";
tag_insight = "Input passed to the 'db' parameter in pmd_pdf.php file is not properly
  sanitised before returning to the user.";
tag_solution = "Upgrade to phpMyAdmin 3.0.1.1 or later";
tag_summary = "This host is running phpMyAdmin and is prone to cross site scripting
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800301";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-4775");
  script_bugtraq_id(31928);
  script_name("phpMyAdmin pmd_pdf.php Cross Site Scripting Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://secunia.com/advisories/32449/");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2008/Oct/0199.html");

  script_description(desc);
  script_summary("Check for the Version of phpMyAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpMyAdmin/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

phpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);

if(phpVer){
  # Grep for version 3.0.1 and prior
  if(version_is_less_equal(version:phpVer[0], test_version:"3.0.1")){
    security_warning(port);
  }
}
