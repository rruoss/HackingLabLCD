###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_zend_mult_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP Zend and GD Multiple Denial of Service Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow local attackers to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application/Network";
tag_affected = "PHPversion prior to 5.2.15 and 5.3.x before 5.3.4";
tag_insight = "The flaws are due to:
  - An use-after-free error in the 'Zend' engine, which allows remote attackers
    to cause a denial of service.
  - A stack-based buffer overflow in the 'GD' extension, which allows attackers
    to cause a denial of service.";
tag_solution = "upgrade to PHP 5.3.5 or later
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to multiple denial of
  service vulnerabilities.";

if(description)
{
  script_id(801586);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-4697", "CVE-2010-4698");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP Zend and GD Multiple Denial of Service Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://bugs.php.net/52879");
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("php/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

phpPort = get_kb_item("Services/www");
if(!phpPort){
  phpPort = 80;
}

if(!get_port_state(phpPort)){
    exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

if(version_is_less(version:phpVer, test_version:"5.2.15") ||
   version_in_range(version:phpVer, test_version:"5.3", test_version2:"5.3.3")){
  security_hole(phpPort);
}
