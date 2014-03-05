###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln_jun13_win.nasl 81 2013-11-27 14:04:23Z veerendragg $
#
# PHP Multiple Vulnerabilities - June13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code or cause
  denial of service condition via crafted arguments.
  Impact Level:System/ Application";

tag_affected = "PHP version before 5.3.26 and 5.4.x before 5.4.16";
tag_insight = "Multiple flaws are due to,
  - Heap-based overflow in 'php_quot_print_encode' function in
    'ext/standard/quot_print.c' script.
  - Integer overflow in the 'SdnToJewish' function in 'jewish.c' in the
    Calendar component.";
tag_solution = "Upgrade to PHP 5.4.16 or 5.3.26 or later,
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(803678);
  script_version("$Revision: 81 $");
  script_cve_id("CVE-2013-4635","CVE-2013-2110");
  script_bugtraq_id(60731, 60411);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-27 15:04:23 +0100 (Wed, 27 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-06-25 17:29:19 +0530 (Tue, 25 Jun 2013)");
  script_name("PHP Multiple Vulnerabilities - June13 (Windows)");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php");
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=64895");
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=64879");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-4635");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-2110");
  script_summary("Check for the vulnerable version of PHP on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("os_fingerprint.nasl","gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
phpPort = "";
phpVer = "";

## If its not windows exit
if(host_runs("windows") != "yes"){
  exit(0);
}

## Get the PHP port
phpPort = get_kb_item("Services/www");
if(!phpPort){
  phpPort = 80;
}

## Check for the PHP support
if(!get_port_state(phpPort)){
  exit(0);
}

## Get the PHP version
phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

if(!isnull(phpVer))
{
  ##Check for PHP version
  if((version_is_less(version:phpVer, test_version:"5.3.26"))||
    (version_in_range(version:phpVer, test_version:"5.4.0", test_version2: "5.4.15")))
  {
    security_warning(phpPort);
    exit(0);
  }
}
