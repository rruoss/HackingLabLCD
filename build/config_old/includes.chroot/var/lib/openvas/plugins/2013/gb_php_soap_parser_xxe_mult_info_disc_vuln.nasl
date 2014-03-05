###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_soap_parser_xxe_mult_info_disc_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# PHP SOAP Parser Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803764";
CPE = "cpe:/a:php:php";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1824");
  script_bugtraq_id(62373);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-24 11:54:43 +0530 (Tue, 24 Sep 2013)");
  script_name("PHP SOAP Parser Multiple Information Disclosure Vulnerabilities");

  tag_summary =
"This host is installed with PHP and is prone to multiple information
disclosure vulnerabilities.";

  tag_vuldetect =
"Get the installed version of PHP with the help of detect NVT and check
the version is vulnerable or not.";

  tag_insight =
"Flaws are due to the way SOAP parser process certain SOAP objects (due to
allowed expansion of XML external entities during SOAP WSDL files parsing).";

  tag_impact =
"Successful exploitation will allow remote attackers to obtain sensitive
information.

Impact Level: Application";

  tag_affected =
"PHP version before 5.3.22 and 5.4.x before 5.4.12";

  tag_solution =
"Upgrade to PHP 5.3.22 or 5.4.12 or later,
http://www.php.net/downloads.php";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_xref(name : "URL" , value : "http://www.osvdb.org/90922");
  script_xref(name : "URL" , value : "http://php.net/ChangeLog-5.php");
  script_xref(name : "URL" , value : "http://git.php.net/?p=php-src.git;a=commit;h=afe98b7829d50806559acac9b530acb8283c3bf4");

  script_description(desc);
  script_summary("Check for the vulnerable version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("php/installed");
  script_require_keys("php/paranoia");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

function check_php_ver(phpversion, phpPort)
{
  ## check the version
  if(version_is_less(version:phpversion, test_version:"5.3.22") ||
     version_in_range(version:phpversion, test_version:"5.4.0", test_version2:"5.4.11"))
  {
    security_warning(phpPort);
    exit(0);
  }
}

## Variable Initialization
phpPort = "";
phpVer = "";

# get the port
if(!phpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# get the version
if(!phpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:phpPort)){
  exit(0);
}

## windows
if(host_runs("Windows") == "yes"){
  check_php_ver(phpversion:phpVer, phpPort:phpPort);
  exit(0);
}

## Linux with backport issue
if(get_kb_item("php/paranoia")){
  check_php_ver(phpversion:phpVer, phpPort:phpPort);
}
