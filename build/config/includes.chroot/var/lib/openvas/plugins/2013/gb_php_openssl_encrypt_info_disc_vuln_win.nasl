###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_openssl_encrypt_info_disc_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# PHP 'openssl_encrypt()' Function Information Disclosure Vulnerability (Win)
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
tag_solution = "Apply patch or upgrade latest version,
  http://www.php.net/downloads.php
  https://bugs.php.net/bug.php?id=61413

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information from process memory by providing zero bytes of input data.
  Impact Level: Application";

tag_affected = "PHP version 5.3.9 through 5.3.13 on windows";
tag_insight = "The flaw is due to error in 'openssl_encrypt()' function when handling empty
  $data strings which will allow an attacker to gain access to arbitrary pieces
  of information in current memory.";
tag_summary = "This host is installed with PHP and is prone to information
  disclosure vulnerability";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803164";
CPE = "cpe:/a:php:php";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6113");
  script_bugtraq_id(57462);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 16:39:00 +0530 (Thu, 24 Jan 2013)");
  script_name("PHP 'openssl_encrypt()' Function Information Disclosure Vulnerability (Win)");
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

  script_xref(name : "URL" , value : "http://www.osvdb.org/89424");
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=61413");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81400");
  script_xref(name : "URL" , value : "http://git.php.net/?p=php-src.git;a=commitdiff;h=270a406ac94b5fc5cc9ef59fc61e3b4b95648a3e");

  script_description(desc);
  script_summary("Check for the version of PHP on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("php/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

phpPort = "";
phpVer = "";

## Exit if its not windows
if(host_runs("Windows") != "yes")exit(0);

# get the port
if(!phpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

# check the port state
if(!get_port_state(phpPort))exit(0);

# get the version
if(!phpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:phpPort))exit(0);

## check the version
if(version_in_range(version:phpVer, test_version:"5.3.9", test_version2:"5.3.13")){
  security_warning(phpPort);
}
