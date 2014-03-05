###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_dos_vuln_jun13_win.nasl 81 2013-11-27 14:04:23Z veerendragg $
#
# PHP Denial of Service Vulnerability - June13 (Windows)
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
tag_impact = "Successful exploitation could allow attackers to cause denial of service
  (invalid pointer dereference and application crash) via an MP3 file.
  Impact Level: Application";

tag_affected = "PHP version before 5.4.X before 5.4.16";
tag_insight = "Flaw in 'mget' function in libmagic/softmagic.c, which triggers incorrect
  MIME type detection during access to an finfo object.";
tag_solution = "Upgrade to PHP 5.4.16 or later,
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone denial of service
  vulnerability.";

if(description)
{
  script_id(803677);
  script_version("$Revision: 81 $");
  script_cve_id("CVE-2013-4636");
  script_bugtraq_id(60728);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-27 15:04:23 +0100 (Wed, 27 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-06-25 17:10:23 +0530 (Tue, 25 Jun 2013)");
  script_name("PHP Denial of Service Vulnerability - June13 (Windows)");
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
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=64830");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-4636");
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

if(!isnull(phpVer) && phpVer =~ "^(5\.4)")
{
  ##Check for PHP version
  if(version_in_range(version:phpVer, test_version:"5.4", test_version2: "5.4.15"))
  {
    security_warning(phpPort);
    exit(0);
  }
}
