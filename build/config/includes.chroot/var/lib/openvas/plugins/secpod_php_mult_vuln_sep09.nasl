###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_mult_vuln_sep09.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP Multiple Vulnerabilities - Sep09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to spoof certificates and can
  cause unknown impacts in the context of the web application.
  Impact Level: Application";
tag_affected = "PHP version prior to 5.2.11";
tag_insight = "- An error in 'php_openssl_apply_verification_policy' function that does not
    properly perform certificate validation.
  - An input validation error exists in the processing of 'exif' data.
  - An unspecified error exists related to the sanity check for the color index
    in the 'imagecolortransparent' function.";
tag_solution = "Upgrade to version 5.2.11 or later
  http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(900871);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293");
  script_bugtraq_id(36449);
  script_name("PHP Multiple Vulnerabilities - Sep09");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36791");
  script_xref(name : "URL" , value : "http://www.php.net/releases/5_2_11.php");
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.2.11");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/09/20/1");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
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


include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!isnull(phpVer))
{
  # Check for PHP version 5.2.11
  if(version_is_less(version:phpVer, test_version:"5.2.11")){
    security_hole(phpPort);
  }
}
