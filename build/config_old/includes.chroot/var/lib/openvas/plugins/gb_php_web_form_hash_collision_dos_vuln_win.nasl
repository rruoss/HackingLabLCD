###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_web_form_hash_collision_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP Web Form Hash Collision Denial of Service Vulnerability (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to cause a denial
  of service via a specially crafted form sent in a HTTP POST request.
  Impact Level: Application";
tag_affected = "PHP Version 5.3.8 and prior.";
tag_insight = "The flaws are due to an error in,
  - A hash generation function when hashing form posts and updating a hash
    table. This can be exploited to cause a hash collision resulting in high
    CPU consumption via a specially crafted form sent in a HTTP POST request.
  - PDORow implementation, when interacting with the session feature.
  - timezone functionality, when handling php_date_parse_tzfile cache.";
tag_solution = "Upgrade PHP to 5.3.9 or later,
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone to remote denial of
  service vulnerability.";

if(description)
{
  script_id(802408);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-4885", "CVE-2012-0788", "CVE-2012-0789");
  script_bugtraq_id(51193, 51952, 52043);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-03 16:47:40 +0530 (Tue, 03 Jan 2012)");
  script_name("PHP Web Form Hash Collision Denial of Service Vulnerability (Win)");
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
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_detect_win.nasl");
  script_require_keys("PHP/Ver/win");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47404");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/903934");
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=53502");
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=55776");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72021");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18305/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18296/");
  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name : "URL" , value : "http://svn.php.net/viewvc?view=revision&amp;revision=321040");
  exit(0);
}


include("version_func.inc");

phpVer = NULL;

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(!isnull(phpVer))
{
  ##Check for PHP version
  if(version_is_less_equal(version:phpVer, test_version:"5.3.8")){
    security_warning(0);
  }
}
