###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_crypt_func_sec_bypass_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'crypt()' Function Security Bypass Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to bypass authentication
  via an arbitrary password.
  Impact Level: Application";
tag_affected = "PHP version 5.3.7";
tag_insight = "The flaw is due to an error in 'crypt()' function which returns the
  salt value instead of hash value when executed with MD5 hash, which allows
  attacker to bypass authentication via an arbitrary password.";
tag_solution = "Upgrade to PHP version 5.3.8 or later.
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(802329);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)");
  script_cve_id("CVE-2011-3189");
  script_bugtraq_id(48259);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("PHP 'crypt()' Function Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/74726");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45678");
  script_xref(name : "URL" , value : "http://www.php.net/archive/2011.php#id2011-08-22-1");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_php_detect_win.nasl");
  script_require_keys("PHP/Ver/win");
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

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(phpVer != NULL)
{
  ##To check PHP version equal to 5.3.7
  if(version_is_equal(version:phpVer, test_version:"5.3.7")){
    security_warning(0);
  }
}
