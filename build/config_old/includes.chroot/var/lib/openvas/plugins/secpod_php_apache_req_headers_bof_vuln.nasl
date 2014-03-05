###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_apache_req_headers_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# PHP 'apache_request_headers()' Function Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "PHP Version 5.4.x before 5.4.3 on Windows";
tag_insight = "The flaw is due to an error in the 'apache_request_headers()'
  function, which can be exploited to cause a denial of service via a long
  string in the header of an HTTP request.";
tag_solution = "Upgrade to PHP Version 5.4.3 or later,
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(902837);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53455);
  script_cve_id("CVE-2012-2329");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-23 16:16:16 +0530 (Wed, 23 May 2012)");
  script_name("PHP 'apache_request_headers()' Function Buffer Overflow Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49014");
  script_xref(name : "URL" , value : "https://bugs.php.net/bug.php?id=61807");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53455");
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.4.3");
  script_xref(name : "URL" , value : "http://www.php.net/archive/2012.php#id2012-05-08-1");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=820000");

  script_description(desc);
  script_summary("Check for the version of PHP on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Buffer overflow");
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

phpVer = "";

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(phpVer)
{
  ## Check for PHP Version 5.4.3 and prior
   if(version_in_range(version: phpVer, test_version: "5.4.0", test_version2: "5.4.2")) {
    security_warning(0);
  }
}
