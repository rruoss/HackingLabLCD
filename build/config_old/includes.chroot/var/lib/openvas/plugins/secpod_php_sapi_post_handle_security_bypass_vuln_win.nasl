###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_sapi_post_handle_security_bypass_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP SAPI_POST_HANDLER_FUNC() Security Bypass Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to delete files from
  the root directory, which may aid in further attacks.
  Impact Level: System/Application";
tag_affected = "PHP version prior to 5.3.7";
tag_insight = "The flaw is due to an error in 'SAPI_POST_HANDLER_FUNC()' function in
  rfc1867.c when handling files via a 'multipart/form-data' POST request. which
  allows attacker to bypass security restriction.";
tag_solution = "Upgrade to PHP version 5.3.7 or later.
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(902606);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2202");
  script_bugtraq_id(48259);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP SAPI_POST_HANDLER_FUNC() Security Bypass Vulnerability");
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
  script_copyright("Copyright (C) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44874");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025659");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67999");
  script_xref(name : "URL" , value : "http://svn.php.net/viewvc?view=revision&amp;revision=312103");
  exit(0);
}


include("version_func.inc");

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");
if(phpVer != NULL)
{
  ##To check PHP version prior to 5.3.7
  if(version_is_less(version:phpVer, test_version:"5.3.7")){
    security_hole(0);
  }
}
