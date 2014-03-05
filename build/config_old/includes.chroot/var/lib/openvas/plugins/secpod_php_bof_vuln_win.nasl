###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'socket_connect()' Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code or to cause denial of service condition.
  Impact Level: Application";
tag_affected = "PHP Version 5.3.5 and prior on windows.";
tag_insight = "The flaw is due to an error in the 'socket_connect()' function within
  socket module. It uses memcpy to copy path from addr to s_un without checking
  addr length in case when AF_UNIX socket is used.";
tag_solution = "No solution or patch is available as of 26th, May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://php.net/downloads.php";
tag_summary = "This host is installed with PHP and is prone to stack buffer
  overflow vulnerability.";

if(description)
{
  script_id(902436);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-1938");
  script_bugtraq_id(47950);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP 'socket_connect()' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/May/472");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101665/cve20111938.txt");
  script_xref(name : "URL" , value : "http://www.bugsearch.net/en/11873/php-535-socketconnect-buffer-overflow-vulnerability-cve-2011-1938.html?ref=3");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
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

## Get version from KB
phpVer = get_kb_item("PHP/Ver/win");

if(phpVer != NULL)
{
  ##Check for PHP version <= 5.3.5
  if(version_is_less_equal(version:phpVer, test_version:"5.3.5")){
    security_hole(0);
  }
}
