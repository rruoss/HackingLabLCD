###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_sec_bypass_vuln_aug09.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP Security Bypass Vulnerability - Aug09
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
tag_impact = "Successful exploitation will let the local attacker execute arbitrary code and
  can bypass security restriction in the context of the web application.
  Impact Level: Application";
tag_affected = "PHP version 5.2.5";
tag_insight = "Error exists when application fails to enforce 'safe_mode_exec_dir' and
  'open_basedir' restrictions for certain functions, which can be caused via
  the exec, system, shell_exec, passthru, or popen functions, possibly
  involving pathnames such as 'C:' drive notation.";
tag_solution = "Upgrade to PHP version 5.3.2 or later,
  For updates refer to http://www.php.net/";
tag_summary = "This host is running PHP and is prone to Security Bypas vulnerability.";

if(description)
{
  script_id(900835);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-7002");
  script_bugtraq_id(31064);
  script_name("PHP Security Bypass Vulnerability - Aug09");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/383831.php");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/31064.php");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
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

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

phpPort = get_http_port(default:80);
if(!phpPort)
{
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!isnull(phpVer))
{
  # Check for PHP version 5.2.5
  if(version_is_equal(version:phpVer, test_version:"5.2.5")){
    security_hole(phpPort);
  }
}
