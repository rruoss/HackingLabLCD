###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_vuln_dec09.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP Multiple Vulnerabilities Dec-09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow local attackers to bypass certain
  security restrictions and cause denial of service.
  Impact Level: Network";
tag_affected = "PHP version 5.2.10 and prior.
  PHP version 5.3.x before 5.3.1";
tag_insight = "Multiple flaws are due to:
   - Error in 'proc_open()' function in 'ext/standard/proc_open.c' that does not
     enforce the 'safe_mode_allowed_env_vars' and 'safe_mode_protected_env_vars'
     directives, which allows attackers to execute programs with an arbitrary
     environment via the env parameter.
   - Error in 'zend_restore_ini_entry_cb()' function in 'zend_ini.c', which
     allows attackers to obtain sensitive information.";
tag_solution = "Upgrade to PHP version 5.3.1
  http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(801060);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-04 14:17:59 +0100 (Fri, 04 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4018","CVE-2009-2626");
  script_bugtraq_id(37138, 36009);
  script_name("PHP Multiple Vulnerabilities Dec-09");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37482");
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=49026");
  script_xref(name : "URL" , value : "http://securityreason.com/achievement_securityalert/65");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/11/23/15");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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


include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

phpPort = get_kb_item("Services/www");
if(!phpPort)
{
  phpPort = 80;
  if(!get_port_state(phpPort)){
    exit(0);
  }
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

if(version_is_less(version:phpVer, test_version:"5.2.11")){
  security_hole(port: phpPort);
  exit(0);
}

else if(phpVer =~ "^5\.3")
{
  if(version_is_less(version:phpVer, test_version:"5.3.1")){
   security_hole(port: phpPort);
  }
}
