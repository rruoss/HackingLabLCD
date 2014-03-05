###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_stack_consumption_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP 'filter_var()' function Stack Consumption Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allows remote attackers to cause a
  denial of service (memory consumption and application crash) via a
  long e-mail address string.
  Impact Level: Network";
tag_affected = "PHP version 5.2 through 5.2.14 and 5.3 through 5.3.3";
tag_insight = "- The flaw exists due to error in 'filter_var()' function, when
    FILTER_VALIDATE_EMAIL mode is used while processing the long e-mail
    address string. 
  - A NULL pointer dereference vulnerability is exists in
   'ZipArchive::getArchiveComment'.";
tag_solution = "No solution or patch is available as of 23rd November, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to stack consumption
  vulnerability";

if(description)
{
  script_id(801547);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-23 14:41:37 +0100 (Tue, 23 Nov 2010)");
  script_cve_id("CVE-2010-3710", "CVE-2010-3709");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("PHP 'filter_var()' function Stack Consumption Vulnerability");
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
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=52929");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=646684");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514562/30/150/threaded");
 

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

if ( report_paranoia < 2 ) exit(0);

phpPort = get_kb_item("Services/www");
if(!phpPort){
  phpPort = 80;
}

if(!get_port_state(phpPort)){
    exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

if(version_in_range(version:phpVer, test_version:"5.2", test_version2:"5.2.14") ||
   version_in_range(version:phpVer, test_version:"5.3", test_version2:"5.3.3")){
  security_warning(phpPort);
}
