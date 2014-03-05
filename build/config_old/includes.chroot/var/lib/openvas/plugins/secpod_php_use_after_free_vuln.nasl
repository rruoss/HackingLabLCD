###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_use_after_free_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'substr_replace()' Use After Free Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of a web server. Failed attempts will likely result in
  denial-of-service conditions.
  Impact Level: Network";
tag_affected = "PHP version 5.3.6 and prior.";
tag_insight = "The flaw is due to passing the same variable multiple times to the
  'substr_replace()' function, which makes the PHP to use the same pointer in
  three variables inside the function.";
tag_solution = "No solution or patch is available as of 21st March 2011, Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to Use After Free vulnerability.";

if(description)
{
  script_id(902356);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_cve_id("CVE-2011-1148");
  script_bugtraq_id(46843);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP 'substr_replace()' Use After Free Vulnerability");
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
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=54238");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/03/13/3");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
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

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

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

if(version_is_less_equal(version:phpVer, test_version:"5.3.6")){
  security_hole(phpPort);
}
