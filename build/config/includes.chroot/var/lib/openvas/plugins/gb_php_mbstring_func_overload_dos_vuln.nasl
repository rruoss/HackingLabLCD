###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mbstring_func_overload_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP 'mbstring.func_overload' DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the local attackers to crash an affected web
  server.
  Impact Level: Application";
tag_affected = "PHP version 4.4.4 and prior
  PHP 5.1.x to 5.1.6
  PHP 5.2.x to 5.2.5";
tag_insight = "This bug is due to an error in 'mbstring.func_overload' setting in .htaccess
  file. It can be exploited via modifying behavior of other sites hosted on
  the same web server which causes this setting to be applied to other virtual
  hosts on the same server.";
tag_solution = "No solution or patch is available as of 17th March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.php.net";
tag_summary = "The host is running PHP and is prone to denial of service vulnerability.";

if(description)
{
  script_id(800373);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0754");
  script_bugtraq_id(33542);
  script_name("PHP 'mbstring.func_overload' DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=27421");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=479272");

  script_description(desc);
  script_summary("Check for the version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
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
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

# Grep for vulnerable PHP versions
if(version_is_less_equal(version:phpVer, test_version:"4.4.4") ||
   version_in_range(version:phpVer, test_version:"5.1", test_version2:"5.1.6") ||
   version_in_range(version:phpVer, test_version:"5.2", test_version2:"5.2.5")){
  security_warning(phpPort);
}
