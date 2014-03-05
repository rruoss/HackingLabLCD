###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_imap_do_open_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'ext/imap/php_imap.c' Use After Free Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow local attackers to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application/Network";
tag_affected = "PHP version 5.2 before 5.2.15 and 5.3 before 5.3.4";
tag_insight = "The flaw is due to an erron in 'imap_do_open' function in the IMAP
  extension 'ext/imap/php_imap.c'.";
tag_solution = "upgrade to PHP 5.2.15 or 5.3.4
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(801583);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_cve_id("CVE-2010-4150");
  script_bugtraq_id(44980);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("PHP 'ext/imap/php_imap.c' Use After Free Denial of Service Vulnerability");
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
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/63390");
  script_xref(name : "URL" , value : "http://svn.php.net/viewvc?view=revision&amp;revision=305032");
  exit(0);
}


include("misc_func.inc");
include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

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
