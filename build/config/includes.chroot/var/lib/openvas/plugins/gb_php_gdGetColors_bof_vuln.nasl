###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_gdGetColors_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP '_gdGetColors()' Buffer Overflow Vulnerability
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
tag_solution = "Apply patches from SVN repository,
  http://svn.php.net/viewvc?view=revision&revision=289557

  *****
  NOTE: Ignore this warning if patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow attackers to potentially compromise a
  vulnerable system.
  Impact Level: System";
tag_affected = "PHP version 5.2.x to 5.2.11 and 5.3.0 on Linux.";
tag_insight = "The flaw is due to error in '_gdGetColors' function in gd_gd.c which fails to
  check certain colorsTotal structure member, whicn can be exploited to cause
  buffer overflow or buffer over-read attacks via a crafted GD file.";
tag_summary = "The host is running PHP and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(801123);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3546");
  script_bugtraq_id(36712);
  script_name("PHP '_gdGetColors()' Buffer Overflow Vulnerability");
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
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_php_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("php/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37080/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2930");
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&amp;m=125562113503923&amp;w=2");
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
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(phpVer)
{
  # Check PHP version 5.2.x through 5.2.11 or 5.3.0
  if(version_is_equal(version:phpVer, test_version:"5.3.0")||
     version_in_range(version:phpVer, test_version:"5.2",
                                     test_version2:"5.2.11")){
    security_hole(phpPort);
  }
}
