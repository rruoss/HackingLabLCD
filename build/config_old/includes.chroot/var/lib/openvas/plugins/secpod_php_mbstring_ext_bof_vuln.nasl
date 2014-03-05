###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_mbstring_ext_bof_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Heap-based buffer overflow in 'mbstring' extension for PHP
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code via
  a crafted string containing an HTML entity.
  Impact Level: Application";
tag_affected = "PHP version 4.3.0 to 5.2.6 on all running platform.";
tag_insight = "The flaw is due to error in mbfilter_htmlent.c file in the mbstring
  extension. These can be exploited via mb_convert_encoding, mb_check_encoding,
  mb_convert_variables, and mb_parse_str functions.";
tag_solution = "Upgrade to version 5.2.7 or later,
  http://www.php.net/downloads.php";
tag_summary = "The host is running PHP and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(900185);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5557");
  script_bugtraq_id(32948);
  script_name("Heap-based buffer overflow in 'mbstring' extension for PHP");
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
  script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=45722");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2008-12/0477.html");

  script_description(desc);
  script_summary("Check for the Version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Buffer overflow");
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
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

# Grep for version 4.3.0 to 5.2.6
if(version_in_range(version:phpVer, test_version:"4.3.0", test_version2:"5.2.6")){
  security_hole(phpPort);
}
