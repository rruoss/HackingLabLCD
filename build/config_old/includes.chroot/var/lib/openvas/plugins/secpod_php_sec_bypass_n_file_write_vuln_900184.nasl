###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_sec_bypass_n_file_write_vuln_900184.nasl 16 2013-10-27 13:09:52Z jan $
#
# PHP Security Bypass and File Writing Vulnerability - Dec08
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
tag_impact = "Successful exploitation could allow remote attackers to write arbitrary file,
  bypass security restrictions and cause directory traversal attacks.
  Impact Level: System/Application";
tag_affected = "PHP versions prior to 5.2.7.";
tag_insight = "The flaw is due to,
  - An error in initialization of 'page_uid' and 'page_gid' global variables
    for use by the SAPI 'php_getuid' function, which bypass the safe_mode
    restrictions.
  - When 'safe_mode' is enabled through a 'php_admin_flag' setting in
    'httpd.conf' file, which does not enforce the 'error_log', 'safe_mode
    restrictions.
  - In 'ZipArchive::extractTo' function which allows attacker to write files
    via a ZIP file.";
tag_solution = "Upgrade to version 5.2.7 or later
  http://www.php.net/downloads.php";
tag_summary = "The host is running PHP and is prone to Security Bypass and File
  Writing vulnerability.";

if(description)
{
  script_id(900184);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5624", "CVE-2008-5625", "CVE-2008-5658");
  script_bugtraq_id(32383, 32625, 32688);
  script_name("PHP Security Bypass and File Writing Vulnerability - Dec08");
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
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.2.7");
  script_xref(name : "URL" , value : "http://www.php.net/archive/2008.php#id2008-12-07-1");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/498985/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of PHP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
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

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}
# Grep for version 5.x to 5.2.6
if(version_in_range(version:phpVer, test_version:"5.0", test_version2:"5.2.6")){
  security_hole(phpPort);
}
