###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_format_string_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP 'phar_stream_flush' Format String Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to obtain sensitive information
  and possibly execute arbitrary code via a crafted phar:// URI.
  Impact Level: Network";
tag_affected = "PHP version 5.3 through 5.3.3";
tag_insight = "The flaws are due to:
  - An error in 'stream.c' in the phar extension, which allows attackers to
    obtain sensitive information.
  - An error in 'open_wrappers.c', allow remote attackers to bypass open_basedir
    restrictions via vectors related to the length of a filename.
  - An error in 'mb_strcut()' function in 'Libmbfl' , allows context-dependent
    attackers to obtain potentially sensitive information via a large value of
    the third parameter (aka the length parameter).";
tag_solution = "No solution or patch is available as of 24th November, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to format string
  vulnerability.";

if(description)
{
  script_id(902317);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_cve_id("CVE-2010-2950", "CVE-2010-3436", "CVE-2010-4156");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP 'phar_stream_flush' Format String Vulnerability");
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
  script_copyright("Copyright (c) 2010 SecPod");
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
  script_xref(name : "URL" , value : "http://security-tracker.debian.org/tracker/CVE-2010-2950");
  script_xref(name : "URL" , value : "http://php-security.org/2010/05/14/mops-2010-024-php-phar_stream_flush-format-string-vulnerability/index.html");
  exit(0);
}


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

## Get the PHP version
phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

## Check PHP version
if(version_in_range(version:phpVer, test_version:"5.3", test_version2:"5.3.3")){
  security_hole(phpPort);
}
