###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_mult_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP Multiple Security Bypass Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-02-04
#  - Added CVE and updated description 
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
tag_impact = "Successful exploitation could allow remote attackers to trigger an incomplete
  output array, and possibly bypass spam detection or have unspecified other
  impact.
  Impact Level: Application/Network";
tag_affected = "PHP version prior to 5.3.4";
tag_insight = "The flaws are caused to:
  - An error in handling pathname which accepts the '?' character in a
    pathname.
  - An error in 'iconv_mime_decode_headers()' function in the 'Iconv'
    extension.
  - 'SplFileInfo::getType' function in the Standard PHP Library (SPL) extension,
    does not properly detect symbolic links in windows.
  - Integer overflow in the 'mt_rand' function.
  - Race condition in the 'PCNTL extension', when a user-defined signal handler exists.";
tag_solution = "upgrade to PHP 5.3.4 or later
  For updates refer to http://www.php.net/downloads.php";
tag_summary = "This host is running PHP and is prone to multiple security
  bypass vulnerability.";

if(description)
{
  script_id(801585);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2006-7243", "CVE-2010-4699", "CVE-2011-0754",
                "CVE-2011-0753", "CVE-2011-0755");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("PHP Multiple Security Bypass Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php");
  script_xref(name : "URL" , value : "http://www.php.net/releases/5_3_4.php");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2010/12/09/9");
  script_xref(name : "URL" , value : "http://svn.php.net/viewvc?view=revision&amp;revision=305507");
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

if(version_is_less(version:phpVer, test_version:"5.3.4")){
  security_warning(port:phpPort);
}
