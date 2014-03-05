###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_lppasswd_sec_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# CUPS 'lppasswd' Tool Localized Message String Security Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows remote attackers to gain privileges via a file
  that contains crafted localization data with format string specifiers.
  Impact Level: Application";
tag_affected = "CUPS versions 1.2.x, 1.3.x, 1.4.x on Linux.";
tag_insight = "The flaw is due to error within the '_cupsGetlang()' function, as used
  by 'lppasswd.c' in 'lppasswd', relies on an environment variable to determine
  the file that provides localized message strings.";
tag_solution = "No solution or patch is available as of 10th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cups.org/software.php";
tag_summary = "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to security bypass vulnerability.";

if(description)
{
  script_id(800488);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0393");
  script_bugtraq_id(38524);
  script_name("CUPS 'lppasswd' Tool Localized Message String Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.ubuntu.com/usn/USN-906-1");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=558460");

  script_description(desc);
  script_summary("Check for the version of CUPS Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
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

cupsPort = get_http_port(default:631);
if(!cupsPort){
  exit(0);
}

cupsVer = get_kb_item("www/"+ cupsPort + "/CUPS");
if(!cupsVer){
  exit(0);
}

if(cupsVer != NULL)
{
  # Check for CUPS version 1.2.x and 1.3.x, 1.4.x
  if(version_in_range(version:cupsVer, test_version:"1.4.0", test_version2:"1.4.1" ) ||
     version_in_range(version:cupsVer, test_version:"1.2.0", test_version2:"1.2.2" ) ||
     version_in_range(version:cupsVer, test_version:"1.3.0", test_version2:"1.3.10")){
    security_hole(cupsPort);
  }
}
