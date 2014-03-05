###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_mar12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apple iTunes Multiple Vulnerabilities - Mar12 (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let attackers to cause a denial of service or
  possibly execute arbitrary code or inject html code via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Apple iTunes version prior to 10.6 (10.6.0.40) on Windows";
tag_insight = "For more details about the vulnerabilities refer to the links given below.";
tag_solution = "Upgrade to Apple Apple iTunes version 10.6 or later,
  For updates refer to http://www.apple.com/itunes/download/";
tag_summary = "This host is installed with Apple iTunes and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802824);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-2825", "CVE-2011-2833", "CVE-2011-2846", "CVE-2011-2847",
                "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2857", "CVE-2011-2860",
                "CVE-2011-2866", "CVE-2011-2867", "CVE-2011-2868", "CVE-2011-2869",
                "CVE-2011-2870", "CVE-2011-2871", "CVE-2011-2872", "CVE-2011-2873",
                "CVE-2011-2877", "CVE-2011-3885", "CVE-2011-3888", "CVE-2011-3897",
                "CVE-2011-3908", "CVE-2011-3909", "CVE-2012-0591", "CVE-2012-0592",
                "CVE-2012-0593", "CVE-2012-0594", "CVE-2012-0595", "CVE-2012-0596",
                "CVE-2012-0597", "CVE-2012-0598", "CVE-2012-0599", "CVE-2012-0600",
                "CVE-2012-0601", "CVE-2012-0602", "CVE-2012-0603", "CVE-2012-0604",
                "CVE-2012-0605", "CVE-2012-0606", "CVE-2012-0607", "CVE-2012-0608",
                "CVE-2012-0609", "CVE-2012-0610", "CVE-2012-0611", "CVE-2012-0612",
                "CVE-2012-0613", "CVE-2012-0614", "CVE-2012-0615", "CVE-2012-0616",
                "CVE-2012-0617", "CVE-2012-0618", "CVE-2012-0619", "CVE-2012-0620",
                "CVE-2012-0621", "CVE-2012-0622", "CVE-2012-0623", "CVE-2012-0624",
                "CVE-2012-0625", "CVE-2012-0626", "CVE-2012-0627", "CVE-2012-0628",
                "CVE-2012-0629", "CVE-2012-0630", "CVE-2012-0631", "CVE-2012-0632",
                "CVE-2012-0633", "CVE-2012-0634", "CVE-2012-0635", "CVE-2012-0636",
                "CVE-2012-0637", "CVE-2012-0638", "CVE-2012-0639", "CVE-2012-0648");
  script_bugtraq_id(49279, 52365, 49658, 52363, 49938, 50360, 50642, 51041);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-20 16:59:10 +0530 (Tue, 20 Mar 2012)");
  script_name("Apple iTunes Multiple Vulnerabilities - Mar12 (Win)");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5191");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521910");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/Mar/msg00000.html");

  script_description(desc);
  script_summary("Check for the version of Apple iTunes");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_require_keys("iTunes/Win/Ver");
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

## Variable Initialization
ituneVer = "";

##Get the version from kb
ituneVer= get_kb_item("iTunes/Win/Ver");
if(!ituneVer){
  exit(0);
}

## Apple iTunes version < 10.6 (10.6.0.40)
if(version_is_less(version:ituneVer, test_version:"10.6.0.40")){
  security_hole(0);
}
