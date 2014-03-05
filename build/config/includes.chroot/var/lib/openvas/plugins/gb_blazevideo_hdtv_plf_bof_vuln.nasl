###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blazevideo_hdtv_plf_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Blazevideo HDTV Player PLF File Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attackers execute arbitrary
  codes within the context of the application and can cause heap overflow
  in the application.

  Impact level: Application";

tag_affected = "Blazevideo HDTV Player 3.5 and prior on all Windows platforms.";
tag_insight = "Player application fails while handling crafted arbitrary playlist plf files.";
tag_solution = "No solution or patch is available as of 13th February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.blazevideo.com/hdtv-player/index.htm";
tag_summary = "This host is running Blazevideo HDTV Player and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(800513);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-13 14:28:43 +0100 (Fri, 13 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0450");
  script_bugtraq_id(33588);
  script_name("Blazevideo HDTV Player PLF File Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7975");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2009-0450");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/filedesc/blazehdtv-hof.txt.html");

  script_description(desc);
  script_summary("Check for the version of Blazevideo HDTV Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_blazevideo_hdtv_detect.nasl");
  script_require_keys("Blazevideo/HDTV/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

blazeVer = get_kb_item("Blazevideo/HDTV/Ver");
if(blazeVer == NULL){
  exit(0);
}

#Grep for Blazevideo HDTV Player version 3.5 or prior.
if(version_is_less_equal(version:blazeVer, test_version:"3.5")){
  security_hole(0);
}
