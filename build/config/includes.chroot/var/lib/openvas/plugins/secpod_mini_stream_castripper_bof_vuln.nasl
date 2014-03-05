###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mini_stream_castripper_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mini-stream CastRipper Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes into
  the contenxt of the application and can crash the application.
  Impact Level: Application.";
tag_affected = "CastRipper version 2.50.70 (2.9.6.0) and prior.
  CastRipper version 2.10.00";
tag_insight = "This flaw is due to a boundary error check when processing user supplied
  input data through '.M3U' files with overly long URI.";
tag_solution = "No solution or patch is available as of 22nd May, 2009. Information
  regarding this issue will be updated once the solution details are available
  For updates refer to http://mini-stream.net/castripper";
tag_summary = "This host is installed with Mini-Stream CastRipper and is prone to Stack
  Overflow Vulnerability.";

if(description)
{
  script_id(900651);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-22 10:20:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1667");
  script_name("Mini-stream CastRipper Stack Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35069");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8660");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8661");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8662");

  script_description(desc);
  script_summary("Checks for the version of Mini Stream CastRipper");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
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

castripperVer = get_kb_item("MiniStream/CastRipper/Ver");
if(castripperVer)
{
   # Ministream CastRipper 2.50.70 points to version 2.9.6.0 & version 2.10.00
   if(version_is_less_equal(version:castripperVer, test_version:"2.9.6.0") ||
      version_is_equal(version:castripperVer, test_version:"2.10.00")){
    security_hole(0);
  }
}
