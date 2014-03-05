###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_faslo_player_m3u_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Faslo Player .m3u Playlist Processing Buffer Overflow Vulnerability
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Attackers can exploit this issue to execute arbitrary code by tricking users
  into opening crafted m3u playlist files and may cause Denial of Service.
  Impact Level: Application";
tag_affected = "Faslo Player version 7.0 on Windows.";
tag_insight = "A boundary error occurs when processing .m3u playlist files containing overly
  long data.";
tag_solution = "No solution or patch is available as of 20th November,2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.faslo.com/";
tag_summary = "The host is installed with Faslo Player and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(900254);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3969");
  script_name("Fasloi Player .m3u Playlist Processing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9487");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36444/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2395");

  script_description(desc);
  script_summary("Check for the version of Faslo Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_faslo_player_detect.nasl");
  script_require_keys("FasloPlayer/Ver");
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

fpVer = get_kb_item("FasloPlayer/Ver");
if(!fpVer){
  exit(0);
}

if(version_is_equal(version:fpVer, test_version:"7.0")){
  security_hole(0);
}
