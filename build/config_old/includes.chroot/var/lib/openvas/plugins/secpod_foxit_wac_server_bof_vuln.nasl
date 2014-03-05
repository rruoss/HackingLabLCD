###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_wac_server_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Foxit WAC Server Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attackers execute arbitrary code
  and crash the application to cause denial of service.";
tag_affected = "Foxit WAC Server 2.0 Build 3503 and prior on Windows.";
tag_insight = "A heap-based buffer-overflow occurs in the 'wacsvr.exe' while processing
  overly long packets sent to SSH/Telnet ports.";
tag_solution = "No solution or patch is available as of 27th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.foxitsoftware.com/wac/server_intro.php";
tag_summary = "This host is running Foxit WAC Server and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(900924);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-7031");
  script_bugtraq_id(27873);
  script_name("Foxit WAC Server Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28272/");
  script_xref(name : "URL" , value : "http://aluigi.org/adv/wachof-adv.txt");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/40608");

  script_description(desc);
  script_summary("Check for the version of Foxit WAC Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_foxit_wac_server_detect.nasl");
  script_require_keys("Foxit-WAC-Server/Ver");
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

wacPort = 22;
if(!get_port_state(wacPort))
{
  wacPort = 23;
  if(!get_port_state(wacPort)){
    exit(0);
  }
}

wacVer = get_kb_item("Foxit-WAC-Server/Ver");
if(!wacVer){
  exit(0);
}

# Grep for version 2.0.3503 and prior.
if(version_is_less_equal(version:wacVer, test_version:"2.0.Build.3503")){
  security_hole(wacPort);
}
