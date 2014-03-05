###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mini_stream_rm_downloader_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mini Stream RM Downloader '.smi' File Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows remote attacker to execute arbitrary code on
  the system or cause the application to crash.
  Impact Level: Application";
tag_affected = "Mini-stream RM Downloader version 3.0.0.9 and prior.";
tag_insight = "The flaw is caused by improper bounds checking when processing '.smi' files
  and can be exploited via crafted '.smi' file to cause buffer overflow.";
tag_solution = "No solution or patch is available as of 31st, March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mini-stream.net/";
tag_summary = "The host is installed with Mini-stream RM Downloader and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902036);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_cve_id("CVE-2009-4761");
 script_bugtraq_id(34794);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mini Stream RM Downloader '.smi' File Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8594");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50266");

  script_description(desc);
  script_copyright("Copyright (c) 2010 SecPod");
  script_summary("Check the version of Mini-stream RM Downloader");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_mini_stream_prdts_detect.nasl");
  script_require_keys("MiniStream/RMDown/Ver");
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

# Get Mini-stream RM Downloader version
rmDownVer = get_kb_item("MiniStream/RMDown/Ver");
if(!rmDownVer){
  exit(0);
}

# Mini-stream RM Downloader version 3.0.0.9 => 3.0.2.1
if(version_is_less_equal(version:rmDownVer, test_version:"3.0.2.1")){
  security_hole(0);
}
