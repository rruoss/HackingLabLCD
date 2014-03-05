###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sdp_downloader_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# SDP Downloader ASX File Heap Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploits will allow attackers to execute arbitrary code and can
  cause application crash via a long .asf URL.
  Impact Level: Application";
tag_affected = "SDP Downloader version 2.3.0 and prior";
tag_insight = "A boundary error exists while processing an HREF attribute of a REF element
  in ASX files, due to which application fails to check user supplied input
  before copying it into an insufficiently sized buffer.";
tag_solution = "No solution or patch is available as of 19th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sdp.ppona.com";
tag_summary = "This host is installed with SDP Downloader and is prone to Buffer
  Overflow vulnerability.";

if(description)
{
  script_id(900642);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1627");
  script_bugtraq_id(34712);
  script_name("SDP Downloader ASX File Heap Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34883");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8536");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1171");

  script_description(desc);
  script_summary("Checks for the version of SDP Downloader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_sdp_downloader_detect.nasl");
  script_require_keys("SDP/Downloader/Ver");
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

sdpVer = get_kb_item("SDP/Downloader/Ver");

if(sdpVer != NULL)
{
  if(version_is_less_equal(version:sdpVer,test_version:"2.3.0")){
    security_hole(0);
  }
}
