###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sdp_downloader_http_header_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SDP Downloader HTTP Header Handling Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to cause a denial of service
  or compromise a vulnerable system.
  Impact Level: Application";
tag_affected = "SDP Downloader version 2.3.0 and prior";
tag_insight = "The flaw is caused by a buffer overflow error when processing overly long
  HTTP headers, which could be exploited by attackers to crash an affected
  application or execute arbitrary code by convincing a user to download a
  file from a malicious server.";
tag_solution = "No solution or patch is available as of 1st February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sdp.ppona.com";
tag_summary = "This host is installed with SDP Downloader and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(801834);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SDP Downloader HTTP Header Handling Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16078/");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/9900");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0253");

  script_description(desc);
  script_summary("Check for the version of SDP Downloader");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

## Get version from KB
sdpVer = get_kb_item("SDP/Downloader/Ver");
if(!sdpVer){
  exit(0);
}

## Check for SDP Downloader version 2.3.0 and prior
if(version_is_less_equal(version:sdpVer,test_version:"2.3.0")) {
  security_hole(0);
}
