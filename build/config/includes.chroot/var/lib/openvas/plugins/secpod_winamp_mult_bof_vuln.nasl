###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winamp_mult_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Winamp AIFF File Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Attackers may leverage this issue by executing arbitrary codes in the context
  of the affected application and can execute denial of service attacks on the
  application.
  Impact Level: Application";
tag_affected = "Winamp version 5.541 and prior on Windows";
tag_insight = "Application fails to play a large Common Chunk (COMM) header value in an AIFF
  file and a large invalid value in an MP3 file.";
tag_solution = "Upgrade to Winamp version 5.57 or later,
  For updates refer to http://www.winamp.com";
tag_summary = "This host is installed with Winamp and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(900197);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0263");
  script_bugtraq_id(33226);
  script_name("Winamp AIFF File Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7742");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33478");

  script_description(desc);
  script_summary("Check for the version of Winamp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_winamp_detect.nasl");
  script_require_keys("Winamp/Version");
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

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

#Check for version 5.541 (5.5.4.2165) and prior
if(version_is_less_equal(version:winampVer, test_version:"5.5.4.2165")){
  security_hole(0);
}
