##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bsplayer_mult_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# BS.Player '.bsl' File Buffer Overflow Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to to execute arbitrary code by
  tricking a user into opening a specially files. Failed attacks will cause
  denial-of-service conditions.
  Impact Level: Application.";
tag_affected = "BS.Global BS.Player version 2.51 Build 1022 and prior.";

tag_insight = "Multiple flaws are due to,
  - A boundary error while processing specially crafted 'BSI' files, when user
    opens a specially crafted 'BSI' file containing an overly long 'Skin' key
    in the 'Options' section.
  - A boundary error in the processing of 'ID3' tags when a user adds a specially
    crafted mp3 file to the media library.";
tag_solution = "No solution or patch is available as of 24th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bsplayer.org/";
tag_summary = "This host is installed BS Player and is prone to multiple buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(902055);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-2004", "CVE-2010-2009");
  script_bugtraq_id(37831, 38568);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("BS.Player '.bsl' File Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38221");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55708");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0148");

  script_description(desc);
  script_summary("Check for the version of BS.Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_bsplayer_detect.nasl");
  script_require_keys("BSPlayer/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}
		

include("version_func.inc");

## Get the version from KB
bsver = get_kb_item("BSPlayer/Ver");
if(!bsver){
exit(0);
}

if(bsver != NULL)
{
  ## Check for BS.Player version <= 2.51 Build 1022
  if(version_is_less_equal(version:bsver, test_version:"2.51.1022")){
    security_hole(0);
  }
}
