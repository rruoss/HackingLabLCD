###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_divx_web_player_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# DivX Web Player Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary
  codes within the context of the application by tricking a user into
  opening a crafted DivX file.

  Impact level: System";

tag_affected = "DivX Web Player 1.4.2.7 and prior on Windows.";
tag_insight = "This flaw is due to the boundary checking error while processing Stream
  Format 'STRF' chunks which causes heap overflow.";
tag_solution = "Update to version 1.4.3.4
  http://www.divx.com/downloads/divx";
tag_summary = "This host is running DivX Web Player which is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(900537);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5259");
  script_bugtraq_id(34523);
  script_name("DivX Web Player Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/377996.php");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33196");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1044");

  script_description(desc);
  script_summary("Check for the version of DivX Web Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_divx_web_player_detect.nasl");
  script_require_keys("DivX/Web/Player/Ver");
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

divxVer = get_kb_item("DivX/Web/Player/Ver");
if(divxVer == NULL){
  exit(0);
}

if(version_is_less(version:divxVer, test_version:"1.4.3.4")){
  security_hole(0);
}
