###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sigplus_pro_activex_control_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SigPlus Pro ActiveX Control 'LCDWriteString()' Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code on the system or cause the victim's browser to crash.
  Impact Level: Application/System";
tag_affected = "SigPlus Pro ActiveX control version 3.74";
tag_insight = "The flaw is due to a boundary error in SigPlus.ocx when handling the
  'HexString' argument passed to the 'LCDWriteString()' method and can be
  exploited to cause a stack-based buffer overflow via an overly long string.";
tag_solution = "Upgrade to SigPlus Pro ActiveX control version 3.95 or later,
  For updates refer to
  http://www.topazsystems.com/software/download/sigplusactivex.htm";
tag_summary = "This host is installed with SigPlus Pro ActiveX Control and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_id(801252);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2931");
  script_bugtraq_id(42109);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("SigPlus Pro ActiveX Control 'LCDWriteString()' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40818");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60839");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14514");

  script_description(desc);
  script_summary("Check for the version of SigPlus Pro ActiveX control");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_sigplus_pro_activex_detect.nasl");
  script_require_keys("SigPlus/Ver");
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
sigVer = get_kb_item("SigPlus/Ver");

if(sigVer)
{
  ##Grep for SigPlus Pro ActiveX control Version 3.74
  if(version_is_equal(version:sigVer, test_version:"3.74") ){
    security_hole(0);
  }
}
