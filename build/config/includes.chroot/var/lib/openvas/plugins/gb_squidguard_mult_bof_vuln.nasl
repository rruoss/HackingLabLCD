###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squidguard_mult_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# SquidGuard Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply the following patches.
  http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091019
  http://www.squidguard.org/Downloads/Patches/1.4/Readme.Patch-20091015

  *****
  NOTE: Please ignore this waring if the above mentioned patches are already applied.
  *****";

tag_impact = "Remote attackers can exploit this issue to bypass the filter security and to
  cause Denail of Service due to application hang.
  Impact Level: System/Application";
tag_affected = "SquidGuard version 1.3 and 1.4";
tag_insight = "- A boundary error occurs in 'sgLog.c' while handling overly long URLs with
    multiple '/' characters while operating in the emergency mode.
  - Multiple buffer overflow errors occur in 'sg.h.in' and 'sgDiv.c.in' while
    processing overly long URLs and can be exploited to bypass the URL filter.";
tag_summary = "The host is installed with SquidGuard and is prone to multiple
  Buffer Overflow vulnerabilities.";

if(description)
{
  script_id(800965);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3826", "CVE-2009-3700");
  script_bugtraq_id(36800);
  script_name("SquidGuard Multiple Buffer Overflow Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/37107");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53922");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3013");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Oct/1023079.html");

  script_description(desc);
  script_summary("Check for the version of SquidGuard");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_squidguard_detect.nasl");
  script_require_keys("SquidGuard/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

sgVer = get_kb_item("SquidGuard/Ver");
if(!sgVer){
  exit(0);
}

if(version_is_equal(version:sgVer, test_version:"1.4")||
   version_is_equal(version:sgVer, test_version:"1.3")){
  security_warning(0);
}
