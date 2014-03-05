###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netscape_select_obj_dos_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Netscape 'selecti()' Object Denial Of Service Vulnerability (Win)
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Netscape version 6 and 8 on Windows";
tag_insight = "Error occurs while calling the 'select()' method with a large integer that
  results in continuous allocation of x+n bytes of memory exhausting memory
  after a while.";
tag_solution = "No solution or patch is available as of 28th July, 2009, Information regarding
  this issue will be updated once the solution details are available.
  For updates refer to http://browser.netscape.com/";
tag_summary = "This host is installed with Netscape browser and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(900393);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2542", "CVE-2009-1692");
  script_bugtraq_id(35446);
  script_name("Netscape 'select()' Object Denial Of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9160");
  script_xref(name : "URL" , value : "http://www.g-sec.lu/one-bug-to-rule-them-all.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of Netscape");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_netscape_detect_win.nasl");
  script_require_keys("Netscape/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


netscapeVer = get_kb_item("Netscape/Win/Ver");
if(netscapeVer =~ "^(6|8)\..*"){
  security_hole(0);
}
