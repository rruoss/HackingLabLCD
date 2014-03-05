###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_systemtap_shell_cmd_injection_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SystemTap 'stap-server' Remote Shell Command Injection Vulnerability
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
tag_impact = "Successful exploitation could allow rmote attackers to inject and execute
  malicious shell commands or compromise a system.
  Impact Level: System.";
tag_affected = "SystemTap versions prior to 1.1";
tag_insight = "The flaw is due to input validation error in the 'stap-server' component
  when processing user-supplied requests.";
tag_solution = "No solution or patch is available as of 29th January, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceware.org/systemtap/";
tag_summary = "This host has SystemTap installed and is prone to Arbitrary Command
  Execution vulnerability";

if(description)
{
  script_id(902017);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4273");
  script_name("SystemTap 'stap-server' Remote Shell Command Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38154");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0169");

  script_description(desc);
  script_summary("Check for the version of SystemTap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("secpod_systemtap_detect.nasl");
  script_family("General");
  script_require_keys("SystemTap/Ver");
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

systapVer = get_kb_item("SystemTap/Ver");
if(systapVer != NULL)
{
  if(version_is_less(version:systapVer, test_version:"1.1")){
    security_hole(0);
  }
}


