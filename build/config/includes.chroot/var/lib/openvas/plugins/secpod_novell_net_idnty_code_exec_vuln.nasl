###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_net_idnty_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Novell NetIdentity Agent Pointer Dereference Remote Code Execution Vulnerability
#
# Authors:
# Sharaths S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code in the
  context of the affected application with system privileges through a valid
  IPC$ connection.
  Impact Level: System";
tag_affected = "Novell NetIdentity Agent version prior to 1.2.4 on Windows.";
tag_insight = "Handling of RPC messages over the XTIERRPCPIPE named pipe in 'xtagent.exe',
  and sending RPC messages that triggers the dereference of an arbitrary
  pointer which can cause remote code execution.";
tag_solution = "Upgrade to NetIdentity Client version 1.2.4
  http://download.novell.com/Download?buildid=6ERQGPjRZ8o~";
tag_summary = "The host is installed with Novell NetIdentity Agent and is prone
  to remote code execution vulnerability.";

if(description)
{
  script_id(900341);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1350");
  script_bugtraq_id(34400);
  script_name("Novell NetIdentity Agent Pointer Dereference Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0954");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-09-016");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Apr/1021990.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502514/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of Novell NetIdentity Agent");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_keys("Novell/NetIdentity/Ver");
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

netidVer = get_kb_item("Novell/NetIdentity/Ver");
if(!netidVer){
  exit(0);
}

# Check for Novell NetIdentity version prior to 1.2.4
if(version_is_less(version:netidVer, test_version:"1.2.4")){
  security_hole(0);
}
