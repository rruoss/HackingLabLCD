###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panda_prdts_priv_esc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Panda Products Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker replace the affected binary file
  with a malicious binary which will be executed with SYSTEM privileges.

  Impact level: System.";

tag_affected = "Panda AntiVirus Pro 2010 version 9.01.00 and prior.
  Panda Internet Security 2010 version 15.01.00 and prior.
  Panda Global Protection 2010 version 3.01.00 and prior.";
tag_insight = "This flaw is due to insecure permissions being set on the 'PavFnSvr.exe'
  file (Everyone/Full Control) within the installation directory, which could be
  exploited by malicious users to replace the affected file with a malicious
  binary which will be executed with SYSTEM privileges.";
tag_solution = "Apply the security updates accordingly.
  http://www.pandasecurity.com/homeusers/support/card?id=80164&idIdioma=2";
tag_summary = "This host is running panda Products and is prone to Privilege
  Escalation Vulnerability.";

if(description)
{
  script_id(801080);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4215");
  script_name("Panda Products Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37373");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1023121");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3126");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507811/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Panda AntiVirus Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_require_keys("Panda/InternetSecurity/Ver", "Panda/GlobalProtection/Ver",
                      "Panda/Antivirus/Ver");
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

# Check for the Panda Antivirus 2010(9.01.00) and prior
if(pandaVer = get_kb_item("Panda/Antivirus/Ver"))
{
  if(version_in_range(version:pandaVer, test_version:"9.0", test_version2:"9.01.00")){
    security_hole(0);
  }
}

# Check for the Panda Internet Security 2010(15.01.00) and prior
else if(pandaVer = get_kb_item("Panda/InternetSecurity/Ver"))
{
  if(version_in_range(version:pandaVer, test_version:"15.0", test_version2:"15.01.00")){
    security_hole(0);
  }
}

#Check for the Panda Global Protection 2010 (3.01.00) and prrior.
else if(pandaVer = get_kb_item("Panda/GlobalProtection/Ver"))
{
   if(version_in_range(version:pandaVer, test_version:"3.0", test_version2:"3.01.00")){
    security_hole(0);
  }
}
