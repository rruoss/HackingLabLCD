###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hplip_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# HP Linux Imaging and Printing System Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_solution = "Upgrade to Higher version,
  http://security.ubuntu.com/ubuntu/pool/main/h/hplip/

  *****
  NOTE: Please ignore the warning, if patch is applied.
  *****";

tag_impact = "Successful exploitation will let the attacker gain unauthorized privileges
  and escalate the privileges in a malicious way.";
tag_affected = "HP Linux Imaging and Printing System version 2.7.7 or 2.8.2";
tag_insight = "This flaw is due to the 'postinst' script of the hplip package which tries
  to change the permissions of user config files in an insecure manner.";
tag_summary = "This host is installed with HP Linux Imaging and Printing System
  and is prone to Security Bypass vulnerability.";

if(description)
{
  script_id(900429);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(33249);
  script_cve_id("CVE-2009-0122");
  script_name("HP Linux Imaging and Printing System Security Bypass Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of HP-LIP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_hplip_detect_lin.nasl");
  script_require_keys("HP-LIP/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33539");
  script_xref(name : "URL" , value : "http://www.ubuntu.com/usn/usn-708-1");
  script_xref(name : "URL" , value : "https://bugs.launchpad.net/ubuntu/+source/hplip/+bug/191299");
  exit(0);
}


hplipVer = get_kb_item("HP-LIP/Linux/Ver");
if(hplipVer != NULL)
{
  # Grep for version 2.7.7 or 2.8.2
  if(hplipVer =~ "2.7.7|2.8.2"){
    security_hole(0);
  }
}
