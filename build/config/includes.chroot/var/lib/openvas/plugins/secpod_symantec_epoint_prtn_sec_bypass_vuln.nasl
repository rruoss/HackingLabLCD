###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_symantec_epoint_prtn_sec_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Symantec Endpoint Protection Scan Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let attacker to pass sufficient specific events
  to the application to bypass an on-demand scan.

  Impact level: Application/System";

tag_solution = "No solution or patch is available as of 24th February, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.symantec.com/downloads/index.jsp

  Workaround:
  - Enable Tamper Protection.";

tag_affected = "Symantec Endpoint Protection 11.x";
tag_insight = "Issue is caused by an unspecified error in the 'on-demand' scanning feature
  when another entity denies read access to the AntiVirus while the Tamper
  protection is disabled.";
tag_summary = "The host is installed with Symantec Endpoint Protection and is
  possible to bypass security scan.";

if(description)
{
  script_id(902124);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Low");
  script_cve_id("CVE-2010-0106");
  script_bugtraq_id(38219);
  script_name("Symantec Endpoint Protection Scan Bypass Vulnerability");
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
  script_summary("Check for the version of Symantec Endpoint Protection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/Endpoint/Protection");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38653");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0410");
  script_xref(name : "URL" , value : "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=2010&amp;suid=20100217_00");
  exit(0);
}


include("version_func.inc");

sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!isnull(sepVer) && (sepVer=~ "^11.*")){
  security_note(0);
}
