###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_esm_priv_esc_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Symantec Enterprise Security Manager/Agent Privilege Escalation Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Symantec Enterprise Security Manager version 11.0 or later
       Or apply the patch SU44
  http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20121213_00

  *****
  NOTE: Ignore this warning if patch is applied already.
        For patch refer to
        http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=esm&pvid=su&year=&suid=20121207_00
  *****";

tag_impact = "Successful exploitation could allow local users to gain privileges via
  unspecified vectors.
  Impact Level: Application";

tag_affected = "Symantec Enterprise Security Manager versions 10.x and prior
  Symantec Enterprise Security Manager Agents versions 10.x and prior";
tag_insight = "An unquoted Windows search path flaw exists in ESM Manager and Agents.";
tag_summary = "This host is installed with Symantec Enterprise Security
  Manager/Agent and is prone to local privilege escalation vulnerability.";

if(description)
{
  script_id(803095);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-4350");
  script_bugtraq_id(56915);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-08 13:22:57 +0530 (Tue, 08 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Symantec Enterprise Security Manager/Agent Privilege Escalation Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.osvdb.org/88465");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027874");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80722");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=&amp;suid=20121213_00");

  script_description(desc);
  script_summary("Check for the version of vulnerable Symantec ESM");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_require_keys("Symantec/ESM/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## Variable Initialisation
sesmVer = "";

## Get Symantec Enterprise Security Manager version
sesmVer = get_kb_item("Symantec/ESM/Ver");
if(!sesmVer){
  exit(0);
}

if(version_is_less(version:sesmVer, test_version:"11.0"))
{
   security_hole(0);
   exit(0);
}
