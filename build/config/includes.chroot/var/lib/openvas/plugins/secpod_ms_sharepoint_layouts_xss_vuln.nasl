###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_sharepoint_layouts_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft SharePoint '_layouts/help.aspx' Cross Site Scripting Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "No solution or patch is available as of 30th, April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sharepoint.microsoft.com/Pages/Default.aspx

  Workaround:
  Apply the workaround as mentioned in below link,
  http://www.microsoft.com/technet/security/advisory/983438.mspx";

tag_impact = "Successful exploitation will allow remote authenticated users to compromise
  the application, theft of cookie-based authentication credentials, disclosure
  or modification of sensitive data.
  Impact Level: Application";
tag_affected = "Microsoft Windows SharePoint Services 3.0 SP 1
  Microsoft Office SharePoint Server SP1 2007 12.0.0.6421 and prior.";
tag_insight = "This flaw is due to insufficient validation of user supplied data
  passed into 'cid0' parameter in the '_layouts/help.aspx' in SharePoint
  Team Services.";
tag_summary = "This host is running Microsoft SharePoint Server and is prone to
  Cross Site Scripting vulnerability.";

if(description)
{
  script_id(902176);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-0817");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft SharePoint '_layouts/help.aspx' Cross Site Scripting Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/983438.mspx");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509683/100/0/threaded");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_microsoft_sharepoint_server_2007.html");

  script_description(desc);
  script_summary("Check for the version of MS SharePoint Team Services");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Windows");
  script_dependencies("remote-detect-WindowsSharepointServices.nasl");
  script_require_keys("MicrosoftSharePointTeamServices/version");
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

stsVer = get_kb_item("MicrosoftSharePointTeamServices/version");
if(isnull(stsVer)){
  exit(0);
}

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6421")){
  security_warning(0);
}
