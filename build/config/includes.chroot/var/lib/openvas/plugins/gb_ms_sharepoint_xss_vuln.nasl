###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_sharepoint_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft SharePoint Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote authenticated users to leverage
  same-origin relationships and conduct cross-site scripting attacks by
  uploading TXT files.
  Impact Level: Application";
tag_affected = "Microsoft Office SharePoint Server 2007 12.0.0.6421 and prior.";
tag_insight = "This flaw is due to insufficient validation of user supplied data
  passed into 'SourceUrl' and 'Source' parameters in the 'download.aspx' in
  SharePoint Team Services.";
tag_solution = "No solution or patch is available as of 03rd March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sharepoint.microsoft.com/Pages/Default.aspx";
tag_summary = "This host is running Microsoft SharePoint Server and is prone to
  Cross Site Scripting vulnerability.";

if(description)
{
  script_id(800481);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0716");
  script_name("Microsoft SharePoint Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.hacktics.com/content/advisories/AdvMS20100222.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509683/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of MS SharePoint Team Services");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("remote-detect-WindowsSharepointServices.nasl");
  script_require_keys("MicrosoftSharePointTeamServices/version");
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

stsVer = get_kb_item("MicrosoftSharePointTeamServices/version");
if(isnull(stsVer)){
  exit(0);
}

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6421")){
  security_warning(0);
}
