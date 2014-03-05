###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_sharepoint_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft SharePoint Team Services Information Disclosure Vulnerability
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
tag_impact = "Attackers can exploit this issue via specially-crafted HTTP requests to
  obtain the source code of arbitrary ASP.NET files from the backend database.
  Impact Level: Application";
tag_affected = "Microsoft Office SharePoint Server 2007 12.0.0.6219 and prior.";
tag_insight = "This flaw is due to insufficient validation of user supplied data
  passed into 'SourceUrl' and 'Source' parameters in the download.aspx in
  SharePoint Team Services.";
tag_solution = "No solution or patch is available as of 04th November, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sharepoint.microsoft.com/Pages/Default.aspx";
tag_summary = "This host is installed with Microsoft SharePoint Server and is
  prone to Information Disclosure Vulnerability.";

if(description)
{
  script_id(800968);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3830");
  script_bugtraq_id(36817);
  script_name("Microsoft SharePoint Team Services Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976829");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53955");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507419/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of MS SharePoint Team Services");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
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

if(version_in_range(version:stsVer, test_version:"12.0", test_version2:"12.0.0.6219")){
  security_warning(0);
}