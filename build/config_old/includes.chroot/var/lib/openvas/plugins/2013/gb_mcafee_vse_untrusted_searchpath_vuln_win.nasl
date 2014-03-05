##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_vse_untrusted_searchpath_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# McAfee VirusScan Enterprise Untrusted Search Path Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code via
  a crafted document embedded with ActiveX control.
  Impact Level: System/Application";

tag_affected = "McAfee VirusScan Enterprise versions prior to 8.7i";
tag_insight = "Flaw is due to loading dynamic-link libraries (DLL) from an untrusted path.";
tag_solution = "No solution or patch is available as of 04th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mcafee.com";
tag_summary = "This host is installed with McAfee VirusScan Enterprise and is
  prone to untrusted search path vulnerability.";

if(description)
{
  script_id(803322);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2009-5118");
  script_bugtraq_id(45080);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-21 19:41:20 +0530 (Thu, 21 Feb 2013)");
  script_name("McAfee VirusScan Enterprise Untrusted Search Path Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/69503");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2009-5118");
  script_xref(name : "URL" , value : "http://www.naked-security.com/cve/CVE-2009-5118");

  script_description(desc);
  script_summary("Check for the vulnerable version of McAfee VirusScan Enterprise on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_virusscan_enterprise_detect_win.nasl");
  script_mandatory_keys("McAfee/VirusScan/Win/Ver");
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

## Variable Initialization
version = "";

## Get version from KB
version = get_kb_item("McAfee/VirusScan/Win/Ver");
if(version)
{
  ## Check for McAfee VirusScan Enterprise versions prior to 8.7i
  if(version_is_less(version:version, test_version:"8.7i"))
  {
    security_hole(0);
    exit(0);
  }
}
