###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_word_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Word 2007 Sensitive Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to retrieve sensitive
  information about sender's account name and a Temporary Internet Files
  subdirectory name.
  Impact Level: System";
tag_affected = "Microsoft Office Word 2007 on Windows.";
tag_insight = "In MS Word when the Save as PDF add-on is enabled, places an absolute pathname
  in the Subject field during an Email as PDF operation.";
tag_solution = "No solution or patch is available as of 06th February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://office.microsoft.com/en-us/word/default.aspx";
tag_summary = "This host is installed with Microsoft Word and is prone to
  information disclosure vulnerability";

if(description)
{
  script_id(800343);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6063");
  script_name("Microsoft Word 2007 Sensitive Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/486088/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Microsoft Word");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("MS/Office/Ver", "SMB/Office/Word/Version");
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

if(egrep(pattern:"^12\..*", string:get_kb_item("MS/Office/Ver")))
{
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  # Grep for version 12.0 to 12.0.6331.4999
  if(version_in_range(version:wordVer, test_version:"12.0",
                                       test_version2:"12.0.6331.4999")){
    security_warning(0);
  }
}
