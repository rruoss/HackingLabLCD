###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libre_office_doc_file_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# LibreOffice 'DOC' File Denial of Service Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system or cause denial of service.
  Impact Level: Application.";
tag_affected = "LibreOffice version 3.3.0 and 3.4.0 through 3.4.2";

tag_insight = "The flaw is due to an error in 'OpenOffice.org'. A remote user can create
  a specially crafted Word document that, when loaded by the target user, will
  trigger an out-of-bounds read and potentially execute arbitrary code on the
  target system.";
tag_solution = "Upgrade to LibreOffice version 3.4.3 or later.
  For updates refer to http://www.libreoffice.org/download/";
tag_summary = "This host is installed with LibreOffice and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802557);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-2713");
  script_bugtraq_id(49969);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-10 16:22:59 +0530 (Tue, 10 Jan 2012)");
  script_name("LibreOffice 'DOC' File Denial of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/76178");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Oct/21");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?102615");
  script_xref(name : "URL" , value : "http://www.libreoffice.org/advisories/CVE-2011-2713/");

  script_description(desc);
  script_summary("Check for the version of LibreOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_libre_office_detect_win.nasl");
  script_require_keys("LibreOffice/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

## Get the version from KB
officeVer = get_kb_item("LibreOffice/Win/Ver");
if(!officeVer){
  exit(0);
}

## Check for LibreOffice version less than 3.3.0
if(officeVer =~ "^3\..*")
{
  if(version_is_less(version:officeVer, test_version:"3.4.3"))
  security_warning(0);
}
