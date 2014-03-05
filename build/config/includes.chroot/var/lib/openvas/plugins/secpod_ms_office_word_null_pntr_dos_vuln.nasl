###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_word_null_pntr_dos_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 secpod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to cause a denial of
  service (NULL pointer dereference and multiple-instance application crash).
  Impact Level: Application";
tag_affected = "Microsoft Office Word 2003 sp3 on Windows.";
tag_insight = "The flaw is due to error in 'MSO.dll' library which fails to handle
  the special crafted buffer in a file.";
tag_solution = "No solution or patch is available as of 22nd September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://office.microsoft.com/en-us/word/default.aspx";
tag_summary = "This host is installed with Microsoft Word and is prone to
  null pointer dereference vulnerability.";

if(description)
{
  script_id(902250);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-3200");
  script_name("Microsoft Word 2003 'MSO.dll' Null Pointer Dereference Vulnerability");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/Sep/100");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513679/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Microsoft Word");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_office_products_version_900032.nasl");
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

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for the office installation
if(egrep(pattern:"^11\..*", string:get_kb_item("MS/Office/Ver")))
{
  ## check for the Office word installation
  wordVer = get_kb_item("SMB/Office/Word/Version");
  if(!wordVer){
    exit(0);
  }

  # Check for the vulnerable product version
  if(version_in_range(version:wordVer, test_version:"11", test_version2:"11.8326.11.8324"))
  {
    ## Get the path of vulnerable file path
    offPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
    if(offPath)
    {
      offPath += "\Microsoft Shared\OFFICE11\MSO.DLL";
      share = ereg_replace(pattern:"([A-Za-z]):.*", replace:"\1$", string:offPath);
      file = ereg_replace(pattern:"[A-Za-z]:(.*)", replace:"\1", string:offPath);

      ## Confirm the vulnerable file exists
      dllVer = GetVer(file:file, share:share);
      if(dllVer){
        security_warning(0);
      }
    }
  }
}
