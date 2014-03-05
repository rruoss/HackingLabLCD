###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cursorarts_zipwrangler_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# CursorArts ZipWrangler 'ZIP Processing' Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  with a specially crafted ZIP file.
  Impact Level: Application.";
tag_affected = "CursorArts ZipWrangler version 1.20.";

tag_insight = "The flaw exists due to boundary error when processing certain ZIP files, which
  leads to stack-based buffer overflow by tricking a user into opening a
  specially crafted ZIP file.";
tag_solution = "No solution or patch is available as of 15th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cursorarts.com/ca_zw.html.";
tag_summary = "This host is installed with CursorArts ZipWrangler and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902071);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1685");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("CursorArts ZipWrangler 'ZIP Processing' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/64079");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39575");
  script_xref(name : "URL" , value : "http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-031-zip-wrangler-1-20-buffer-overflow/");

  script_description(desc);
  script_summary("Check for the version of CursorArts ZipWrangler");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
         "\ZipWrangler version 1.20_is1";

if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for ZipWrangler DisplayName
zipName = registry_get_sz(key:key, item:"DisplayName");
if("ZipWrangler" >< zipName)
{
  ## Grep the version for ZipWrangler
  zipVer = eregmatch(pattern:" version ([0-9.]+)", string:zipName);
  if(zipVer[1] != NULL)
  {
    ## Check for ZipWrangler version equal to '1.20'
    if(version_is_equal(version:zipVer[1], test_version:"1.20")){
      security_hole(0) ;
    }
  }
}
