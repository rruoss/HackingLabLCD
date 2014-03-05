###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsync_mult_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Rsync Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to crash an affected
  application or execute arbitrary code by tricking a user into connecting
  to a malicious rsync server and using the '--recursive' and '--delete'
  options without the '--owner' option.
  Impact Level: Application.";
tag_affected = "rsync version 3.x before 3.0.8";

tag_insight = "The flaws are due to
  - a memory corruption error when processing malformed file list data.
  - error while handling directory paths, '--backup-dir', filter/exclude lists.";
tag_solution = "Upgrade to rsync version 3.0.8 or later
  For updates refer to http://rsync.samba.org/";
tag_summary = "This host is installed with Rsync and is prone to multiple denial
  of service vulnerabilities.";

if(description)
{
  script_id(801772);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1097");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Rsync Multiple Denial of Service Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025256");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0792");

  script_description(desc);
  script_summary("Check for the version of rsync");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
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
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" +
       "\cwRsync";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for rsync DisplayName
rsyncName = registry_get_sz(key:key, item:"DisplayName");
if("cwRsync" >< rsyncName)
{
  rsyncPath = registry_get_sz(key:key, item:"UninstallString");
  if(!isnull(rsyncPath))
  {
    rsyncPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:rsyncPath);
    rsyncVer = fetch_file_version(sysPath:rsyncPath);

    ## Get the Version for rsync
    if(rsyncVer != NULL)
    {
      ## Check for rsync version
      if(version_in_range(version:rsyncVer, test_version:"3.0", test_version2:"3.0.7")){
        security_hole(0) ;
      }
    }
  }
}
