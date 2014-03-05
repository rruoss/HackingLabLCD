###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftpgetter_pasv_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# FTPGetter 'PASV' Command Remote Stack Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation allows execution of arbitrary code.
  Impact Level: Application.";
tag_affected = "FTPGetter version 3.58.0.21 and prior.";

tag_insight = "The flaw is due to a boundary error when reading a log file using
  fgets() which can be exploited to cause a stack-based buffer overflow by
  tricking a user into connecting to a malicious FTP server and sending a
  specially crafted 'PWD' or 'PASV' response.";
tag_solution = "No solution or patch is available as of 4th February, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.ftpgetter.com/download.php";
tag_summary = "This host is installed with FTPGetter FTP Client and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(801839);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46120);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("FTPGetter 'PASV' Command Remote Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "https://secunia.com/advisories/41857");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16101/");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/46120.py");

  script_description(desc);
  script_summary("Check for the version of FTPGetter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
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

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  fgName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check the name of the application
  if("FTPGetter" >< fgName)
  {
    ## Get FTPGetter Path
    fgpath = registry_get_sz(key: key + item , item:"DisplayIcon");
    if(!isnull(fgpath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:fgpath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:fgpath);

      ## Check for FTPGetter Version
      fgVer = GetVer(file:file, share:share);
      if(fgVer != NULL)
      {
        ## Check for FTPGetter version 3.58.0.21 and prior
        if(version_is_less_equal(version:fgVer, test_version:"3.58.0.21"))
        {
          security_hole(0) ;
          exit(0);
        }
      }
    }
  }
}
