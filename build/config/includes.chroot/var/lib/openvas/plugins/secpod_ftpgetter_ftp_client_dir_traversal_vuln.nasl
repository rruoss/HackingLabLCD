###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ftpgetter_ftp_client_dir_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FTPGetter FTP Client Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to write files into a user's
  Startup folder to execute malicious code when the user logs on.
  Impact Level: Application.";
tag_affected = "FTPGetter FTP Client 3.51.0.05 and prior.";

tag_insight = "The flaw exists due to error in handling of certain crafted file names.
  It does not properly sanitise filenames containing directory traversal
  sequences that are received from an FTP server.";
tag_solution = "No solution or patch is available as of 25th August, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.ftpgetter.com/download.php";
tag_summary = "This host is installed with FTPGetter FTP Client and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(902233);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-25 17:02:03 +0200 (Wed, 25 Aug 2010)");
  script_cve_id("CVE-2010-3103");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("FTPGetter FTP Client Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41069");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/directory_traversal_in_ftpgetter.html");

  script_description(desc);
  script_summary("Check for the version of FTPGetter FTP Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
    ## Check for FTPGetter FTP Client
    fgpath = registry_get_sz(key: key + item , item:"DisplayIcon");
    if(!isnull(fgpath))
    {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:fgpath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:fgpath);

      ## Check for FTPGetter FTP Clent File Version
      fgVer = GetVer(file:file, share:share);
      if(fgVer != NULL)
      {
        ## Check for FTPGetter FTP Clent version 3.51.0.05 and prior
        if(version_is_less_equal(version:fgVer, test_version:"3.51.0.05"))
        {
          security_hole(0) ;
          exit(0);
        }
      }
    }
  }
}
