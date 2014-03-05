###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fresh_ftp_client_dir_traversal_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FreshWebMaster Fresh FTP Filename Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to download files to an arbitrary
  location on a user's system.
  Impact Level: Application.";
tag_affected = "FreshWebMaster Fresh FTP version 5.37 and prior";

tag_insight = "The flaw is due to an input validation error when downloading
  directories containing files with directory traversal specifiers in the
  filename.";
tag_solution = "No solution or patch is available as of 03rd November, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.freshwebmaster.com/";
tag_summary = "This host is installed with Fresh FTP Client and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(801535);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_cve_id("CVE-2010-4149");
  script_bugtraq_id(44072);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("FreshWebMaster Fresh FTP Filename Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/68667");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41798/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1010-exploits/freshftp-traversal.txt");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/directory_traversal_vulnerability_in_freshftp.html");

  script_description(desc);
  script_summary("Check for the version of Fresh FTP Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

## Get the file content
function read_content(path)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
  radFile = read_file(share:share, file:file, offset:0, count:500);
  return radFile;
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## check application installation
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FreshWebmaster FreshFTP_is1\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get install location
ftpPath = registry_get_sz(key:key, item:"InstallLocation");
if(ftpPath)
{
  ## get the version from license.txt
  ftpPath1  = ftpPath + "\license.txt";
  radFile =  read_content(path:ftpPath1);
  if(isnull(radFile))
  {
     ## get the version from readme.txt
     reamePath = ftpPath + "\readme.txt";
     radFile = read_content(path:ftpPath);
  }

  if(!isnull(radFile))
  {
    ## match the version
    ftpVer = eregmatch(pattern:"FRESHFTP ver ([0-9.]+)", string:radFile, icase:1);
    if(ftpVer[1] != NULL)
    {
      ## Check version less or equal 5.37
      if(version_is_less_equal(version:ftpVer[1], test_version:"5.37")){
        security_hole(0) ;
      }
    }
  }
}
