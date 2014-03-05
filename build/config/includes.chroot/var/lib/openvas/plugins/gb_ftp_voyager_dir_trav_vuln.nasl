###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftp_voyager_dir_trav_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# FTP Voyager Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to download or upload arbitrary
  files. This may aid in further attacks.
  Impact Level: Application";
tag_affected = "FTP Voyager 15.2.0.11 and prior.";
tag_insight = "The flaw is due to an input validation error when downloading
  directories containing files with directory traversal specifiers in the
  filename. This can be exploited to download files to an arbitrary location
  on a user's system.";
tag_solution = "No solution or patch is available as of 4th November, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ftpvoyager.com/download/";
tag_summary = "This host is installed with FTP Voyager and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(801627);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_bugtraq_id(43869);
  script_cve_id("CVE-2010-4154");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("FTP Voyager Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41719");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62392");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1010-exploits/ftpvoyager-traversal.txt");

  script_description(desc);
  script_summary("Check for the version of FTP Voyager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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

## Check for Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## check application installation
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FTP Voyager_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get install location
ftpPath = registry_get_sz(key:key, item:"Inno Setup: App Path");
if(!ftpPath) {
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:ftpPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:ftpPath +
                                                      "\FTPVSetup.exe");

## Get FTP Voyager Version
ftpVer = GetVer(share:share, file:file);
if(ftpVer)
{
  ## Check FTP Voyager version
  if(version_is_less_equal(version:ftpVer, test_version:"15.2.0.11")){
    security_hole(0);
  }
}
