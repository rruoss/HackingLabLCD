###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kmplayer_mp3_file_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# KMPlayer '.mp3' File Remote Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code in the
  context of the application. Failed attacks will cause denial-of-service
  conditions.
  Impact Level: Application";
tag_affected = "KMPlayer versions 3.0.0.1440 and prior.";
tag_insight = "The flaw is due to an error when processing MP3 files and can be
  exploited to cause a stack-based buffer overflow via a specially crafted
  file.";
tag_solution = "No solution or patch is available as of 14th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.kmplayer.com/";
tag_summary = "This host is installed with KMPlayer and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802208);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_bugtraq_id(48112);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("KMPlayer '.mp3' File Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44825");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67855");
  script_xref(name : "URL" , value : "http://www.kmplayer.com/forums/showthread.php?p=87891");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102196/km_pwn_aslr.py.txt");

  script_description(desc);
  script_summary("Check for the version of KMPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Application
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\The KMPlayer";
if(!registry_key_exists(key:key)){
  exit(0);
}

kmName = registry_get_sz(key:key, item:"DisplayName");
if("KMPlayer" >< kmName)
{
  ## Get the path of uninstallstring
  kmPath = registry_get_sz(key:key + item, item:"UninstallString");
  if(kmPath)
  {
    kmPath = ereg_replace(pattern:'\"(.*)\"', replace:"\1", string:kmPath);
    kmPath = ereg_replace(pattern:'uninstall.exe', replace:"KMPlayer.exe", string:kmPath);

    ## Get Version from KMPlayer.exe
    kmVer = fetch_file_version(sysPath:kmPath);
    if(! kmVer){
      exit(0);
    }

    ## Check for KMPlayer versions 3.0.0.1440 and prior.
    if(version_is_less_equal(version:kmVer, test_version:"3.0.0.1440")){
      security_hole(0);
    }
  }
}
