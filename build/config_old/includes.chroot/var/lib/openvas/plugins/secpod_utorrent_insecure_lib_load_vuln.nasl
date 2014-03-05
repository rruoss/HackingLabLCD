###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_utorrent_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# uTorrent File Opening Insecure Library Loading Vulnerability
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary code and
  conduct DLL hijacking attacks.
  Impact Level: Application.";
tag_affected = "uTorrent version 2.0.3 and prior";

tag_insight = "The flaw is due to the application insecurely loading certain librairies
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a Torrent file.";
tag_solution = "Upgrade to uTorrent version 2.0.4 or later,
  For updates refer to http://www.utorrent.com/downloads";
tag_summary = "This host is installed with uTorrent and is prone to insecure library
  loading vulnerability.";

if(description)
{
  script_id(902240);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3129");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("uTorrent File Opening Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41051");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14726/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2164");

  script_description(desc);
  script_summary("Check for the version of uTorrent");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\uTorrent\";
if(!registry_key_exists(key:key)){
 exit(0);
}

utName = registry_get_sz(key:key, item:"DisplayIcon");

## Check the name of the application
if("uTorrent" >< utName)
{
  ## Check for utorrent
  utVer = registry_get_sz(key: key, item:"DisplayVersion");
  if(utVer)
  {
    ## Check for uTorrent version 2.0.3 and prior
    if(version_is_less_equal(version:utVer, test_version:"2.0.3")){
      security_hole(0) ;
    }
  }
}
