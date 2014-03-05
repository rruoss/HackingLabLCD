##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kvirc_detect_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# KVIrc Version Detection (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of KVIrc and sets
  the result in KB.";

if(description)
{
  script_id(901010);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("KVIrc Version Detection (Win)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the KB for the Version of KVIrc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901010";
SCRIPT_DESC = "KVIrc Version Detection (Win)";

# Check for Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  kvireName = registry_get_sz(key:key + item, item:"DisplayName");

  if("KVIrc" >< kvireName)
  {
    # Grep Version from Registry
    kvircVer = eregmatch(pattern:"KVIrc ([0-9.]+)", string:kvireName);

    if(kvircVer[1] != NULL){
      kvircVer = kvircVer[1];
    }
    else
    {
      # Grep Version from .EXE File
      path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\",
                             item:"ProgramFilesDir");
      exePath = path + "\kvirc\kvirc.exe";
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
      kvircVer = GetVer(file:file, share:share);

      if(kvircVer == NULL)
      {
        # Taking Version From README File
        exePath = exePath -"kvirc.exe" + "README.txt";

        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
        file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);
        readmeText = read_file(share:share, file:file, offset:0, count:500);

        if(readmeText)
        {
          kvircVer = eregmatch(pattern:"Release ([0-9.]+)", string:readmeText);

          if(kvircVer != NULL){
            kvircVer = kvircVer[1];
          }
          else
          {
            exit(0);
          }
        }
      }
    }

    # Set KB for KVIrc
    if(kvircVer != NULL){
      set_kb_item(name:"Kvirc/Win/Ver", value:kvircVer);
      security_note(data:"KVIrc Version " + kvircVer + " running at location "
                                     + exePath +  " was detected on the host");
     
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:kvircVer, exp:"^([0-9.]+)", base:"cpe:/a:kvirc:kvirc:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
