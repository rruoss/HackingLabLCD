###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_media_player_classic_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gabset Media Player Classic Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script detects the installed version of Gabset Media Player
  Classic and sets the result in KB.";

if(description)
{
  script_id(900947);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Gabset Media Player Classic Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Media Player Classic");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900947";
SCRIPT_DESC = "Gabset Media Player Classic Version Detection";

if(!get_kb_item("SMB/WindowsVersion")) {
  exit(0);
}

mpcPath = registry_get_sz(key:"SOFTWARE\Gabest\Media Player Classic",
                          item:"ExePath");
if(mpcPath != NULL)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:mpcPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:mpcPath);

  mpcVer = GetVer(file:file, share:share);
  if(mpcVer != NULL){
    set_kb_item(name:"MediaPlayerClassic/Ver", value:mpcVer);
    security_note(data:"Media Player Classic version " + mpcVer +
             " running at location " + mpcPath +  " was detected on the host");
     
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:mpcVer, exp:"^([0-9.]+)", base:"cpe:/a:rob_schultz:media_player_classic:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
