###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grabit_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Grabit Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed Grabit Version in Windows and
  saves the result in KB.";

if(description)
{
  script_id(800712);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Grabit Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set Version of Grabit in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800712";
SCRIPT_DESC = "Grabit Version Detection";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GrabIt_is1\";
name = registry_get_sz(key:key, item:"DisplayName");

if("GrabIt" >< name)
{
  grabitVer = eregmatch(pattern:"GrabIt ([0-9.]+) Beta\ ?([0-9]+)?", string:name);
  build = eregmatch(pattern:"build ([0-9]+)", string:name);

  if(grabitVer[1] != NULL && grabitVer[2] == NULL){
    appVer = grabitVer[1];
  }
  else if(grabitVer[1] != NULL && grabitVer[2] != NULL)
  {
    # Beta version string goes here in the 2nd index value.
    appVer = grabitVer[1] + "." + grabitVer[2];
  }

  set_kb_item(name:"GrabIt/Ver", value:appVer);
  security_note(data:" version " + appVer + " was detected on the host");
    
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:appVer, exp:"^([0-9]\.[0-9]+\.[0-9]+)", base:"cpe:/a:shemes:grabit:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  if(build[1] != NULL){
    set_kb_item(name:"GrabIt/Build/Ver", value:build[1]); # Sets for Build Version.
  }
}
