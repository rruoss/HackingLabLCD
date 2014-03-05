###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_putty_version.nasl 1020 2009-06-01 20:05:29Z Feb $
#
# PuTTY Version Detection
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
################################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900618";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-02 12:54:52 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"detection", value:"registry version check");
  script_name("PuTTY Version Detection");

  tag_summary =
"Detection of installed version of PuTTY.

The script logs in via smb, searches for PuTTy in the registry, gets
version from the 'DisplayName' string and set it in the KB item.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Sets KB of PuTTY version");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 SecPod.");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

path = "";
insloc = "";
version = "";


path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PuTTY_is1",item:"DisplayName");
if(!path){
  exit(0);
}

insloc = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PuTTY_is1",item:"InstallLocation");
if(!insloc){
  insloc = "Could not find the install location from registry";
}

version = eregmatch(pattern:"[0-9.]+", string:path);
if(version[0])
{
  set_kb_item(name:"PuTTY/Version", value:version[0]);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version[0], exp:"^([0-9.]+)", base:"cpe:/a:putty:putty:");
  if(isnull(cpe))
    cpe = "cpe:/a:putty:putty";

  register_product(cpe:cpe, location:insloc, nvt:SCRIPT_OID);

  log_message(data: build_detection_report(app: "PuTTY",
                                           version: version[0],
                                           install: insloc,
                                           cpe: cpe,
                                           concluded: version[0]));
}
