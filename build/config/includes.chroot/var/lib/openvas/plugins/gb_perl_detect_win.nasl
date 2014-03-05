##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_perl_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Perl Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of installed version of Active or Strawberry Perl.

The script logs in via smb, searches for Active or Strawberry Perl in the
registry and gets the version from registry";

if(description)
{
  script_id(800966);
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-11-05 12:25:48 +0100 (Thu, 05 Nov 2009)");
  script_name("Perl Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Perl in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800966";
SCRIPT_DESC = "Perl Version Detection (Windows)";

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Perl")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  perlName = registry_get_sz(key:key + item, item:"DisplayName");

  # Check for Strawberry Perl
  if("Strawberry Perl" >< perlName)
  {
    ## Get Location
    perlLoc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!perlLoc)
    {
      perlLoc = "Location not found";
    }

    ## Get Version
    perlVer = registry_get_sz(key:key + item, item:"Comments");
    perlVer = eregmatch(pattern:"Strawberry Perl ([0-9.]+)", string:perlVer);
    if(!isnull(perlVer[1]))
    {
      set_kb_item(name:"Strawberry/Perl/Ver", value:perlVer[1]);
      set_kb_item(name:"Strawberry/Perl/Loc", value:perlLoc);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:perlVer[1], exp:"^([0-9.]+)",
                      base:"cpe:/a:vanilla_perl_project:strawberry_perl:");
      if(isnull(cpe))
        cpe = "cpe:/a:vanilla_perl_project:strawberry_perl";

      register_product(cpe:cpe, location:perlLoc, nvt:SCRIPT_OID);

      log_message(data: build_detection_report(app:"Strawberry Perl",
                                             version:perlVer[1],
                                             install: perlLoc,
                                             cpe:cpe,
                                             concluded:perlVer[1]));
    }
  }

  # Check for ActivePerl
  if("ActivePerl"  >< perlName)
  {
    ## Get Location
    perlLoc = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!perlLoc)
    {
      perlLoc = "Location not found";
    }

    ## Get Version
    perlVer = eregmatch(pattern:"ActivePerl ([0-9.]+)", string:perlName);
    if(!isnull(perlVer[1]))
    {
      set_kb_item(name:"ActivePerl/Ver", value:perlVer[1]);
      set_kb_item(name:"ActivePerl/Loc", value:perlLoc);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:perlVer[1], exp:"^([0-9.]+)",
                      base:"cpe:/a:perl:perl:");
      if(isnull(cpe))
        cpe = "cpe:/a:perl:perl";

      register_product(cpe:cpe, location:perlLoc, nvt:SCRIPT_OID);


      log_message(data: build_detection_report(app:"Active Perl",
                                               version:perlVer[1],
                                               install: perlLoc,
                                               cpe:cpe,
                                               concluded:perlVer[1]));
    }
  }
}
