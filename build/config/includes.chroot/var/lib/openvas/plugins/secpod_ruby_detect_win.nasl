##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ruby_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Ruby Interpreter Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2020-07-13
# Updated to check for recent version
#
# Copyright:
# Copyright (c) 2009 SecPod, http//www.secpod.com
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
tag_summary = "This script finds the installed Ruby Interpreter and saves the
  version in KB.";

if(description)
{
  script_id(900799);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Ruby Interpreter Version Detection (Windows)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Ruby Interpreter in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900799";
SCRIPT_DESC = "Ruby Interpreter Version Detection (Windows)";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key1 = "SOFTWARE\RubyInstaller\MRI\";
if(registry_key_exists(key:key1))
{
  foreach item (registry_enum_keys(key:key1))
  {
    name = registry_get_sz(key:key1 + item, item:"InstallLocation");
    if("Ruby" >< name)
    {
      patch = registry_get_sz(key:key1 + item, item:"PatchLevel");
      if(patch)
      {
        version = item  + ".p" + patch;
        set_kb_item(name:"Ruby/Win/Ver", value:version);
        security_note(data:"Ruby version " + version + " was detected on the host");

        ## build cpe and store it as host_detail
        register_cpe(tmpVers:version , tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:ruby-lang:ruby:");

        exit(0);
      }
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
      exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("Ruby" >< name)
  {
    rubyVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(rubyVer != NULL)
    {
      replace = ereg_replace(pattern:"-", string:rubyVer, replace:".");
      set_kb_item(name:"Ruby/Win/Ver", value:replace);
      security_note(data:"Ruby version " + replace + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers: replace, tmpExpr:"^([0-9.]+([a-z0-9]+)?)", tmpBase:"cpe:/a:ruby-lang:ruby:");


    }
  }
}
