##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_postgresql_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# PostgreSQL Version Detection (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "This script detects the installed version of PostgreSQL and
  saves the result in KB.";

if(description)
{
  script_id(900479);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("PostgreSQL Version Detection (Windows)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the KB for the Version of PostgreSQL");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900479";
SCRIPT_DESC = "PostgreSQL Version Detection (Windows)";

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\PostgreSQL")){
  exit(0);
}

key = "SOFTWARE\PostgreSQL Global Development Group\PostgreSQL\";
path = registry_get_sz(key:key, item:"Location");

exePath = path + "\bin\postgres.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

gresqlVer = GetVer(file:file, share:share);
if(gresqlVer != NULL)
{
  set_kb_item(name:"PostgreSQL/Win/Ver", value:gresqlVer);
  security_note(data:"PostgreSQL version " + gresqlVer + " running at " +
                     "location " + path +  " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: gresqlVer, exp:"^([0-9.]+)",base:"cpe:/a:postgresql:postgresql:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}
