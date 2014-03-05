###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_gupnp_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# GUPnP Version Detection
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
tag_summary = "The script detects the installed version of GUPnP and sets the
  reuslt into KB.";

if(description)
{
  script_id(900681);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("GUPnP Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for GUPnP version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900681";
SCRIPT_DESC = "GUPnP Version Detection";

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

gupnpPaths = find_file(file_name:"config.status", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);
foreach gupnpBin (gupnpPaths)
{
  gupnpVer = get_bin_version(full_prog_name:chomp(gupnpBin), sock:sock,
                             version_argv:"--version",
                             ver_pattern:"gupnp config.status ([0-9.]+)");
  if(gupnpVer[1] != NULL){
    set_kb_item(name:"GUPnP/Ver", value:gupnpVer[1]);
    security_note(data:"GUPnP version " + gupnpVer[1] +
            " running at location " + gupnpBin + " was detected on the host");
    
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:gupnpVer[1], exp:"^([0-9.]+)", base:"cpe:/a:gupnp:gupnp:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
ssh_close_connection();
