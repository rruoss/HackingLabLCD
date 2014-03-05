###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netscape_detect_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Netscape Version Detection (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of Netscape browser
  and sets the result in KB.";

if(description)
{
  script_id(900394);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Netscape Version Detection (Linux)");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Netscape");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900394";
SCRIPT_DESC = "Netscape Version Detection (Linux)";

scape_sock = ssh_login_or_reuse_connection();
if(!scape_sock){
  exit(0);
}

netflag = 1;
scapePaths = find_file(file_name:"netscape", file_path:"/netscape/", useregex:TRUE,
                       regexpar:"$", sock:scape_sock);
foreach scapeBin (scapePaths)
{
  scapeVer = get_bin_version(full_prog_name:chomp(scapeBin), sock:scape_sock,
                             version_argv:"-version", ver_pattern:"Netscape" +
                                       "[0-9]\/([0-9.]+)(, build ([0-9]+))?");
  if(scapeVer == NULL){
    netflag = 0;
  }
}

if(netflag == 0)
{
  scapePaths = find_file(file_name:"install.log", file_path:"/netscape/",
                         useregex:TRUE, regexpar:"$", sock:scape_sock);
  foreach scapeBin (scapePaths)
  {
    scapeVer = get_bin_version(full_prog_name:"cat", sock:scape_sock,
                               version_argv:chomp(scapeBin),
                               ver_pattern:"Netscape([a-zA-Z (/]+)?([0-9]\.[0-9.]+)");
  }
  if(scapeVer == NULL){
    exit(0);
  }
}

if("Netscape" >< scapeVer)
{
  if(scapeVer[1] =~ "^[0-9][0-9.]+")
  {
    if(scapeVer[3] =~ "^[0-9][0-9]+")
      ver = scapeVer[1] + "." + scapeVer[3];
    else
      ver = scapeVer[1];
  }
  else if(scapeVer[2] =~ "^[0-9][0-9.]+")
    ver = scapeVer[2];
  if(ver != NULL){
    set_kb_item(name:"Netscape/Linux/Ver", value:ver);
    security_note(data:"Netscape version " + ver + " was detected on the host");
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ver, exp:"^([0-9]+)", base:"cpe:/a:netscape:navigator:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
