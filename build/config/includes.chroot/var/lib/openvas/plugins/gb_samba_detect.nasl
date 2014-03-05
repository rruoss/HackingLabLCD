###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Samba Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Modified by: Sujit Ghosal (sghosal@secpod.com)
# Date: 8th May 2009
# Changes: Changed the command from smbd to smbclient and Modified Regex
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-24
# Revised to comply with Change Request #57.
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
tag_summary = "Detection of installed version of Samba.

The script logs in via ssh, searches for executable 'smbd' and
queries the found executables via command line option '-V'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800403";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"detection", value:"executable version check");
  script_name("Samba Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}

smbName = find_file(file_name:"smbd", file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);
foreach executableFile (smbName)
{
  executableFile = chomp(executableFile);
  smbVer = get_bin_version(full_prog_name:executableFile, version_argv:"-V",
                           ver_pattern:"Version (.*)", sock:sock);
  smbVer = split(smbVer[1], "\n", keep:0);
  if(smbVer[0] != NULL)
  {
    set_kb_item(name:"Samba/Version", value:smbVer[0]);
    log_message(data:'Detected Samba version: ' + smbVer[0] +
        '\nLocation: ' + executableFile +
        '\n\nConcluded from version identification result:\n' + smbVer[max_index(smbVer)-1]);

#    cpe = build_cpe(value:gzipVer[1], exp:"^([0-9.]+)", base:"cpe:/a:TODO:TODO:");
#    if(!isnull(cpe))
#      register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);
  }
}
ssh_close_connection();