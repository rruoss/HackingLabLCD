###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_detect_lin.nasl 42 2013-11-04 19:41:32Z jan $
#
# Wireshark Version Detection (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-21
# Revsied to comply with Change Request #57.
#
# Copyright:
# Copyright (c) 2008, 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of installed version of Wireshark.

The script logs in via ssh, searches for executable 'wireshark' and
queries the found executables via command line option '-v'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800039";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-10-24 15:11:55 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"detection", value:"executable version check");
  script_name("Wireshark Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008, 2011 Greenbone Networks GmbH");
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
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  if (defined_func("error_message"))
    error_message(port:port, data:"Failed to open ssh port.");
  exit(-1);
}

wiresharkName = find_file(file_name:"wireshark", file_path:"/", useregex:TRUE,
                          regexpar:"$", sock:sock);
foreach executableFile (wiresharkName)
{
  executableFile = chomp(executableFile);
  sharkVer = get_bin_version(full_prog_name:executableFile, version_argv:"-v",
                             ver_pattern:"wireshark ([0-9.]+)", sock:sock);
  if(sharkVer)
  {
    set_kb_item(name:"Wireshark/Linux/Ver", value:sharkVer[1]);

    cpe = build_cpe(value:sharkVer[1], exp:"^([0-9.]+)", base:"cpe:/a:wireshark:wireshark:");
    if(!isnull(cpe))
       register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);

    log_message(data:'Detected Wireshark version: ' + sharkVer[1] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + sharkVer[max_index(sharkVer)-1]);
  }
}

ssh_close_connection();
