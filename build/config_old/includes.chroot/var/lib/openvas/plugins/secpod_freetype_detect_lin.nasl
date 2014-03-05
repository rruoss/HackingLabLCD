###############################################################################
# OpenVAS Vulnerability Test
# $Id:secpod_freetype_detect_lin.nasl 1793 2009-04-22 13:00:34Z apr $
#
# FreeType Version Detection (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-24
# Revised to comply with Change Request #57.
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
tag_summary = "Detection of installed version of FreeType.

The script logs in via ssh, searches for executable 'freetype-config' and
queries the found executables via command line option '--ftversion'.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900626";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"detection", value:"executable version check");
  script_name("FreeType Version Detection (Linux)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Detection of installed version of FreeType");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

binFiles = find_file(file_name:"freetype-config",file_path:"/", useregex:TRUE,
                    regexpar:"$", sock:sock);
foreach executableFile (binFiles)
{
  executableFile = chomp(executableFile);
  ftVer = get_bin_version(full_prog_name:executableFile, sock:sock,
                  version_argv:"--ftversion",ver_pattern:"[0-9.]+");
  if(ftVer[0] != NULL)
  {
    set_kb_item(name:"FreeType/Linux/Ver", value:ftVer[0]);
    cpe = build_cpe(value:ftVer[0], exp:"^([0-9.]+)", base:"cpe:/a:freetype:freetype:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:executableFile, nvt:SCRIPT_OID);

    log_message(data:'Detected FreeType version: ' + ftVer[0] +
        '\nLocation: ' + executableFile +
        '\nCPE: '+ cpe +
        '\n\nConcluded from version identification result:\n' + ftVer[max_index(ftVer)-1]);
  }
}

ssh_close_connection();
