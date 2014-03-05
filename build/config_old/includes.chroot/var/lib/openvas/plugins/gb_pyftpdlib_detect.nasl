###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# pyftpdlib Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the version of running FTPServer.py in pyftpdlib
  and saves the result in KB.";

if(description)
{
  script_id(801612);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("pyftpdlib Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of pyftpdlib in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801612";
SCRIPT_DESC = "pyftpdlib Version Detection";

## Get FTP port
port = get_kb_item("Services/ftp");
if(!port) {
  port = 21;
}

## Check port status
if(!get_port_state(port)) {
  exit(0);
}

## Get Banner
banner = get_ftp_banner(port:port);
if("pyftpd" >< tolower(banner))
{
  ## Get Version from Banner
  ver = eregmatch(pattern:"[Pyftpd|pyftpdlib] ([0-9.]+)",string:banner);

  ## Set pyftpdlib Version in KB
  if(ver[1] != NULL)
  {
    set_kb_item(name:"pyftpdlib/Ver", value:ver[1]);
    security_note(data:"pyftpdlib FTP server version " + ver[1] +
                       " was detected on the host", port:port);
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:g.rodola:pyftpdlib:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
