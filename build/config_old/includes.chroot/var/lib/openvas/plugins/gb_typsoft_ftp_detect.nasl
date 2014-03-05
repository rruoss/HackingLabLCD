##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typsoft_ftp_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# TYPSoft FTP Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
################################################################################

include("revisions-lib.inc");
tag_summary = "This script determines the TYPSoft FTP server version on the remote host
  and sets the result in the KB.";

if(description)
{
  script_id(801057);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("TYPSoft FTP Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB of TYPSoft FTP version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801057";
SCRIPT_DESC = "TYPSoft FTP Server Version Detection";

port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_ftp_banner(port:port);
if("TYPSoft FTP" >< banner)
{
  tsVer = eregmatch(pattern:"TYPSoft FTP Server ([0-9.]+)", string:banner);
  if(tsVer[1] != NULL)
  {
    set_kb_item(name:"TYPSoft/FTP/Ver", value:tsVer[1]);
    security_note(data:"TYPSoft FTP Server version " + tsVer[1] +
                         " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tsVer[1], exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:typsoft:typsoft_ftp_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
