###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_filezilla_server_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# FileZilla Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_summary = "This script finds the version of FileZilla Server and
  sets the result in KB.";

if(description)
{
  script_id(900518);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 08:26:42 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("FileZilla Server Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of FileZilla Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900518";
SCRIPT_DESC = "FileZilla Server Version Detection";

fzillaPort = get_kb_item("Services/ftp");
if(!fzillaPort){
  fzillaPort = 21;
}

if(get_port_state(fzillaPort))
{
  banner = get_ftp_banner(port:fzillaPort);
  if("FileZilla Server" >!< banner){
    exit(0);
  }

  fzillaVer = eregmatch(pattern:"FileZilla Server version ([0-9a-z.]+)",
                        string:banner);
  if(fzillaVer[1] != NULL){
    set_kb_item(name:"FileZilla/Serv/Ver", value:fzillaVer[1]);
    security_note(data:"FileZilla Server version " + fzillaVer[1] +
                                             " was detected on the host");
    
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:fzillaVer[1], exp:"^([0-9.]+([a-z])?)", base:"cpe:/a:filezilla:filezilla_server:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
