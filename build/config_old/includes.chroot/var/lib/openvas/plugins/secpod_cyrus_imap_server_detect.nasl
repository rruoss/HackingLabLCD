###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cyrus_imap_server_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Cyrus IMAP Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the running version of Cyrus IMAP Server
  and saves the result in KB.";

if(description)
{
  script_id(902220);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Cyrus IMAP Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of Cyrus IMAP Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/imap", 143);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

port = get_kb_item("Services/imap");
if(!port){
  port = 143;
}

banner = get_kb_item(string("imap/banner/", port));
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    {
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}

if(!banner){
  exit(0);
}

if(("Cyrus IMAP" >< banner && "server ready" >< banner))
{

  imapVer = eregmatch(pattern:"IMAP v([0-9.]+)", string:banner);
  if(!isnull(imapVer[1]))
  {
    set_kb_item(name:"Cyrus/IMAP4/Server/Ver", value:imapVer[1]);
    set_kb_item(name:"Cyrus/IMAP4/Server/port", value:port);
    security_note(data:"Cyrus IMAP4 server " + imapVer[1] +
                  " was detected on the host", port:port);
  }
}
