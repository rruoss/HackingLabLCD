###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Dlink DIR Devices Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "Detection of Dlink DIR Devices
                    
The script sends a connection request to the server and attempts to
determine if the remote host is a Dlink DIR device from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103689";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-04-08 13:52:56 +0200 (Mon, 08 Apr 2013)");
 script_name("Dlink DIR Devices Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Dlink DIR Devices");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

fw = FALSE;
typ = FALSE;

if(banner =~ "Server: Linux, HTTP/1.1, DIR-[0-9]+[^ ]++ Ver") {

  typ = 'unknown';
  dlink_typ = eregmatch(pattern:", DIR-([^ ]+)", string:banner);
  if(!isnull(dlink_typ[1])) typ = dlink_typ[1];

  fw = 'unknown';
  fw_version = eregmatch(pattern:string("Ver ([^\r\n]+)"), string:banner);
  if(!isnull(fw_version[1])) fw = fw_version[1];
  concluded = banner;

}  else {

  if("Server: Mathopd/" >< banner) {
  
    url = "/";
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>D-LINK" >< buf && "LOGIN_USER" >!< buf) {

      url = "/index_temp.php";
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    }  

    if("<title>D-LINK" >!< buf && "LOGIN_USER" >!< buf)exit(0);

    typ = 'unknown';
    dlink_typ = eregmatch(pattern:"class=l_tb>DIR-([^ <]+)<", string:buf);
    if(!isnull(dlink_typ[1])) typ = dlink_typ[1];

    fw = 'unknown';
    fw_version = eregmatch(pattern:string(">Firmware Version&nbsp;:&nbsp;([^& ]+)&nbsp;<"), string:buf);
    if(!isnull(fw_version[1])) fw = fw_version[1];
    concluded = dlink_typ[0] + ' ' + fw_version[0];

  }

}

if(fw && typ) {

  tmp_cpe = 'cpe:/h:dlink:dir-' + typ;

  cpe = build_cpe(value:tolower(fw), exp:"^([0-9A-Za-z.]+)", base: tmp_cpe + ":");
  if(isnull(cpe))
    cpe = tmp_cpe;

  set_kb_item(name:"host_is_dlink_dir", value:TRUE);
  set_kb_item(name:"dlink_typ/", value:'DIR-' + typ);
  set_kb_item(name:"dlink_fw_version", value:fw);
  set_kb_item(name:"dlink_dir_port", value: port);

  register_product(cpe:cpe, location:port + '/tcp', nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"Dlink DIR-" + typ, version:fw, install:port + '/tcp', cpe:cpe, concluded: concluded),
              port:port);

  exit(0);

}  
