###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_merak_mail_server_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Merak Mail Server Web Mail Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-09-27
#   Updated to detect the recent versions.
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of Merak Mail Server Web Mail.
                     
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800096";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-02 09:27:25 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("Merak Mail Server Web Mail Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Merak Mail Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get the default port
port = get_http_port(default:80);
if(!port){
  port = 32000;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

banner = get_http_banner(port);
if("IceWarp" >!< banner){
  exit(0);
}

version = eregmatch(pattern:"(Merak|IceWarp).?([0-9.]+)", string:banner);
if(version[2] == NULL)
{
  smtpPort = get_kb_item("Services/smtp");
  if(!smtpPort){
    smtpPort = 25;
  }

  imapPort = get_kb_item("Services/imap");
  if(!imapPort){
    imapPort = 143;
  }

  popPort = get_kb_item("Services/pop3");
  if(!popPort){
    popPort = 110;
  }

  foreach port (make_list(smtpPort, imapPort, popPort))
  {
    banner = get_kb_item(string("Banner/", port));
    if(banner =~ "IceWarp|Merak")
    {
      version = eregmatch(pattern:"(Merak|IceWarp) ([0-9.]+)", string:banner);
      if(version[2] != NULL){
         ver = version[2];
     }
   }
  }
}
else if(version[2] != NULL){
 ver = version[2];
}

if(ver)
{

  install = '/';  
  dirs = make_list("/webmail",cgi_dirs());

  foreach dir (dirs) {
    url = dir + '/';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
    if(buf =~ "<title>(Merak|IceWarp)") {
      install = dir;
      break;
    }  
  }  

  set_kb_item(name:"MerakMailServer/Ver", value:ver);
  cpe = build_cpe(value:ver, exp:"^([0-9.]+)", base:"cpe:/a:icewarp:merak_mail_server:");
  if(isnull(cpe))
    cpe = 'cpe:/a:icewarp:merak_mail_server';

   register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

   log_message(data: build_detection_report(app:"Merak Mail Server Web Mail", version:ver, install:install, cpe:cpe, concluded: banner),
               port:port);
   exit(0);
  
}

exit(0);
