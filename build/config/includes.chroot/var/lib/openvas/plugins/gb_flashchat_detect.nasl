###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flashchat_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# FlashChat Version Detection
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
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of FlashChat and sets the
  result in KB.";

if(description)
{
  script_id(800617);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("FlashChat Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of FlashChat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800617";
SCRIPT_DESC = "FlashChat Version Detection";

flashport = get_http_port(default:80);
if(!flashport){
  exit(0);
}

foreach dir (make_list("/chat","/script","/FlashChat", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:flashport);
  rcvRes = http_send_recv(port:flashport, data:sndReq);
  if(rcvRes != NULL)
  {
    if(("200 OK" >< rcvRes) && ("Welcome to FlashChat" >< rcvRes))
    {
      flashchatVer = eregmatch(pattern:"FlashChat v([0-9.]+)", string:rcvRes);
      if(flashchatVer[1] != NULL){

        tmp_version = flashchatVer[1] + " under " + dir;
        set_kb_item(name:"www/" + flashport + "/FlashChat",
                    value:tmp_version);
        security_note(data:"Flash Chat version " + flashchatVer[1] + " running" + 
                           " at location " + dir +  " was detected on the host"); 
   
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:tufat:flashchat:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
      exit(0);
    }
  }
}
