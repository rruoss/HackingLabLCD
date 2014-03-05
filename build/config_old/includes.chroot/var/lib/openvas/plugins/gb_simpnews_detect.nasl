###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simpnews_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# SimpNews Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_summary = "This script finds the running version of SimpNews and saves
  the result in KB.";

if(description)
{
  script_id(801390);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 16:33:48 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("SimpNews Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of SimpNews in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

snPort = get_http_port(default:80);
if(!snPort){
  snPort = 80;
}

if(!get_port_state(snPort)){
  exit(0);
}

foreach dir (make_list("/SimpNews", "/simpnew248", "", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/news.php"), port:snPort);
  rcvRes = http_send_recv(port:snPort, data:sndReq);
  if(">SimpNews</" >< rcvRes)
  {
    snVer = eregmatch(pattern:"> V([0-9.]+)", string:rcvRes);
    if(isnull(snVer[1]))
    {
      sndReq = http_get(item:string(dir , "/admin/news.php"), port:snPort);
      rcvRes = http_send_recv(port:snPort, data:sndReq);
      if(isnull(rcvRes))
      {
        snVer = eregmatch(pattern:"> V([0-9.]+)", string:rcvRes);
        if(isnull(snVer[1]))
        {
          sndReq = http_get(item:string(dir , "/doc/version.txt"),port:snPort);
          rcvRes = http_send_recv(port:snPort, data:sndReq);
          if("Programmversion" >< rcvRes){
            snVer = eregmatch(pattern:"([0-9.]+)", string:rcvRes);
          }
        }
      }
    }

    if(!isnull(snVer[1]))
    {
      set_kb_item(name:"www/" + snPort + "/SimpNews", value:snVer[1]
               + " under " + dir);
      security_note(data:"SimpNews " + snVer[1] + " running at location "
                       + dir + " was detected on the host",port:snPort);
    }
  }
}
