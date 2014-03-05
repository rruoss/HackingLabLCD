##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tikiwiki_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# TikiWiki Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated by Rachana Shetty <srachana@secpod.com> on 2011-12-06
# - Updated to detect the recent versions and CR 57
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
################################################################################

include("revisions-lib.inc");
tag_summary = "Detection of TikiWiki, a open source web application
is a wiki-based CMS (http://tiki.org/tiki-index.php).

The script sends a connection request to the web server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901001";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("TikiWiki Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for TikiWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");

tikiPort = get_http_port(default:80);
if(!tikiPort){
  tikiPort = 80;
}

if(!get_port_state(tikiPort)){
  exit(0);
}

foreach dir (make_list("/tikiwiki", "/tiki", "/wiki", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/tiki-index.php"), port:tikiPort);
  rcvRes = http_send_recv(port:tikiPort, data:sndReq);

  if("TikiWiki" >< rcvRes || "Tiki Wiki CMS" >< rcvRes)
  {
    tikiVer = eregmatch(pattern:"TikiWiki ([0-9.]+)", string:rcvRes);

    if(tikiVer == NULL)
    {
      sndReq = http_get(item:string(dir, "/README"), port:tikiPort);
      rcvRes = http_send_recv(port:tikiPort, data:sndReq);
      tikiVer = eregmatch(pattern:"[v|V]ersion ([0-9.]+)", string:rcvRes);
    }

    if(tikiVer[1] != NULL)
    {
      tmp_version = tikiVer[1] + " under " + dir;

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:tikiwiki:tikiwiki:");
      if(!cpe) {
        cpe = 'cpe:/a:tikiwiki:tikiwiki';
      }  

      register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:tikiPort);

      set_kb_item(name:"TikiWiki/" + tikiPort + "/Ver", value:tmp_version);
      set_kb_item(name:"TikiWiki/installed", value:TRUE);

      log_message(data:'Detected TikiWiki version: ' + tmp_version +
                       '\nLocation: ' + dir +
                       '\nCPE: '+ cpe +
                       '\n\nConcluded from version identification result:\n' +
                       tikiVer[max_index(tikiVer)-1], 
                  port:tikiPort);
    }
  }
}
