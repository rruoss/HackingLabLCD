###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# DokuWiki Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Rachana Shetty <srachana@secpod.com> on 2010-02-18
# Update to consider the bodyonly for responses
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
tag_summary = "Detection of Dokuwiki.

The script sends a connection request to the server and attempts to extract the
version number from the reply.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800587";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"detection", value:"remote probe");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("DokuWiki Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for the presence of DokuWiki");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

dokuwikiPort = get_http_port(default:80);
if(!dokuwikiPort){
  dokuwikiPort = 80;
}

if(!get_port_state(dokuwikiPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:dokuwikiPort)){
  exit(0);
}

foreach dir (make_list("", "/dokuwiki", cgi_dirs()))
{

  req = http_get(item:string(dir + "/feed.php"), port:dokuwikiPort);
  rcv = http_keepalive_send_recv(port:dokuwikiPort, data:req,bodyonly:0);
  if("<title>dokuwiki" >!< tolower(rcv))continue;

  sndReq = http_get(item:string(dir + "/VERSION"), port:dokuwikiPort);
  rcvRes = http_keepalive_send_recv(port:dokuwikiPort, data:sndReq, bodyonly:1);
  if (rcvRes != NULL)
  {
    dokuwikiVer = eregmatch(pattern:"(rc)?([0-9]+\-[0-9]+\-[0-9]+[a-z]?)",
                            string:rcvRes);
    dokuVer = ereg_replace(pattern:"-", string:dokuwikiVer[2], replace: ".");
    if(dokuVer)
    {
      tmp_version = dokuVer + " under " + dir;
      set_kb_item(name:"www/" + dokuwikiPort + "/DokuWiki",
                  value:tmp_version);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+[a-z0-9]+?)", base:"cpe:/a:dokuwiki:dokuwiki:");
      if(isnull(cpe))
        cpe = 'cpe:/a:dokuwiki:dokuwiki';

      register_product(cpe:cpe, location:dir, nvt:SCRIPT_OID, port:dokuwikiPort);

      log_message(data: build_detection_report(app:"Dokuwiki",
                                         version:dokuVer,
                                         install:dir,
                                         cpe:cpe,
                                         concluded: dokuwikiVer[max_index(dokuwikiVer)-1]),
                                         port: dokuwikiPort);
    }
  }
  set_kb_item(name:"dokuwiki/installed",value:TRUE);
}
