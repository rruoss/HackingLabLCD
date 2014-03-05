###############################################################################
# OpenVAS Vulnerability Test
# $Id: opencart_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# OpenCart Detection
#
# Authors:
# Michael Meyer
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2010-06-15
#   Added code for detecting version from /admin/index.php
#
# Updated By : Madhuri D <dmadhuri@secpod.com> on 2012-04-23
#   Updated according to CR57
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "Detection of OpenCart,free online store system.

The script sends a request to acess the 'admin/index.php' and attempts to
extract the version number from the reply.";

# need desc here to modify it later in script.

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100178";

if (description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("OpenCart Detection");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_name("OpenCart Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Checks for the presence of OpenCart");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");


## Variable Initialization
port = "";
dirs = "";
dir = "";
url = "";
req = "";
buf = "";
install= "";
vers = "";
sndReq = "";
rcvRes = "";
cartVer = "";
tmp_version = "";
cpe = "";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/shop","/store","/opencart","/upload",cgi_dirs());
foreach dir (dirs) {

 url = string(dir, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(
    (egrep(pattern: "Powered By <a [^>]+>OpenCart", string: buf, icase: TRUE) ||
     egrep(pattern: "<title>.* \(Powered By OpenCart\)</title>", string: buf, icase: TRUE)) &&
     egrep(pattern: 'Set-Cookie: language=', string: buf, icase: TRUE) )
 {
    if(strlen(dir)>0) {
       install=dir;
    } else {
       install=string("/");
    }

    vers = string("unknown");

    ## Send and Recieve the response
    sndReq = http_get(item:string(dir, "/admin/index.php"), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

    ## Try to get the version
    cartVer = eregmatch(pattern:">Version ([0-9.]+)<", string:rcvRes);
    if(cartVer[1]) {
      vers = cartVer[1];
    }

    tmp_version = string(vers, " under ", install);
    set_kb_item(name: string("www/", port, "/opencart"), value: tmp_version);
    set_kb_item(name:"OpenCart/installed",value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:opencart:opencart:");
    if(!cpe) {
      cpe = 'cpe:/a:opencart:opencart';
    }  

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data:'OpenCart Detected  version: ' + vers +
    '\nLocation: ' + install +
    '\nCPE: '+ cpe +
    '\n\nConcluded from version identification result:\n' + vers, port:port);
 }
}
