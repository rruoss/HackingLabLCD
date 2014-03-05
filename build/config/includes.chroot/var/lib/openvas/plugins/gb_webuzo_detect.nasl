###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webuzo_detect.nasl 65 2013-11-14 11:18:55Z mime $
#
# Webuzo Detection
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103830";   

if (description)
{
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 65 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_tag(name:"last_modification", value:"$Date: 2013-11-14 12:18:55 +0100 (Do, 14. Nov 2013) $");
 script_tag(name:"creation_date", value:"2013-11-13 18:05:10 +0100 (Wed, 13 Nov 2013)");
 script_name("Webuzo Detection");

tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

 script_description(desc);
 script_summary("Checks for the presence of Webuzo");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 2002, 2004);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:2004);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

url = "/index.php?act=login";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Login" >< buf && "Powered By Webuzo" >< buf && "SOFTCookies" >< buf) {

  set_kb_item(name:"webuzo/installed", value:TRUE);
  vers = 'unknown';

  version = eregmatch(pattern:"Powered By Webuzo ([0-9.]+)", string:buf);

  if(!isnull(version[1]))
     vers = version[1];

   cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:softaculous:webuzo:");
   if(isnull(cpe))
     cpe = 'cpe:/a:softaculous:webuzo';

   register_product(cpe:cpe, location:url, nvt:SCRIPT_OID, port:port);

   log_message(data: build_detection_report(app:"Webuzo", version:vers, install:url, cpe:cpe, concluded: version[0]),
               port:port);

}  

exit(0);


