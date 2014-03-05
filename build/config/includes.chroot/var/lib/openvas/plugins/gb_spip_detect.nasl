###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_spip_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# SPIP Detection
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103776";   

if (description)
{
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 18 $");
 script_tag(name:"detection", value:"remote probe");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-29 11:47:51 +0200 (Thu, 29 Aug 2013)");
 script_name("SPIP Detection");

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
 script_summary("Checks for the presence of SPIP");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

dirs = make_list("/spip",cgi_dirs());

foreach dir (dirs) {

  url = dir + '/spip.php';
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if("Composed-By: SPIP" >< buf) {

    if( strlen( dir ) > 0 )
      install = dir;
    else
      install = '/';

    vers = 'unknown';

    version = eregmatch(pattern:"Composed-By: SPIP ([^ ]+)", string:buf);
    if(isnull(version[1])) {
      version = eregmatch(pattern:'meta name="generator" content="SPIP ([^ ]+)', string:buf);
    }  

    if(!isnull(version[1]))vers = version[1];

    set_kb_item(name: string("www/", port, "/spip"), value: vers + ' under ' + install);
    set_kb_item(name:"spip/installed",value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:spip:spip:");
    if(isnull(cpe))
      cpe = 'cpe:/a:spip:spip';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"SPIP", version:vers, install:install, cpe:cpe, concluded: version[0]),
                port:port);


  }  


}  

exit(0);






















