###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_XI_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Nagios XI Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Detection of Nagios XI.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100752";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"detection", value:"remote probe");
  script_name("Nagios XI Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Nagios XI");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");


port = "";
dirs = "";
url = "";
req = "";
buf = "";
install = "";
vers = "";
version = "";
cpe = "";

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

if(!can_host_php(port:port)){
  exit(0);
}

dirs = make_list("/nagiosxi","/nagios",cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/login.php");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;

  if(egrep(pattern: "Set-Cookie: nagiosxi", string: buf, icase: TRUE) &&
    "Nagios Enterprises" >< buf && "Nagios XI - Login" >< buf)
  {

    if(strlen(dir)>0) {
       install=dir;
    } else {
       install=string("/");
    }

    vers = string("unknown");

    ### try to get version
    version = eregmatch(string: buf, pattern: 'footernotice">Nagios XI (20[0-9]{2}[^ ]+)',icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/nagiosxi"), value: string(vers," under ",install));

    set_kb_item(name:"nagiosxi/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^(20[0-9]{2}[^ ]+)", base:"cpe:/a:nagios:nagiosxi:");
    if(isnull(cpe))
      cpe = 'cpe:/a:nagios:nagiosxi:';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Nagios XI", version:vers, install:install,
                cpe:cpe, concluded:vers), port:port);

 }
}
exit(0);
