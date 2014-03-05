###############################################################################
# OpenVAS Vulnerability Test
# $Id: GlassFish_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# GlassFish Server Detection
#
# Authors:
# Michael Meyer
#
# Updated by: Antu Sanadi <santu@secpod.com> on 2010-01-31
# Updated to detect recent versions (3.x)
# Updated to to read the data from index.html, on 2012-01-06
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2012-05-07
# - Updated according to CR57
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
tag_summary = "Detection of Oracle GlassFish Server.

The script sends a connection request to the server and attempts to extract the
version number from the reply.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100190";

if (description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_tag(name:"detection", value:"remote probe");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("GlassFish Server Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Checks for the presence of GlassFish Server");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

 url = string("/index.html");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

 if( buf == NULL )continue;
 if( egrep(pattern: '.*GlassFish.*', string: buf, icase: TRUE) ||
     egrep(pattern: 'Server:.*GlassFish.*', string: buf, icase: TRUE))
 {

    vers = string("unknown");

    version = eregmatch(string: buf, pattern: 'Server:.*GlassFish[^0-9]+v([0-9.]+)',icase:TRUE);
    if(isnull(version[1]))
    {
     version = eregmatch(string: buf, pattern: "GlassFish Server ([0-9.]+)",icase:TRUE);
     if(!isnull(version[1]))
      vers = version[1];
    }
    else {
     vers = version[1];
    }

    if(egrep(pattern:"Location:.*login.jsf", string: buf) ||
      (egrep(pattern:"Log In to.*GlassFish", string:buf) && "<title>Login" >< buf)) {

      report = "\nThe GlassFish Administration Console is running at this Port.\n";
      set_kb_item(name: string("www/", port, "/GlassFishAdminConsole"), value: TRUE);
      set_kb_item(name: string("GlassFishAdminConsole/port"), value: port);
    }  else {
      set_kb_item(name: string("www/", port, "/GlassFish"), value: vers);

      ## build cpe and store it as host_detail
      cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:oracle:glassfish_server:");
      if(isnull(cpe))
        cpe = 'cpe:/a:oracle:glassfish_server';

      register_product(cpe:cpe, location:'/', nvt:SCRIPT_OID, port:port);

    }
    set_kb_item(name:"GlassFish/installed",value:TRUE);

    log_message(data: build_detection_report(app:"GlassFish Server",
                version:vers, install:'/', cpe:cpe, concluded: vers),
                port:port);

  }
exit(0);
