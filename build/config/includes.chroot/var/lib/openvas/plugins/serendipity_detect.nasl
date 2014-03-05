###############################################################################
# OpenVAS Vulnerability Test
# $Id: serendipity_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Serendipity Detection
#
# Authors:
# Michael Meyer
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-09-21
# Updated to detect the recent versions
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
tag_summary = "Detection of Serendipity.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100112";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-04-08 12:09:59 +0200 (Wed, 08 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Serendipity Detection");

 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Serendipity");
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

## Constant values
SCRIPT_DESC = "Serendipity Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/serendipity", "/", cgi_dirs());
foreach dir (dirs)
{
  url = string(dir, "/index.php");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( buf == NULL )continue;
  if(egrep(pattern: "Powered.by.*Serendipity", string: buf, icase: TRUE))
  {
    ### try to get version
    vers = eregmatch(string: buf, pattern: "Serendipity v\.([0-9.]+[-a-zA-Z0-9]*)",icase:TRUE);
    if(vers){
       directory = dir;
    }

    if(isnull(vers[1]))
    {
      url = string(dir, "/serendipity_admin.php");
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
      if("Powered by Serendipity" >< buf)
      {
        version = eregmatch(string: buf, pattern: "Serendipity ([0-9.]+[-a-zA-Z0-9]*)",icase:TRUE);
        if(version)
        {
          vers = version;
          directory = dir;
        }
      }
    }
  }

  if(vers[1])
  {
    tmp_version = string(vers[1]," under ", directory);

    set_kb_item(name: string("www/", port, "/serendipity"), value: tmp_version);
    set_kb_item(name:"Serendipity/installed", value:TRUE);

    cpe = build_cpe(value:vers[1], exp:"^([0-9.]+)", base:"cpe:/a:s9y:serendipity:");
    if(isnull(cpe))
      cpe = 'cpe:/a:s9y:serendipity';

    register_product(cpe:cpe, location:directory, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Serendipity", version:vers[1], install:directory, cpe:cpe, concluded: vers[0]),
                port:port);
   
    exit(0);
   
  }
}
