###############################################################################
# OpenVAS Vulnerability Test
# $Id: ntop_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Ntop Detection
#
# Authors:
# Michael Meyer
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
tag_summary = "Detection of Ntop

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100256";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-08-23 12:14:46 +0200 (Sun, 23 Aug 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Ntop Detection");

 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Ntop");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 3000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100256";

port = get_http_port(default:3000);
if(!get_port_state(port))exit(0);

buf = get_http_banner(port:port);
if( buf == NULL )exit(0);

if(egrep(pattern:"Server: ntop" , string: buf, icase: TRUE))
 {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Server: ntop/([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/ntop"), value: string(vers));
    set_kb_item(name: string("/ntop/installed"), value: TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:string(vers), exp:"^([0-9.]+)", base:"cpe:/a:ntop:ntop:");
    if(isnull(cpe))
      cpe = 'cpe:/a:ntop:ntop'; 

    register_product(cpe:cpe, location:'/', nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Ntop", version:vers, install:'/', cpe:cpe, concluded: version[0]),
                port:port);




 }

exit(0);
