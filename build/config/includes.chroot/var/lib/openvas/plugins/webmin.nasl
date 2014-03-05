# OpenVAS Vulnerability Test
# $Id: webmin.nasl 50 2013-11-07 18:27:30Z jan $
# Description: Check for Webmin
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "Detection of Symantec Web Webmin.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.10757";

if(description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 50 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 script_name("Check for Webmin");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 
 script_summary("Check for Webmin");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 script_family("Product detection");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 10000);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:10000);

foreach port (ports)
{
 banner = get_http_banner(port:port);

 if(banner)
 {
  if(egrep(pattern:"^Server: MiniServ.*",string:banner))
  {
     banner = http_keepalive_send_recv(port:port, data:http_get(item:"/",port:port));
     if(banner != NULL ) {
     if(egrep(pattern:"webmin", string:banner, icase:TRUE))
     {

     set_kb_item(name:"www/" + port + "/webmin", value:TRUE);
     set_kb_item(name:"webmin/installed",value:TRUE);

     version = ereg_replace(pattern:".*Webmin *([0-9]\.[0-9][0-9]).*$", string:banner, replace:"\1");
     concluded = version;
     if (version == banner) version = 'unknown';

     if (version)
     {
       set_kb_item(name:"webmin/" + port + "/version",value:version); 

       cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:webmin:webmin:");
       if(!cpe)
         cpe = 'cpe:/a:webmin:webmin';

       register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);
       log_message(data: build_detection_report(app:"Webmin", version:vers, install:'/', cpe:cpe, concluded: iconcluded),
                   port:port);

     }
    }
   }
  }
 }
}
