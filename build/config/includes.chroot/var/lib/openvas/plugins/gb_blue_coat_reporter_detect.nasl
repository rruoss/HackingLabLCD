###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_blue_coat_reporter_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Blue Coat Reporter Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "This host is running ther Blue Coat Reporter.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(103245);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-08 15:23:37 +0200 (Thu, 08 Sep 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Blue Coat Reporter Detection");

 script_description(desc);
 script_summary("Checks for the presence of Blue Coat Reporter");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.bluecoat.com/products/proxysg/addons/reporter");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);

if("BCReport" >!< banner && "Blue Coat Reporter" >!< banner)exit(0);

url = string("/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( buf == NULL )continue;

if(egrep(pattern: "Blue Coat Reporter", string: buf, icase: TRUE))
{

    vers = string("unknown");
    ### try to get version 

    version = eregmatch(string: buf, pattern:'[ \t\r\n]alert[ \t]*\\([ \t]*"Blue Coat Reporter:[ \t]*([0-9.]+).*-[ \t]*build number:[ \t]*([0-9]+))"');

    if(!isnull(version)) {
      vers  = version[1];
      if(!isnull(version[2]))vers = vers + ' Build ' + version[2];

    } else {

      server_info = eregmatch(pattern:'src="(serverinfo.js\\?cb=[^"]+)"',string:buf); 
      
      if(!isnull(server_info[1])) {

        url = "/" + server_info[1];
        req = http_get(item:url, port:port);
        buf1 = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        version = eregmatch(string: buf1, pattern: "version='([0-9.]+)'.*build='([0-9]+)'",icase:TRUE);

        if(!isnull(version)) {
          vers  = version[1];
  	  if(!isnull(version[2]))vers = vers + ' Build '+  version[2];
        }

      }

    }

    set_kb_item(name: string("www/", port, "/blue_coat_reporter"), value: string(vers," under /"));

    info = string("reporter\n\nBlue Coat Reporter Version '");
    info += string(vers);
    info += string("' was detected on the remote host\n");

    desc = ereg_replace(
        string:desc,
        pattern:"reporter$",
        replace:info
    );

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);

}

exit(0);

