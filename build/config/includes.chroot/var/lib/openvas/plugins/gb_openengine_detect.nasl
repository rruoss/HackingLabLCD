###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openengine_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# openEngine Detection
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
tag_summary = "This host is running openEngine, a Web Content Management System.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100845);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-10-06 12:55:58 +0200 (Wed, 06 Oct 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None"); 
 script_name("openEngine Detection");

 script_description(desc);
 script_summary("Checks for the presence of openEngine");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.openengine.de");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100845";
SCRIPT_DESC = "openEngine Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/openengine","/cms",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/cms/website.php?id=/de/index.htm&admin=login");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: '<title>openEngine', string:  buf, icase: FALSE) &&
    egrep(pattern:"openEngine.*Open Source Web Content Management System", string:buf))
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "openEngine ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/openengine"), value: string(vers," under ",install));
    if(vers == "unknown") {
      register_host_detail(name:"App", value:string("cpe:/a:openengine:openengine"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else { 
      register_host_detail(name:"App", value:string("cpe:/a:openengine:openengine:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }

    info = string("dee\n\nopenEngine Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    desc = ereg_replace(
        string:desc,
        pattern:"de$",
        replace:info
    );

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);
 }
}
exit(0);

