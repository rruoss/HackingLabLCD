###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_archiva_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Apache Archiva Detection
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
tag_summary = "This host is running Apache Archiva, an extensible repository
management software.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100923);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None"); 
 script_name("Apache Archiva Detection");

 script_description(desc);
 script_summary("Checks for the presence of Apache Archiva");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archiva.apache.org/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

dir = "/archiva";

url = string(dir, "/index.action");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if("<title>Apache Archiva" >< buf && "Artifact ID" >< buf && "The Apache Software Foundation" >< buf)
{

    install = dir;

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: ">Apache Archiva ([0-9.]+)<",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/apache_archiva"), value: string(vers," under ",install));

    info = string("org/\n\nApache Archiva Version '");
    info += string(vers);
    info += string("' was detected on the remote host\n\n");

    desc = ereg_replace(
        string:desc,
        pattern:"org/$",
        replace:info
    );

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);

}

exit(0);
