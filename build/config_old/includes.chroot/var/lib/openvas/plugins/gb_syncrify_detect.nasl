###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syncrify_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Syncrify Detection
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
tag_summary = "This host is running Syncrify, an incremental, and cloud-ready backup
that implements the rsync protocol over HTTP.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(100819);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-09-22 16:24:51 +0200 (Wed, 22 Sep 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Syncrify Detection");
 script_description(desc);
 script_summary("Checks for the presence of Syncrify");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 5800);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://web.synametrics.com/Syncrify.htm");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:5800);

if(!get_port_state(port))exit(0);
banner = get_http_banner(port:port);
if(!banner || "Server: Apache-Coyote" >!< banner)exit(0);

url = string(dir, "/app?operation=about");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if("Syncrify" >< buf && "Synametrics Technologies" && "Fast incremental backup" >< buf)
{
    if(strlen(dir)>0) {
       install=dir;
    } else {
       install=string("/");
    }

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Version: ([0-9.]+) - build ([0-9]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
       if(!isnull(version[2])) {
         vers = vers + "." + version[2]; # ver string: Version: 2.1 build 420 -> version in kb 2.1.420
       }	 
    }

    set_kb_item(name: string("www/", port, "/syncrify"), value: string(vers," under ",install));

    info = string("htm\n\nSyncrify Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    desc = ereg_replace(
        string:desc,
        pattern:"htm$",
        replace:info
    );

   if(report_verbosity > 0) {
     security_note(port:port,data:desc);
   }
   exit(0);
 }

exit(0);

