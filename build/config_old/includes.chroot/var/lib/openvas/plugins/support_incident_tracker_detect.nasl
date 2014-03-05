###############################################################################
# OpenVAS Vulnerability Test
# $Id: support_incident_tracker_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# SiT! Support Incident Tracker Detection
#
# Authors:
# Michael Meyer
#
# Updated by Madhuri D <dmadhuri@secpod.com> on 2011-07-28
#   - Modified the regex for detecting p1 versions.
#
# Updated By : Rachana Shetty <srachana@secpod.com> on 2012-02-03
#  - Updated to set KB if SIT is installed
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
tag_summary = "This host is running SiT! Support Incident Tracker, a web based
application which uses PHP and MySQL for tracking technical support
calls/emails.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100466);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("SiT! Support Incident Tracker Detection");

 script_description(desc);
 script_summary("Checks for the presence of SiT! Support Incident Tracker");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://sitracker.org/wiki/Main_Page");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100466";
SCRIPT_DESC = "SiT! Support Incident Tracker Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/tracker","/support","/sit", cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: '<meta name="GENERATOR" content="SiT! Support Incident Tracker', string: buf, icase: TRUE) &&
    "SiT! - Login" >< buf )
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Support Incident Tracker v(([0-9.]+).?([a-zA-Z0-9]+))",icase:TRUE);
    if (!isnull(version[1])){
      vers = ereg_replace(pattern:" |-", string:version[1], replace:".");
    }

    ## To set version
    if(vers != NULL){
      tmp_version = vers + " under " + dir;
    }
    else
    {
      tmp_version = "unknown under " + dir;
      vers = "unknown";
    }
    tmp_version = vers + " under " + dir;
    set_kb_item(name:"www/" + port + "/support_incident_tracker", value:tmp_version);
    set_kb_item(name:"sit/installed",value:TRUE);


    info = string("\n\nSiT! Support Incident Tracker Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    desc = desc + info;

    ## build cpe and store it as host detail
    register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+)",tmpBase:"cpe:/a:sitracker:support_incident_tracker:");

    if(report_verbosity > 0) {
      security_note(port:port,data:desc);
    }
    exit(0);
 }
}
exit(0);

