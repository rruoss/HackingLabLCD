###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_kace_2000_web_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Dell KACE K2000 Detection
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
tag_summary = "The web interface for the  Dell KACE K2000 is running at this Host.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(103317);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-11 10:17:05 +0100 (Fri, 11 Nov 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Dell KACE K2000 Detection");
 
 script_description(desc);
 script_summary("Checks for the presence of Dell KACE K2000");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.kace.com/products/systems-deployment-appliance");
 exit(0);
}

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103317";
SCRIPT_DESC = "Dell KACE K2000 Detection";

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner)exit(0);


 if(egrep(pattern: "X-KACE-Version:", string: banner, icase: TRUE))
 {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: banner, pattern: "X-KACE-Version: ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/dell_kace_version"), value: string(vers));

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/h:dell:kace_k2000_systems_deployment_appliance:");
    if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("\n\nDell KACE K2000 Version '");
    info += string(vers);
    info += string("' was detected on the remote host.\n\n");

    desc = desc + info;

       if(report_verbosity > 0) {
         security_note(port:port,data:desc);
       }
       exit(0);

 }

exit(0);

