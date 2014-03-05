###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_artica_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Artica Detection
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
tag_summary = "This host is running Artica, a full web based management console.";

if (description)
{
 
 script_id(100870);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Artica Detection");

 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Checks for the presence of Artica");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 9000);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.artica.fr/");
 exit(0);
}

include("http_func.inc");
include("openvas-https.inc");
include("global_settings.inc");

port = 9000;

if(!get_port_state(port))exit(0);

req = string("GET /logon.php HTTP/1.1\r\nHost: ",get_host_name(),"\r\n");
buf = https_req_get(port:port,request:req);
if( buf == NULL )exit(0);

if("lighttpd" >< buf && "artica-language" >< buf && "artica-template" >< buf && "Artica for postfix" >< buf)
{

   set_kb_item(name: string("www/", port, "/artica"), value: TRUE);

   if(report_verbosity > 0) {
     security_note(port:port);
   }
   exit(0);

}

exit(0);

