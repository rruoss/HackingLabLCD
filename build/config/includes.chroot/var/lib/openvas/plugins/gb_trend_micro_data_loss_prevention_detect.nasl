###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_data_loss_prevention_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Trend Micro Data Loss Prevention Detection
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
tag_summary = "This host is running Trend Micro Data Loss Prevention, a network and
endpoint-based data loss prevention (DLP) solution.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 
 script_id(103181);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("Trend Micro Data Loss Prevention Detection");
 script_description(desc);
 script_summary("Checks for the presence of Trend Micro Data Loss Prevention");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:8443);
if(!get_port_state(port))exit(0);

url = string("/dsc/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);

 if(egrep(pattern: "<title>Trend Micro Data Loss Prevention Logon", string: buf, icase: TRUE))  {

   install = "/dsc";

   vers = string("unknown");

   set_kb_item(name: string("www/", port, "/trend_micro_data_loss_prevention"), value: string(vers," under ",install));

   if(report_verbosity > 0) {
     security_note(port:port);
   }
   exit(0);

}

exit(0);

