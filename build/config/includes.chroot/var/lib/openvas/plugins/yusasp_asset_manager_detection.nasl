# OpenVAS Vulnerability Test
# $Id: yusasp_asset_manager_detection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: YusASP Web Asset Manager Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "YusASP Web Asset Manager is a complete file manager for your website.
If left uprotected, the YusASP allows you to anage the remote server's
web folder structure, upload and download files, etc.";

# YusASP Web Asset Manager Vulnerability
# "eric basher" <basher13@linuxmail.org>
# 2005-05-04 12:23

if(description)
{
 script_id(18192);
 script_version("$Revision: 17 $");
 script_bugtraq_id(13501);
 script_cve_id("CVE-2005-1668");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 
 name = "YusASP Web Asset Manager Vulnerability";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for the presence of a YusASP Web Asset vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get (item: string(loc, "/editor/assetmanager/assetmanager.asp"), port: port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:'input type="hidden" name="inpAssetBaseFolder', string:r))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

