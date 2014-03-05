###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_upnp_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# UPnPd Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "Detection of the UPnP protocol.

The script sends a UPnP discovery request and attempts to
determine if the remote host supports the UPnP protocol";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103652";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-01 09:39:54 +0100 (Fri, 01 Feb 2013)");
 script_name("MiniUPnPd Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Checks for the presence of UPnP");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_udp_ports(1900);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

port = 1900;

if(islocalhost())exit(0);
if(TARGET_IS_IPV6())exit(0);
if(!get_udp_port_state(1900))exit(0);

soc = open_sock_udp(port);
if(!soc)exit(0);

src = this_host();
dst = get_host_ip();
sport = (rand() % 64511) + 1024;

req = string("M-SEARCH * HTTP/1.1\r\n",
             "HOST: 239.255.255.250:1900\r\n",
             'MAN: "ssdp:discover"',"\r\n",
             "MX: 10\r\n",
             "ST: ssdp:all\r\n\r\n");

len = strlen(req) + 8;

ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_tos:0, ip_len:20, ip_id: rand(), ip_off:0, ip_ttl:64, ip_p:IPPROTO_UDP, ip_src:src);
udp = forge_udp_packet(ip:ip, uh_sport:sport, uh_dport:1900, uh_ulen:len, data:req);

filter = "udp and src " + dst + " and dst " + src + " and dst port " + sport;

attempt = 2;
ret = FALSE;

while (!ret && attempt--) {

  ret = send_packet(udp, pcap_active:TRUE, pcap_filter:filter);
  len = strlen(ret);

  if (len > 28)  {
    x = ord(ret[0]);
    if ((x & 0xF0) == 0x40)
    {
      x = (x & 0xF) * 4;
      if (x + 8 < len)
        result = substr(ret, x + 8);
    }
  }
}

if(result && "HTTP/" >< result) {

  server = egrep(pattern:"Server: ", string:result, icase:TRUE);
  if(server) {
    set_kb_item(name:"upnp/server", value:server);
  } 
   
  register_service(port: 1900, ipproto: "udp", proto: "upnp");
  log_message(data:'The remote Host supports the UPnP protocol. You should restrict access\n' +
                   'to port 1900/udp. The remote Host answers the following to a SSDP M-SEARCH request\n\n' + result + '\n'
                    ,port:port, proto:"udp");

  exit(0);

}

exit(0);
