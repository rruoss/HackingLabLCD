# OpenVAS Vulnerability Test
# $Id: sip_detection.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Detect SIP Compatible Hosts
#
# Authors:
# Noam Rathaus
# Modified by Michael Meyer 2009-05-04
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
tag_summary = "A Voice Over IP service is listening on the remote port.

Description :

The remote host is running SIP (Session Initiation Protocol), a protocol
used for Internet conferencing and telephony.

Make sure the use of this program is done in accordance with your corporate
security policy.";

tag_solution = "If this service is not needed, disable it or filter incoming traffic
to this port.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(11963);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Detect SIP Compatible Hosts";
 script_name(name);

 script_description(desc);

 summary = "SIP Detection";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
 script_family("Service detection");
 script_require_udp_ports(5060);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.cs.columbia.edu/sip/");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

sip_installed = FALSE;

ports = make_list(5060, 5061, 5070);

foreach port (ports) {

  if (!get_udp_port_state(port))continue;

  if (islocalhost()) {
        soc = open_sock_udp(port);
  }	
  else {
        soc = open_priv_sock_udp(sport:5060, dport:port);
  }

  if(!soc)continue;

  sndReq = string(
            "OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
            "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
            "To: User <sip:user", get_host_name(), ":", port, ">\r\n",
            "From: OpenVAS <sip:openvas@", this_host(), ":", port, ">\r\n",
            "Call-ID: ", rand(), "\r\n",
            "CSeq: ", rand(), " OPTIONS\r\n",
            "Contact: OpenVAS <sip:openvas@", this_host(), ">\r\n",
            "Max-Forwards: 10\r\n",
            "Accept: application/sdp\r\n",
            "Content-Length: 0\r\n\r\n");

  send(socket:soc, data:sndReq);
  data = recv(socket:soc, length:1024);
  close(soc);
 
  if("SIP/2.0" >!< data)continue;

  if (egrep(pattern: '^Server:', string: data))
  {
   banner = egrep(pattern: '^Server:', string: data);
   banner -= "Server: ";
   banner -= string("\r\n");
  }

  else if (egrep(pattern: '^User-Agent:', string: data)) {

    banner = egrep(pattern: '^User-Agent:', string: data);
    banner -= "User-Agent: ";
    banner -= string("\r\n");

  }

  if( banner ) {
   if(!get_kb_item("sip/banner/5060"))
   {
    set_kb_item(name:"sip/banner/5060", value:banner);
   }
  }

  desc += '\n\nPlugin output :\n\n' + banner + '\n';

  if(egrep(pattern:"Allow:.*OPTIONS.*", string: data)) {

    OPTIONS = egrep(pattern:"Allow:.*OPTIONS.*", string: data);
    OPTIONS -= "Allow: ";
    OPTIONS = chomp(OPTIONS);
  }

  if(!isnull(OPTIONS)) {

    desc += '\nSupported Options:\n' + OPTIONS + '\n';

  }

  log_message(port:5060, protocol:"udp", data:desc);
  register_service(port: 5060, ipproto: "udp", proto: "sip");

}  

