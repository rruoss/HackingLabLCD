# OpenVAS Vulnerability Test
# $Id: qmtp_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: QMTP
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "For your information, a QMTP/QMQP server is running on this port.
QMTP is a proposed replacement of SMTP by D.J. Bernstein.

** Note that OpenVAS only runs SMTP tests currently.";

if(description)
{
  script_id(11134);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("QMTP");
 
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
 
  summary = "Detect QMTP servers";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports(209, 628);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

####

include("global_settings.inc");
include("misc_func.inc");
include("network_func.inc");

ports = get_kb_list("Services/QMTP");
if (! ports) ports = make_list(209, 628);
ports = make_list(209, 628);

function netstr(str)
{
  local_var	l;

  l = strlen(str);
  return strcat(l, ":", str, ",");
}

foreach port (ports)
  if (service_is_unknown(port: port) && get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if (soc)
    {
      msg = strcat(netstr(str: "
Message-ID: <1234567890.666.openvas@example.org>
From: openvas@example.org
To: postmaster@example.com

OpenVAS is probing this server.
"), 
		netstr(str: "openvas@example.org"),
		netstr(str: netstr(str: "postmaster@example.com")));
      # QMQP encodes the whole message once more
      if (port == 628)
      {
         msg = netstr(str: msg);
         srv = "QMQP";
      }
      else
        srv = "QMTP";

send(socket: soc, data: msg);
r = recv(socket: soc, length: 1024);
close(soc);

if (ereg(pattern: "^[1-9][0-9]*:[KZD]", string: r))
{
  security_note(port);
  register_service(port: port, proto: srv);
}

      if (ereg(pattern: "^[1-9][0-9]*:K", string: r))
      {
        # K: Message accepted for delivery
        # Z: temporary failure
        # D: permanent failure
        if (is_private_addr(addr: get_host_ip()) ||
            is_private_addr(addr: this_host()) )
          security_warning(port: port, data: 
"The " + srv + " server accepts relaying. 
Make sure it rejects connections from Internet so that spammers cannot use
it as an open relay");
        else
          security_hole(port: port, data: 
"The "+ srv + " server accepts relaying on or from Internet. 
Spammers can use it as an open relay.

Risk : High");
      }

    }
  }
