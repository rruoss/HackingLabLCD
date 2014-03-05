###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rlogin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Check rlogin Service Running
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_insight = "rlogin has several serious security problems,
  - All information, including passwords, is transmitted unencrypted.
  - .rlogin (or .rhosts) file is easy to misuse (potentially allowing
    anyone to login without a password)

  Impact Level: System";
tag_solution = "Disable rlogin service and use ssh instead.";
tag_summary = "This remote host is running rlogin service.";

if(description)
{
  script_id(901202);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)");
  script_cve_id("CVE-1999-0651");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Check rlogin Service Running");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/Rlogin");
  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc1282.txt");

  script_description(desc);
  script_summary("Check for rlogin Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("find_service.nasl");
  script_family("Useless services");
  script_require_ports(513);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

include("misc_func.inc");

## Check is it a rlogin service
port = get_kb_item("Services/unknown");
if(!port){
  ## Default rlogin port
  port = 513;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

nullStr = raw_string(0x00);

## Client user name : Server user name : Terminal Type / Terminal Speed
req1 = "root" + nullStr + "root" + nullStr + "vt100/9600" + nullStr;
soc = open_priv_sock_tcp(dport:port);
if(!soc){
  exit();
}

## Send Client Start-up flag
send(socket:soc, data:nullStr);

## Rlogin user info
send(socket:soc, data:req1);

## Receive startup info flag
res1 = recv(socket:soc, length:1);

## Receive data
res2 = recv(socket:soc, length:1024);

## Confirm rlogin by checking response
if(res1 == nullStr && "Password:" >< res2)
{
  security_hole(port);
  set_kb_item(name:"rlogin/active", value:TRUE);
  register_service(port: port, proto: "rlogin");
}
