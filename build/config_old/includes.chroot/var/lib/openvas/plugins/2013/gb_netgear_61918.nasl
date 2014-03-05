###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_61918.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple NetGear ProSafe Switches Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "An attacker can exploit this issue to download configuration file and
disclose sensitive information. Information obtained may aid in
further attacks.
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103773";

tag_insight = "The web management application fails to restrict URL access to differenti
application areas. Remote, unauthenticated attackers could exploit this issue to
download the device's startup-config, which contains administrator credentials in
encrypted form.";


tag_affected = "GS724Tv3 and GS716Tv2 - firmware 5.4.1.13
GS724Tv3 and GS716Tv2 - firmware 5.4.1.10
GS748Tv4              - firmware 5.4.1.14
GS510TP               - firmware 5.4.0.6
GS752TPS and GS728TPS - firmware 5.3.0.17
GS728TS and GS725TS   - firmware 5.3.0.17
GS752TXS and GS728TXS - firmware 6.1.0.12";

tag_summary = "Multiple NetGear ProSafe switches are prone to an information-
disclosure vulnerability.";

tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Try to read /filesystem/startup-config with a HTTP GET request and check the response.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(61918);
 script_cve_id("CVE-2013-4775","CVE-2013-4776");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 11 $");

 script_name("Multiple NetGear ProSafe Switches  Information Disclosure Vulnerability");

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

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61918");
 script_xref(name:"URL", value:"http://www.netgear.com");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-22 12:52:30 +0200 (Thu, 22 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to access /filesystem/startup-config");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = "/";

if(http_vuln_check(port:port, url:url,pattern:"<TITLE>NETGEAR")) {

  url = '/filesystem/startup-config';

  if(http_vuln_check(port:port, url:url,pattern:"Current Configuration", extra_check:make_list("System Description","System Software Version","network parms"))) {
    security_hole(port:port);
    exit(0);
  }  

  exit(99);

}  

exit(0);


   
