##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_omnistar_dms_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Omnistar Document Manager Software Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to compromise dbms via
  sql injection or information disclosure via local system file include and
  hijack administrator/moderator/customer sessions via persistent malicious
  script code inject on application side
  Impact Level: Application";
tag_affected = "Omnistar Document Manager Version 8.0 and prior";

tag_insight = "- Multiple sql bugs are located in index.php file with the bound vulnerable
    report_id, delete_id, add_id, return_to, interface, page and sort_order
    parameter requests.
  - The LFI bug is located in the index module with the bound vulnerable 'area'
    parameter request.
  - Multiple non stored XSS bugs are located in the interface exception-handling
    module of the application with the client side  bound vulnerable interface,
    act, name and alert_msg parameter requests.";
tag_solution = "No solution or patch is available as of 11th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.omnistardrive.com";
tag_summary = "This host is running Omnistar Document Manager Software and is
  prone multiple SQL vulnerabilities.";

if(description)
{
  script_id(802467);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-11 13:29:47 +0530 (Thu, 11 Oct 2012)");
  script_name("Omnistar Document Manager Software Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Oct/65");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/524380");

  script_description(desc);
  script_summary("Check the XSS vulnerability in Omnistar Document Manager");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 443);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("openvas-https.inc");

## Variable Initialization
req = "";
res = "";
host = "";
url = "";
port = "";

## Get Port
port = get_http_port(default:443);
if(!port){
  port = 443;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Check for PHP supports
if(!can_host_php(port:port)){
 exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

foreach dir (make_list("", "/dm", "/dms"))
{
  ## Construct https request
  req = string("GET ", dir, "/index.php HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n");
  res = https_req_get(port:port, request:req);

  ## Confirm the application before trying exploit
  if(res && ">Document Management Software<" >< res)
  {
    ## Construct the XSS attack request
    url = dir + "/index.php?interface=><script>alert(document.cookie)"+
                ";</script>";

    req = string("GET ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n\r\n");
    res = https_req_get(port:port, request:req);

    ## Confirm exploit worked by checking the response
    if(res && "><script>alert(document.cookie);</script>" >< res &&
       ">Interface Name:<" >< res){
      security_hole(port);
    }
  }
}
