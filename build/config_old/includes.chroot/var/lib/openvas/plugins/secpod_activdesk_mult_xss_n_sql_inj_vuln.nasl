###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_activdesk_mult_xss_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ActivDesk Multiple Cross Site Scripting and SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation allow an attacker to steal cookie-based authentication
  credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "ActivDesk version 3.0 and prior.";
tag_insight = "Multiple flaws are due to
  - Improper validation of user-supplied input passed to the 'keywords0',
    'keywords1', 'keywords2' and 'keywords3' parameters in search.cgi,
    which allows attackers to execute arbitrary HTML and script code on
    the web server.
  - Improper validation of user-supplied input passed to the 'cid' parameter
    in kbcat.cgi and the 'kid' parameter in kb.cgi, which allows attacker to
    manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to ActivDesk version 3.0.1 or later,
  For updates refer to http://www.webhelpdesk-software.com/download.html";
tag_summary = "This host is running ActivDesk and is prone to multiple cross site
  scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(902530);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_bugtraq_id(46937);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("ActivDesk Multiple Cross Site Scripting and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45057/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17443/");
  script_xref(name : "URL" , value : "http://itsecuritysolutions.org/2011-06-24-ActivDesk-3.0-multiple-security-vulnerabilities/");

  script_description(desc);
  script_summary("Determine ActivDesk Cross Site Scripting and SQL Injection Vulnerabilities");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/adesk", "/support", "/hdesk", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir, "/login.cgi"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if("<title>Support</title>" >< res)
  {
    ## Construct attack requests
    url = dir + "/search.cgi?keywords0=<script>alert(document.cookie)</script>";

    ## Try Exploit and check the response to confirm vulnerability
    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document.cookie\)</script>"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
