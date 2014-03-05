###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oraclejsp_demos_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# OracleJSP Demos Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary scripts
  or actions written by an attacker. In addition, an attacker may obtain
  authorization cookies that would allow him to gain unauthorized access to
  the application.
  Impact Level: Application";
tag_affected = "OracleJSP Demos version 1.1.2.4.0 with iAS v1.0.2.2";
tag_insight = "The flaws are due to failure in the,
  - '/demo/sql/index.jsp' script to properly sanitize user supplied input in
    'connStr' parameter.
  - '/demo/basic/hellouser/hellouser.jsp' script to properly sanitize
    user-supplied input in 'newName' parameter.
  - '/demo/basic/hellouser/hellouser_jml.jsp' script to properly sanitize
    user-supplied input in 'newName' parameter.
  - '/demo/basic/simple/welcomeuser.jsp' script to properly sanitize
    user-supplied input in 'user' parameter.
  - '/demo/basic/simple/usebean.jsp?' script to properly sanitize
    user-supplied input in 'newName' parameter.";
tag_solution = "Apply the patch from below link,
  http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html";
tag_summary = "This host is running OracleJSP Demos and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(902412);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("OracleJSP Demos Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.gossamer-threads.com/lists/fulldisc/full-disclosure/79673");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100650/cybsecoraclejsp-xss.txt");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html");

  script_description(desc);
  script_summary("Check if OracleJSP Demos is vulnerable to XSS");
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

## Get OracleJSP Demo  Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## check for each possible path
foreach dir (make_list("/ojspdemos", "/OracleJSP", "/OracleJSPDemos", "/"))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.html"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('OracleJSP Demo</' >< res && "Oracle Corporation" >< res)
  {
     req = http_get(item:string(dir, '/sql/index.jsp?connStr="><script>' +
                        'alert("XSS-TEST")</script>'), port:port);

     res = http_keepalive_send_recv(port:port, data:req);

     ## Confirm exploit worked by checking the response
     if('><script>alert("XSS-TEST")</script>' >< res)
     {
       security_warning(port);
       exit(0);
     }
  }
}
