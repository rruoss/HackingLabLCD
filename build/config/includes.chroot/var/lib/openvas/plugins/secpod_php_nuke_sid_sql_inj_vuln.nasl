###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_nuke_sid_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP-Nuke 'sid' Parameter SQL Injection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to add, modify or delete data
  in the back end database.
  Impact Level: Application";
tag_affected = "PHP-Nuke versions 5.6, 6.0, 6.5 RC1, 6.5 RC2, 6.5 RC3, 6.5";
tag_insight = "The flaw is caused by input validation errors in the 'article.php' when
  processing user-supplied data in 'sid' parameter, which could be exploited
  by attackers to execute SQL code.";
tag_solution = "No solution or patch is available as of 22th July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://phpnuke.org";
tag_summary = "The host is running PHP-Nuke and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902612);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-27 09:16:39 +0200 (Wed, 27 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP-Nuke 'sid' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16550");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/11599");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/vulnwatch/2003-q1/0147.html");

  script_description(desc);
  script_summary("Determine if PHP-Nuke is prone to SQL injection vulnerability");
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

foreach dir (make_list("/nuke", "/nuke/html", "/html", "/", cgi_dirs()))
{
   ##Request to confirm application
   req = string("GET " , dir , "/index.php HTTP/1.1\r\n",
                "Host: " , get_host_ip() , " \r\n\r\n");
   res = http_keepalive_send_recv(port:port, data:req);

   if(res == NULL)
   {
      sndReq = http_get(item:string(dir, "/admin.php"), port:port);
      res = http_keepalive_send_recv(port:port, data:sndReq);
      if(res == NULL){
      exit(0);
      }
   }

  if("PHP-Nuke" >< res)
  {
     ## Construct attack request
     req = string("GET " , dir , "/article.php?sid=sid=24%27 HTTP/1.1\r\n",
                  "Host: " , get_host_ip(), " \r\n\r\n");
     res = http_keepalive_send_recv(port:port, data:req);

     if(res)
     {
        if("mysql_fetch_row()" >< res && "MySQL result" >< res)
        {
          security_hole(port);
          exit(0);
        }
     }
  }
}
