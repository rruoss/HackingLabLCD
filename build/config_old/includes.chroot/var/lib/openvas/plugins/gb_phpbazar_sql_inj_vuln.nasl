###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpbazar_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpBazar 'classified.php' SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow execution of arbitrary SQL commands in
  the affected application.
  Impact Level: Application";
tag_affected = "phpBazar version 2.1.1 and prior.";
tag_insight = "The flaw is due to error in 'classified.php' which can be exploited to cause
  SQL injection via the 'catid' parameter, and 'admin/admin.php' which allows to
  obtain access to the admin control panel via a direct request.";
tag_solution = "No solution or patch is available as of 17th February, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.smartisoft.com/";
tag_summary = "The host is running phpBazar and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(800465);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4221", "CVE-2009-4222");
  script_bugtraq_id(37144,37132);
  script_name("phpBazar 'classified.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54447");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10245");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0911-exploits/phpbazar211fix-sql.txt");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check through the attack string and version of phpBazar");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_phpbazar_detect.nasl");
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

pbport = get_http_port(default:80);
if(!pbport){
  exit(0);
}

pbver = get_kb_item("www/" + pbport + "/phpBazar");
if(isnull(pbver)){
  exit(0);
}

pbver = eregmatch(pattern:"^(.+) under (/.*)$", string:pbver);
if(!isnull(pbver[2]) && !safe_checks())
{
  url = string(pbver[2], "/classified.php?catid=2+and+1=0+union+all" +
                               "+select+1,2,3,4,5,6,7--");
  sndReq = http_get(item:url, port:pbport);
  rcvRes = http_send_recv(port:pbport, data:sndReq);

  if("2 and 1=0 union all select 1,2,3,4,5,6,7--&subcatid=1" >< rcvRes)
  {
    security_hole(pbport);
    exit(0);
  }
  else
  {
    sndReq = http_get(item:string(pbver[2], "/admin/admin.php"), port:pbport);
    rcvRes = http_send_recv(port:pbport, data:sndReq);
    if("phpBazar-AdminPanel" >< rcvRes)
    {
      security_hole(pbport);
      exit(0);
    }
  }
}

if(!isnull(pbver[1]))
{
  # phpBazar version 2.1.1(2.1.0)
  if(version_is_less_equal(version:pbver[1], test_version:"2.1.0")){
    security_hole(pbport);
  }
}
