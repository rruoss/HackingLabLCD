##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagull_sql_injection_n_mult_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Seagull SQL Injection and Multiple Remote File Inclusion Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on
  the vulnerable Web server and to execute arbitrary SQL commands.
  Impact Level: Application.";
tag_affected = "Seagull version 0.6.7";

tag_insight = "Multiple flaws are due to:
  - An error in the 'Config/Container.php', which is not properly validating the
    input passed to 'includeFile' parameter.
  - An error in the 'fog/lib/pear/HTML/QuickForm.php', which is not properly
    validating the input passed to 'includeFile' parameter.
  - An error in the 'fog/lib/pear/DB/NestedSet.php', which is not properly
    validating the input passed to 'driverpath' parameter.
  - An error in the 'fog/lib/pear/DB/NestedSet/Output.php', which is not properly
    validating the input passed to 'path' parameter.
  - An SQL injection error in 'index.php', which allows remote attackers to
    execute arbitrary SQL commands via the frmQuestion parameter in a retrieve
    action, in conjunction with a user/password PATH_INFO.";
tag_solution = "No solution or patch is available as of 8th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://seagullproject.org/download/";
tag_summary = "This host is running Seagull and is prone to SQL injection and
  multiple remote file inclusion vulnerabilities.";

if(description)
{
  script_id(801513);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-3209", "CVE-2010-3212");
  script_name("Seagull SQL Injection and Multiple Remote File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41169");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14838/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1008-exploits/seagull-rfi.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1008-exploits/seagull-sql.txt");

  script_description(desc);
  script_summary("Check for SQL attack on Seagull");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("version_func.inc");

## Get HTTP port
sglPort = get_http_port(default:80);
if(!sglPort){
  exit(0);
}

foreach dir (make_list("/seagull/www", "/Seagull", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir , "/index.php"), port:sglPort);
  rcvRes = http_send_recv(port:sglPort, data:sndReq);

  ## Confirm application Seagull
  if("<title>Seagull Framework :: Home<" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/index.php/user/password/?action=" +
                                 "retrieve&frmEmail=111-222-1933email@add" +
                                 "ress.tst&frmQuestion=1'[SQLI]&frmAnswer" +
                                 "=111-222-1933email@address.tst&submitte" +
                                  "d=retrieve"),  port:sglPort);
    rcvRes = http_send_recv(port:sglPort, data:sndReq);

     ## Confirm exploit worked by checking the response
    if('this->whereAdd' >< rcvRes && 'Object of class DB_' >< rcvRes)
    {
      security_hole(sglPort);
      exit(0);
    }
  }
}
