##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_omnistar_mailer_mult_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Omnistar Mailer Software Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to view, add, modify or
  delete information in the back-end database and compromise the application.
  Impact Level: Application";
tag_affected = "Omnistar Mailer Version 7.2 and prior";

tag_insight = "The flaw caused by improper validation of bound vulnerable 'id' and 'form_id'
  parameters in responder, preview, pages, navlinks, contacts, register and
  index modules.";
tag_solution = "No solution or patch is available as of 04th October, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.omnistarmailer.com/";
tag_summary = "This host is running Omnistar Mailer Softwar and is prone multiple
  SQL injection vulnerabilities.";

if(description)
{
  script_id(802464);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-04 10:42:09 +0530 (Thu, 04 Oct 2012)");
  script_name("Omnistar Mailer Software Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21716/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Oct/27");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/524301/30/0/threaded");

  script_description(desc);
  script_summary("Check the SQL injection vulnerability in Omnistar Mailer Software");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

port = "";
dir = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Check for PHP support
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/mailer", "/mailertest", "", cgi_dirs()))
{
  ## Send and Receive request
  sndReq = http_get(item:string(dir, "/admin/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm application
  if("<title>OmniStar" >< rcvRes && ">Email Marketing Software<" >< rcvRes )
  {
    url = string(dir,"/users/register.php?nav_id='");

    ## Try exploit and check response to confirm vulnerability
    if(http_vuln_check(port:port,url:url,pattern:">SQL error.*error in your" +
       " SQL syntax;", check_header:TRUE, extra_check:make_list("register.php ",
       "return smtp_validation")))
    {
      security_hole(port);
      exit(0);
    }
  }
}
