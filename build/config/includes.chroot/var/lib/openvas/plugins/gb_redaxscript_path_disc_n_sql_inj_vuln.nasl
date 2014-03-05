##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redaxscript_path_disc_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Redaxscript Path Disclosure and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  queries to the database, compromise the application, access or modify
  sensitive data, or exploit various vulnerabilities in the underlying
  SQL database.
  Impact Level: Application.";
tag_affected = "Redaxscript version 0.3.2a";

tag_insight = "The flaws are due to
  - Error in the '/templates/default/index.php', which reveals the full path
    of the script.
  - Input passed to the 'id' and 'password' parameters in '/includes/password.php'
    is not properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 4th February 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://redaxscript.com/download";
tag_summary = "This host is running Vaadin is prone to path disclosure and SQL
  injection vulnerabilities.";

if(description)
{
  script_id(801733);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(46089);
  script_name("Redaxscript Path Disclosure and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16096/");
  script_xref(name : "URL" , value : "http://securityreason.com/exploitalert/9918");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/sql_injection_in_redaxscript.html");

  script_description(desc);
  script_summary("Check if Redaxscript is vulnerable to Path Disclosure and SQL Injection attacks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

redPort = get_http_port(default:80);
if(!redPort){
  redPort = 80;
}

foreach dir (make_list("/redaxscript", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:redPort);
  rcvRes = http_send_recv(port:redPort, data:sndReq);

  ## Confirm application Redaxscript
  if(">Redaxscript" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/templates/default/index.php"), port:redPort);
    rcvRes = http_keepalive_send_recv(port:redPort, data:sndReq);

    ## Check the response to confirm vulnerability
    if(">Fatal error<" >< rcvRes && "Call to undefined function" >< rcvRes)
    {
      security_hole(redPort);
      exit(0);
    }
  }
}
