###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_searchblox_mult_vuln_sept13.nasl 11 2013-10-27 10:12:02Z jan $
#
# SearchBlox Multiple Vulnerabilities Sept-13
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

if(description)
{
  script_id(802060);
  script_version("$Revision: 11 $");
  script_bugtraq_id(61973, 61974, 61975);
  script_cve_id("CVE-2013-3598", "CVE-2013-3597", "CVE-2013-3590");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-03 10:46:51 +0530 (Tue, 03 Sep 2013)");
  script_name("SearchBlox Multiple Vulnerabilities Sept-13");

  tag_summary =
"This host is running SearchBlox and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to
get confidential information.";

  tag_insight =
"Multiple flaws are due to,
- Input passed via 'name' parameter to 'servlet/CreateTemplateServlet' not
  properly sanitised before being used to create files.
- Error when accessing 'servlet/CollectionListServlet' servlet when 'action'
  is set to 'getList' can be exploited to disclose usernames and passwords
  from the database.
- 'admin/uploadImage.html' script allows to upload an executable file with the
  image/jpeg content type and it can be exploited to execute arbitrary JSP
  code by uploading a malicious JSP script.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary JSP code or
obtain potentially sensitive information or can overwrite arbitrary files
via directory traversal sequences.

Impact Level: Application";

  tag_affected =
"SearchBlox before 7.5 build 1";

  tag_solution =
"Upgrade to SearchBlox version 7.5 build 1 or later,
For updates refer to http://www.searchblox.com";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/96619");
  script_xref(name : "URL" , value : "http://osvdb.org/96620");
  script_xref(name : "URL" , value : "http://osvdb.org/96621");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54629");
  script_xref(name : "URL" , value : "http://www.searchblox.com/developers-2/change-log");
  script_summary("Check if SearchBlox is Information Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 8080;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

foreach dir (make_list("", "/search", "/searchblox", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/searchblox/search.html"),  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if( 'action="servlet/SearchServlet"' >< res &&
      'id="searchPageCollectionList"' >< res )
  {
    url = dir + '/searchblox/servlet/CollectionListServlet?action=getList' +
                '&orderBy=colName&direction=asc';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                       pattern:"scanner-auth-password",
                       extra_check: make_list("rootURLStr1",
                       'scanner-user-agent":"SearchBlox')))
    {
      security_hole(http_port);
      exit(0);
    }
  }
}
