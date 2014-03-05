###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_tomcat_priv_esc_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apache Tomcat Windows Installer Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Apply patch from below link,
  http://svn.apache.org/viewvc?view=revision&revision=834047

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful attempt could lead remote attackers to bypass security restrictions
  and gain the privileges.
  Impact Level: Application.";
tag_affected = "Apache Tomcat version 5.5.0 to 5.5.28 and 6.0.0 through 6.0.20 on Windows.";
tag_insight = "The flaw is due to the windows installer setting a blank password by default
  for the administrative user, which could be exploited by attackers to gain
  unauthorized administrative access to a vulnerable installation.";
tag_summary = "Apache Tomcat Server is running on this host and that is prone to
  Privilege Escalation vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901050";
CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3548");
  script_bugtraq_id(36954);
  script_name("Apache Tomcat Windows Installer Privilege Escalation Vulnerability");
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

  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3185");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Nov/1023146.html");

  script_description(desc);
  script_summary("Check for the version of Apache Tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("ApacheTomcat/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("version_func.inc");

if (host_runs("windows") != "yes")exit(0);

if(!tomPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!tomcatVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:tomPort))exit(0);

# Check Tomcat version < 5.5.28, or < 6.0.20
if(version_in_range(version:tomcatVer, test_version:"5.5.0", test_version2:"5.5.28")||
   version_in_range(version:tomcatVer, test_version:"6.0.0", test_version2:"6.0.20")){
  security_hole(tomPort);
}
