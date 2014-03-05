###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_mult_sec_bypass_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Tomcat Multiple Security Bypass Vulnerabilities (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_solution = "Apply patch or upgrade Apache Tomcat to 5.5.36, 6.0.36, 7.0.30 or later,
  For updates refer to http://tomcat.apache.org/

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to bypass intended
  access restrictions by sniffing the network for valid requests.
  Impact Level: Application";
tag_affected = "Apache Tomcat version 5.5.x to 5.5.35, 6.x to 6.0.35 and 7.x to 7.0.29";
tag_insight = "The flaws are due to error in HTTP digest access authentication
  implementation, which does not properly validate for,
  - stale nonce values in conjunction with enforcement of proper credentials
  - caches information about the authenticated user within the session state
  - cnonce values instead of nonce and nc values.";
tag_summary = "The host is running Apache Tomcat Server and is prone to multiple
  security bypass vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802678";
CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5887", "CVE-2012-5886", "CVE-2012-5885");
  script_bugtraq_id(56403);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-27 16:27:51 +0530 (Tue, 27 Nov 2012)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Apache Tomcat Multiple Security Bypass Vulnerabilities (Windows)");
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
  script_summary("Check for the version of Apache Tomcat on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("ApacheTomcat/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51138/");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.36");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.36");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.30");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1377807");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1380829");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1392248");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

# variable initialization
tomport = 0;
tomvers = "";

## Exit if its not windows
if(host_runs("Windows") != "yes")exit(0);

# get the port
if(!tomport = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

# check the port state
if(!get_port_state(tomport))exit(0);

# get the version
if(!tomvers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:tomport))exit(0);

# check the version for 5.5 < 5.5.36, 6.0 < 6.0.36 and 7.0 < 7.0.30
if(!isnull(tomvers) && tomvers >!< "unknown" &&
   (version_in_range(version:tomvers, test_version:"5.5", test_version2:"5.5.35")||
    version_in_range(version:tomvers, test_version:"6.0", test_version2:"6.0.35")||
    version_in_range(version:tomvers, test_version:"7.0", test_version2:"7.0.29")))
{
  security_warning(port:tomport);
  exit(0);
}