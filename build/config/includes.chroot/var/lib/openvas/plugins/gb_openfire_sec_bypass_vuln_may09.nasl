##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openfire_sec_bypass_vuln_may09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Openfire Security Bypass Vulnerabilities (May09)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Openfire 3.6.4 or later
  http://www.igniterealtime.org/projects/openfire

  *****
  Note: Vulnerability is related to CVE-2009-1595 and CVE-2009-1596
  *****";

tag_impact = "Successful exploitation will let the attacker change the passwords of
  arbitrary accounts via a modified username element in a passwd_change
  action or can bypass intended policy and change their own passwords via
  a passwd_change IQ packet.
  Impact Level: Application/Network
  Impact Level: Application/Network";
tag_affected = "Openfire prior to 3.6.4";

desc1 = "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


desc2 = "
  Impact:
  Successful exploitation will let the attacker bypass intended policy
  and change their own passwords via a passwd_change IQ packet.

  Affected Software/OS:
  Openfire prior to 3.6.5

  Fix:
  Upgrade to Openfire 3.6.5.
  http://www.igniterealtime.org/projects/openfire

  *****
  Note: Vulnerability is related to CVE-2009-1596
  *****";


if(description)
{
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34976");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34984");
  script_xref(name : "URL" , value : "http://www.igniterealtime.org/issues/browse/JM-1532");
  script_xref(name : "URL" , value : "http://www.igniterealtime.org/issues/browse/JM-1531");
  script_id(800718);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1595");
 script_bugtraq_id(34804);
  script_name("Openfire Security Bypass Vulnerabilities");
  script_description(desc2);
  script_summary("Check for the version of Openfire");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_detect.nasl");
  script_require_ports("Services/www", 9090);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34984");
  script_xref(name : "URL" , value : "http://www.igniterealtime.org/issues/browse/JM-1532");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

report = string("\n  Overview: This host is running Openfire, which is prone" +
                " to security bypass\n  vulnerability.\n\n" +
                "  Vulnerability Insight:\n");
 vuln1 = string("  - Error exists in 'jabber:iq:auth' implementation in" +
                " IQAuthHandler.java\n    File via a modified username " +
                "element in a passwd_change action.\n");
 vuln2 = string("  - Error due to improper implementation of 'register" +
                ".password' console\n    configuration settings via a " +
                "passwd_change IQ packet.\n");

openfirePort = get_http_port(default:9090);
if(!openfirePort){
  exit(0);
}

openfireVer = get_kb_item("www/" + openfirePort + "/Openfire");
if(openfireVer != NULL)
{
  # Grep for Openfire version prior to 3.6.4
  if(version_is_less(version:openfireVer, test_version:"3.6.4"))
  {
    security_warning(data:string(report, vuln1, desc1),
                     port:openfirePort);
  }

  # Grep for Openfire version 3.6.4
  else if(version_is_equal(version:openfireVer, test_version:"3.6.4"))
  {
    security_warning(data:string(report, vuln2, desc2),
    port:openfirePort);
  }
}
