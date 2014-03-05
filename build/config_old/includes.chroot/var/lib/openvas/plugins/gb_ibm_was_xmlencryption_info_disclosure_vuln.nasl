###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_xmlencryption_info_disclosure_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server WS-Security XML Encryption Weakness Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "For WebSphere Application Server 6.1:
  Apply the latest Fix Pack (6.1.0.39 or later) or APAR PM34841.

  For WebSphere Application Server 7.0:
  Apply the latest Fix Pack (7.0.0.17 or later) or APAR PM34841.
  http://www-01.ibm.com/support/docview.wss?uid=swg21474220

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will let remote attackers to obtain plaintext data
  from a JAX-RPC or JAX-WS Web Services.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 6.1 before 6.1.0.39 and
  7.0 before 7.0.0.17";
tag_insight = "The flaw is caused by a weak encryption algorithm being used by WS-Security
  to encrypt data exchanged via a Web Service (JAX-WS or JAX-RPC), which could
  allow attackers to decrypt the encrypted data contained in web requests.";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_id(801888);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-1209");
  script_bugtraq_id(47831);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM WebSphere Application Server WS-Security XML Encryption Weakness Vulnerability");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/67115");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1084");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg24029632");

  script_description(desc);
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Get Version from KB
vers = get_kb_item(string("www/", port, "/websphere_application_server"));
if(isnull(vers)){
  exit(0);
}

## Check for IBM WebSphere Application Server versions
if(version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.37") ||
   version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.0.15")) {
  security_warning(port:port);
}
