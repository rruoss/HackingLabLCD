###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_smime_openssl_crypto_weakness.nasl 11 2013-10-27 10:12:02Z jan $
#
# OTRS S/MIME OpenSSL Cryptographic Entropy Weakness
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803933";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2008-7278");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-20 17:07:00 +0530 (Fri, 20 Sep 2013)");
  script_name("OTRS S/MIME OpenSSL Cryptographic Entropy Weakness");

tag_summary =
"This host is installed with OTRS (Open Ticket Request System) and is prone to
cryptographic entropy weakness.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight ="An error exists in S/MIME feature which does not properly configure
the RANDFILE environment variable for OpenSSL";

tag_impact =
"Successful exploitation will allow remote attackers to decrypt e-mail messages
that had lower than intended entropy available for cryptographic operations.

Impact Level: Application";

tag_affected =
"OTRS (Open Ticket Request System) version before 2.2.5, and 2.3.x
before 2.3.0-beta1";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) version 2.2.5, or 2.3.0-beta1
or later, For updates refer to http://www.otrs.com/en/";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/74261");
  script_summary("Determine if the OTRS version is less than 2.2.5");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialisation
port = "";
vers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  if(version_is_less(version: vers, test_version: "2.2.5"))
  {
      security_warning(port:port);
      exit(0);
  }

}
