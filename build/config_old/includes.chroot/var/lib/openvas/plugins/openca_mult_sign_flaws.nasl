# OpenVAS Vulnerability Test
# $Id: openca_mult_sign_flaws.nasl 17 2013-10-27 14:01:43Z jan $
# Description: OpenCA multiple signature validation bypass
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote host seems to be running an older version of OpenCA. 

It is reported that OpenCA versions up to and incluing 0.9.1.3 contains 
multiple flaws that may allow revoked or expired certificates to be accepted as valid.";

tag_solution = "Upgrade to the newest version of this software";

# Ref: Chris Covell and Gottfried Scheckenbach

if (description) {
  script_id(14714);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9123);
  script_cve_id("CVE-2003-0960");
  script_xref(name:"OSVDB", value:"2884");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  name = "OpenCA multiple signature validation bypass";
  script_name(name);
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

  script_description(desc);
 
  summary = "Checks for the version of OpenCA";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("openca_html_injection.nasl");
  script_require_ports("Services/www", 80);

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

version = get_kb_item("www/" + port + "/openca/version");
if ( ! version ) exit(0);


if ( egrep(pattern:"(0\.[0-8]\.|0\.9\.(0|1$|1\.[1-3][^0-9]))", string:version) ) security_hole(port);

