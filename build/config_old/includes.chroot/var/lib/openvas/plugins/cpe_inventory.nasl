###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# CPE Inventory
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
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
tag_summary = "CPE Inventory

This NVT uses information present in the Knowledge Base (KB) to
determine CPE identities (http://cpe.mitre.org/) of operating
systems, services and applications detected during the scan.";

if(description)
{
  script_id(810002);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-11-18 11:43:05 +0100 (Wed, 18 Nov 2009)");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CPE Inventory");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("CPE Inventory");
  script_category(ACT_END);
  script_copyright("Copyright (c) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("host_details.inc");


translate_to_cpe ();

ip = get_host_ip ();


# TODO: Ultimately, this report should also contain
# the OID of the NVT which found this OS/App/Service
# and the port it was found listening on, if applicable.
  
cpes = get_kb_list("cpe:/*");
report = '';

if (!isnull(cpes))
  foreach cpe (keys(cpes))
  {
    if ("cpe:/o" >< cpe || "cpe:/h" >< cpe)
      register_host_detail(name:"OS", value:cpe, nvt:"1.3.6.1.4.1.25623.1.0.810002", desc:"CPE Inventory");
    else
      register_host_detail(name:"App", value:cpe, nvt:"1.3.6.1.4.1.25623.1.0.810002", desc:"CPE Inventory");
  }

# update the report with CPE's registered as host details
cpes = host_details_cpes();
foreach cpe (cpes)
  if (cpe >!< report)
    report = report + ip + '|' + cpe + '\n';

if (report != '')
  log_message (proto: "CPE-T", data: report);
