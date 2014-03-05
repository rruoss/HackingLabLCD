###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_file_checksums_violation.nasl 10 2013-10-27 10:03:59Z jan $
#
# List File Checksum Violations
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103942";

tag_summary = "List files with checksum violations";

if (description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10 $");
  script_name("File Checksums: Violations");

  desc = "Summary:
" + tag_summary;

  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-21 10:56:19 +0200 (Wed, 21 Aug 2013)");
  script_description(desc);
  script_summary("List File Checksum Violations");
  script_category(ACT_GATHER_INFO);
  script_family("Policy");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_dependencies("policy_file_checksums.nasl");

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  exit(0);
}

md5fail = get_kb_item("policy/md5cksum_fail");
sha1fail = get_kb_item("policy/sha1cksum_fail");

if (md5fail || sha1fail) {
  report = "The following file checksums don't match:\n\n";
  report += 'Filename|Result|Errorcode;\n' + md5fail + sha1fail;
  log_message(data:report, port:0, proto:"ssh");
}

exit(0);

