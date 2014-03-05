###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libguestfs FEDORA-2013-19452
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(867022);
  script_version("$Revision: 34 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:55:38 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-28 13:55:08 +0530 (Mon, 28 Oct 2013)");
  script_cve_id("CVE-2013-4419", "CVE-2013-2124");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Fedora Update for libguestfs FEDORA-2013-19452");

  tag_insight = "Libguestfs is a library for accessing and modifying guest disk images.
Amongst the things this is good for: making batch configuration
changes to guests, getting disk used/free statistics (see also:
virt-df), migrating between virtualization systems (see also:
virt-p2v), performing partial backups, performing partial guest
clones, cloning guests and changing registry/UUID/hostname info, and
much else besides.

Libguestfs uses Linux kernel and qemu code, and can access any type of
guest filesystem that Linux and qemu can, including but not limited
to: ext2/3/4, btrfs, FAT and NTFS, LVM, many different disk partition
schemes, qcow, qcow2, vmdk.

Libguestfs provides ways to enumerate guest storage (eg. partitions,
LVs, what filesystem is in each LV, etc.).  It can also run commands
in the context of the guest.

Libguestfs is a library that can be linked with C and C++ management
programs.

For high level virt tools, guestfish (shell scripting and command line
access), and guestmount (mount guest filesystems using FUSE), install
'libguestfs-tools'.

For shell scripting and command line access, install 'guestfish'.

To mount guest filesystems on the host using FUSE, install
'libguestfs-mount'.

For Erlang bindings, install 'erlang-libguestfs'.

For GObject bindings and GObject Introspection, install
'libguestfs-gobject-devel'.

For Java bindings, install 'libguestfs-java-devel'.

For Lua bindings, install 'lua-guestfs'

For OCaml bindings, install 'ocaml-libguestfs-devel'.

For Perl bindings, install 'perl-Sys-Guestfs'.

For PHP bindings, install 'php-libguestfs'.

For Python bindings, install 'python-libguestfs'.

For Ruby bindings, install 'ruby-libguestfs'.
";

  tag_affected = "libguestfs on Fedora 18";

  tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_description(desc);
  script_xref(name: "FEDORA", value: "2013-19452");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/pipermail/package-announce/2013-October/119693.html");
  script_summary("Check for the Version of libguestfs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC18")
{

  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.20.12~1.fc18", rls:"FC18")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}