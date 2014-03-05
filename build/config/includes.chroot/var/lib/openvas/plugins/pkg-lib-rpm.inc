#
# This script was written by Thomas Reinke <reinke@securityspace.com>
#
# Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
# rpmcheck is intended to provide a quick way to verify that
# a given rpm, if it is installed, is up to date. The function
# isrpmvuln returns 0 if it is not installed or is installed
# but up to date, and returns 1 if it is installed and vulnerable



# This variable is defined at inclusion time. It's declared global and is set
# to True if isrpmvuln() is called for an OS version and a package name that
# match the target's configuration. It allows the callers to distinguish
# between non-installed packages and packages installed but not vulnerable.
__pkg_match = FALSE;


# Example call: isrpmvuln(pkg:"gnutls-utils", rpm:"gnutls-utils~1.4.1~3", rls:"FC6")

function isrpmvuln(pkg, rpm, rls) {
    local_var a, b, kbrls, pat, matches, checkshorta, checkshortb, rc, norm_pkg, report;
    # Check that we have the data for this release.
    kbrls = get_kb_item("ssh/login/release");
    if(kbrls!=rls) {
	return NULL;
    }
    rpms = get_kb_item("ssh/login/rpms");
    if(!rpms) return NULL;

    # Must include in the package search leading \n or ; to prevent
    # overly permissive search (e.g. search for 'ash' must not match 'bash')

    pat = string("[\n;](", pkg, "~[^;]+);");
    matches = eregmatch(pattern:pat, string:rpms);
    if(isnull(matches)) {
	return NULL;
    }
#security_note(0, data: "Comparing " + matches[1] + " against " + rpm);

    # Ok...revcomp handles almost all situations intellligently. But,
    # it can get caught on the following two string example:
    #    a:a="kernel~2.6.9~89.EL"; b="kernel~2.6.9~89.0.20.EL";
    # One would expect 'a' to be < (older than) 'b'.  However, in this
    # case revcomp differentiates the 'E' from the '0', and thinks that
    # that b is as a result older (lexicographically less than) a.
    # This is the only situation we've seen where this type of suffix
    # causes problems.  So, as a patch, we solve the problem locally 
    # BEFORE we call revcomp, by stripping from both strings the trailing
    # '.EL[0-9]*' suffix, but only if both strings have the identical suffix.
    # If we find other systems where this type of problem occurred, it may
    # make sense to consider if we should be stripping equal trailing strings
    # from the a/b parameters within revcomp. For now, though we'll do it here.

    a = matches[1];
    b = rpm;
    checkshorta = eregmatch(pattern:"^(.*)[.]([Ee][Ll][0-9]*)$", string:a);
    checkshortb = eregmatch(pattern:"^(.*)[.]([Ee][Ll][0-9]*)$", string:b);
    if(!isnull(checkshorta) && !isnull(checkshortb)) {
	if(checkshorta[2]==checkshortb[2]) {
	    a = checkshorta[1];
	    b = checkshortb[1];
	}
    }

    __pkg_match = TRUE;

    # Now proceed with the normal revision comparison
    rc = revcomp(a:a, b:b);
    if(rc<0) {
	norm_pkg = "";
	foreach comp (split(matches[1], sep: "~", keep:0)) {
	    norm_pkg = string(norm_pkg,"-",comp);
	}
	norm_pkg = substr(norm_pkg, 1);
	report = "Package " + pkg + " version " +
		 norm_pkg + ' is installed which is known to be vulnerable.\n';
	return report;
    }
    return NULL;
}
