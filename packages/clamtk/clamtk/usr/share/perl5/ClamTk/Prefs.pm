# ClamTk, copyright (C) 2004-2012 Dave M
#
# This file is part of ClamTk (http://clamtk.sourceforge.net).
#
# ClamTk is free software; you can redistribute it and/or modify it
# under the terms of either:
#
# a) the GNU General Public License as published by the Free Software
# Foundation; either version 1, or (at your option) any later version, or
#
# b) the "Artistic License".
package ClamTk::Prefs;

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use Digest::MD5 'md5_hex';
use File::Path 'mkpath';
use Date::Calc 'Date_to_Days';

use Locale::gettext;
use POSIX 'locale_h';

sub structure {
    my $paths = ClamTk::App->get_path('all');

    # Ensure default paths/files exist.
    # If they do, ensure they have the proper permissions.
    # The default Fedora umask for users is 0002,
    # while Ubuntu's is 0022... sigh.
    # I'm going to assume that it's one or the other.
    # my $umask = sprintf("%04o", umask());
    my $mask = ( umask() == 2 ) ? '0775' : '0755';

    # This is /home/user/.clamtk/viruses,
    # used for the quarantine directory
    if ( !-d $paths->{viruses} ) {
        eval { mkpath( $paths->{viruses}, { mode => oct($mask) } ) };
        warn $@  if ($@);
        return 0 if ($@);
    } else {
        # Ensure the permissions are correct
        chmod oct($mask), $paths->{viruses};
    }

    # This is /home/user/.clamtk/history,
    # which holds records of scans
    if ( !-d $paths->{history} ) {
        eval { mkpath( $paths->{history}, { mode => oct($mask) } ) };
        warn $@  if ($@);
        return 0 if ($@);
    } else {
        # Ensure the permissions are correct
        chmod oct($mask), $paths->{history};
    }

    # The path /home/user/.clamtk/db stores signatures
    if ( !-d $paths->{db} ) {
        eval { mkpath( $paths->{db}, { mode => oct($mask) } ) };
        warn $@  if $@;
        return 0 if ($@);
    } else {
        # Ensure the permissions are correct
        chmod oct($mask), $paths->{db};
    }

    # This is /home/user/.clamtk/prefs,
    # a custom INI-style file.
    if ( !-e $paths->{prefs} ) {
        warn "note: (re)creating prefs file.\n";
        open( my $F, '>:encoding(UTF-8)', $paths->{prefs} )
            or do {
            warn "Unable to create preferences! $!\n";
            return 0;
            };
        close($F);
        eval { custom_prefs() };
        warn $@  if ($@);
        return 0 if ($@);
    }

    # This is /home/user/.clamtk/restore, which holds
    # information for putting back false positives
    if ( !-e $paths->{restore} ) {
        open( my $F, '>:encoding(UTF-8)', $paths->{restore} )
            or do {
            warn "Unable to create restore file! $!\n";
            return 0;
            };
        close($F);
    }

    # This is /home/user/.clamtk/submit
    if ( !-d $paths->{submit} ) {
        eval { mkpath( $paths->{submit}, { mode => oct($mask) } ) };
        warn $@  if $@;
        return 0 if ($@);
    } else {
        # Ensure the permissions are correct
        chmod oct($mask), $paths->{submit};
    }

    # Now create the file to track submissions (ClamTk::Submit).
    # Not going to recreate everything here.
    if ( !-e "$paths->{submit}/times" ) {
        ClamTk::Submit->create_file();
    }

    return 1;
}

sub custom_prefs {
   # ensure prefs have normalized variables, especially for 3.11 -> 4.00 users
    my %pkg;
    # Get the user's current prefs
    my $paths = ClamTk::App->get_path('prefs');

    open( my $F, '<:encoding(UTF-8)', $paths )
        or do {
        warn "Unable to read preferences! $!\n";
        return 0;
        };

    while (<$F>) {
        my ( $k, $v ) = split(/=/);
        chomp($v);
        $pkg{$k} = $v;
    }
    close($F);

    # If the preferences aren't already set,
    # use 'shared' by default. This makes it work out of the box.
    if ( !exists $pkg{Update} ) {
        $pkg{Update} = 'shared';
    } elsif ( $pkg{Update} !~ /shared|single/ ) {
        # If it's set to 'shared' or 'single', leave it alone.
        # Otherwise, look for system signatures.
        $pkg{Update} = 'shared';
    }

    # The proxy is off by default
    if ( !exists $pkg{HTTPProxy} ) {
        $pkg{HTTPProxy} = 0;
    }

    # The whitelist is off by default
    if ( !exists $pkg{Whitelist} ) {
        $pkg{Whitelist} = '';
    }

    # Last infected file
    if ( !exists $pkg{'LastInfection'} ) {
        $pkg{'LastInfection'} = gettext('Never');
    }

    if ( !exists $pkg{'PulseMode'} ) {
        $pkg{'PulseMode'} = 'activity';
    }

    for my $o (
        qw{SaveToLog ScanHidden SizeLimit
        Thorough Recursive Mounted}
        ) {
        # off by default
        if ( !exists $pkg{$o} ) {
            $pkg{$o} = 0;
        }
    }

    for my $p (qw{AVCheck GUICheck TruncateLog DupeDB }) {
        # on by default
        if ( !exists $pkg{$p} ) {
            $pkg{$p} = 1;
        }
    }
    write_all(%pkg);
    return;
}

sub get_all_prefs {
    # Sometimes it's useful to have all
    # the preferences rather than just one.
    my %pkg;
    my $paths = ClamTk::App->get_path('prefs');
    open( my $F, '<:encoding(UTF-8)', $paths )
        or do {
        warn "Unable to read preferences! $!\n";
        return 0;
        };

    while (<$F>) {
        my ( $k, $v ) = split(/=/);
        chomp($v);
        $pkg{$k} = $v;
    }
    close($F);
    return %pkg if %pkg;
}

sub legit_key {
    # Sanity check the prefs file's keys.
    my @keys = qw(
        SizeLimit HTTPProxy
        LastInfection GUICheck DupeDB
        TruncateLog SaveToLog
        Whitelist Update ScanHidden
        Thorough Recursive Mounted PulseMode
        );
    return 1 if ( grep { $_[0] eq $_ } @keys );
}

sub write_all {
    my %loc = @_;

    my $paths = ClamTk::App->get_path('prefs');
    open( my $F, '>:encoding(UTF-8)', $paths )
        or do {
        warn "Unable to write preferences! $!\n";
        return 0;
        };

    while ( my ( $k, $v ) = each %loc ) {
        if ( legit_key($k) ) {
            print $F "$k=$v\n";
        }
    }
    close($F);

    return 1;
}

sub set_preference {
    my ( undef, $wk, $wv ) = @_;    # undef = package name
    my $paths = ClamTk::App->get_path('prefs');

    open( my $F, '<:encoding(UTF-8)', $paths )
        or do {
        warn "Unable to read preferences! $!\n";
        return 0;
        };

    my %pkg;
    while (<$F>) {
        my ( $k, $v ) = split(/=/);
        chomp($v);
        $pkg{$k} = $v;
    }
    close($F);

    open( $F, '>:encoding(UTF-8)', $paths )
        or return -1;

    while ( my ( $k, $v ) = each %pkg ) {
        if ( legit_key($k) && ( $k ne $wk ) ) {
            print $F "$k=$v\n";
        }
    }
    print $F "$wk=$wv\n" if ( legit_key($wk) );
    close($F)
        or warn "Couldn't close $paths: $!\n";
    return 1;
}

sub get_preference {
    my ( undef, $wanted ) = @_;    # undef = package name

    my $paths = ClamTk::App->get_path('prefs');
    my %pkg;
    open( my $F, '<:encoding(UTF-8)', $paths )
        or do {
        warn "Unable to read preferences! $!\n";
        return 0;
        };

    while (<$F>) {
        my ( $k, $v ) = split(/=/);
        chomp($v);
        $pkg{$k} = $v;
    }
    close($F);

    return unless %pkg;
    return $pkg{$wanted} || '';
}

sub set_proxy {
    my ( undef, $ip, $port ) = @_;    # undef = package name

    # If the user doesn't set a port, we'll just jot down port 80.
    $port = $port || '80';

    my $path = ClamTk::App->get_path('db');

    # This gets clobbered every time.
    # Doesn't need to be utf-8 friendly. I think.
    open( my $FH, '>', "$path/local.conf" )
        or return -1;
    print $FH <<"EOF";
HTTPProxyServer $ip
HTTPProxyPort $port
DatabaseMirror db.local.clamav.net
DatabaseMirror database.clamav.net
EOF
    close($FH)
        or warn "Couldn't close $path/local.conf: $!\n";
    return 1;
}

sub restore {
    shift;    # throw one away
    my $wanted = shift;    # the md5sum of the file we're after
    my $job    = shift;    # either exists, add, or remove
    my $path   = shift;    # full path of file
    my $perm   = shift;    # permissions in octal (eg., 0644)

    my %p;
    my $restore_path = ClamTk::App->get_path('restore');

    open( my $F, '<:encoding(UTF-8)', $restore_path ) or do {
        warn "Can't open restore file for reading: $!\n";
        return -1;
    };
    binmode( $F, ':encoding(UTF-8)' );

    while (<$F>) {
        chomp;
        my ( $m, $paths, $perms ) = split /:/;
        if ( exists $p{$m} ) {
            return -1;
        }
        $p{$m} = { path => $paths, perm => $perms };
    }
    close($F)
        or warn "Couldn't close $restore_path: $!\n";

    if ( $job eq 'exists' ) {
        for my $e ( keys %p ) {
            if ( $e eq $wanted ) {
                return ( $p{$e}->{path}, $p{$e}->{perm} );
            }
        }
        return 0;
    }

    if ( $job eq 'add' ) {
        if ( exists( $p{$wanted} ) ) {
            #warn "File $wanted already exists?\n";
            return -1;
        }
        open( $F, '>:encoding(UTF-8)', $restore_path ) or do {
            warn "Can't open restore file for writing: $!\n";
            return -1;
        };
        binmode( $F, ':encoding(UTF-8)' );

        if ( scalar( keys %p ) ) {
            for my $e ( keys %p ) {
                print $F $e, ":", $p{$e}->{path}, ":", $p{$e}->{perm}, "\n";
            }
        }
        print $F "$wanted:$path:$perm\n";
        close($F);
    }

    if ( $job eq 'remove' ) {
        open( $F, '>:encoding(UTF-8)', $restore_path ) or do {
            warn "Can't open restore file for writing: $!\n";
            return -1;
        };
        binmode( $F, ':encoding(UTF-8)' );

        for my $e ( keys %p ) {
            next if ( $e eq $wanted );
            print $F $e, ":", $p{$e}->{path}, ":", $p{$e}->{perm}, "\n";
        }
        close($F)
            or warn "Couldn't close $restore_path: $!\n";
    }
    return;
}

###############
### Patches ###
###############

sub restore_file_fix {
    # This subroutine was only supposed to be in 4.25 because the line
    # 'next if ($e eq $wanted)' got dropped from 'sub restore' above.
    # So, we need to remove all the lines from the restore file that
    # don't have coresponding viruses in the quarantine directory.

    my $restore    = ClamTk::App->get_path('restore');
    my $quarantine = ClamTk::App->get_path('viruses');
    return unless ( -e $restore && -e $quarantine );

    # First, grab everything quarantined.
    my @viruses = grep { -f $_ } glob "$quarantine/*";

    # Now, grab their md5sums
    my %p;
    for my $f (@viruses) {
        my $ctx = do {
            local $/ = undef;
            open( my $G, '<', $f ) or next;
            binmode($G);
            <$G>;
        };
        my $md5 = md5_hex($ctx);
        $p{$md5} = $f;
    }

    # Now grab the md5sums the restore file says we have
    my %q;
    open( my $F, '<:encoding(UTF-8)', $restore )
        or return;
    while (<$F>) {
        chomp;
        my ( $m, undef, undef ) = split /:/;
        $q{$m} = 1;
    }
    close($F)
        or warn "Couldn't close $restore: $!\n";

    # Go through the keys (md5s) of the restore file;
    # remove the records of those that don't exist.
    for my $k ( keys %q ) {
        unless ( exists $p{$k} ) {
            ClamTk::Prefs->restore( $k, 'remove' );
        }
    }
    return;
}

sub remove_VIRUS_ext {
    # This is a "patch" to remove the extension
    # .VIRUS from quarantined files.
    my $path  = ClamTk::App->get_path('viruses');
    my @files = glob "$path/*.VIRUS";

    for my $f (@files) {
        my ($new) = ( $f =~ /(.*?).VIRUS/ );
        rename( $f, $new ) or warn "Unable to rename file: $!\n";
    }
}

1;
