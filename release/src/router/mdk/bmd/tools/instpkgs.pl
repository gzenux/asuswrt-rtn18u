#!/usr/bin/env perl
###############################################################################
#
# instpkgs
#
###############################################################################

use File::Compare;
require Getopt::Std; 

sub show_usage
{
    print STDERR <<EOT; 
OPTIONS:
-d <directory>             Target BMD directory (required)
-c <chip0>,<chip1>...      Alternative List of chips to install
                           (contents of chip-list file used by default)
-a                         Install all packages
-f                         Force installation
-i                         Ignore unsupported patch levels
-s                         Use symlinks when installing
-v                         Verbose output
-r                         Release Processing
-g                         Install only Released packages
-h                         Show this message
EOT
    exit;
}

###############################################################################
#
# MAIN ENTRY POINT
#
###############################################################################

my $options = "d:c:gafisvrh";

show_usage() if($#ARGV == -1);
Getopt::Std::getopts($options);
show_usage() if(defined($opt_h));

# Set up base directories
if(!defined($opt_d)) {
    die("no BMD directory specified");
}
my $bmddir = $opt_d;
my $pkgdir = "$bmddir/PKG";
my $toolsdir = "$bmddir/tools";

# Pull in modules
push @INC, $toolsdir;
require PackageInstaller;
require BmdInstaller;
my $pkginst = new PackageInstaller("$pkgdir", defined($opt_i), defined($opt_s), defined($opt_v));
my $bmdinst = new BmdInstaller();

if(defined($opt_r)) {
  $pkginst->release_packages(); 
  exit; 
}

# Get library base version
my $basever = "0.0";
if (open(RELFILE, "$bmddir/RELEASE")) {
    my @lines = <RELFILE>;
    $basever = @lines[0];
    $basever =~ s/\s+$//;
}

# Check destination directories
my $dest_base_src = "$bmddir/pkgsrc";
if (!(-e "$dest_base_src")) {
    $pkginst->error_exit("Output directory $dest_base_src not found\n");
}
my $dest_base_inc = "$bmddir/include/bmdi";
if (!(-e $dest_base_inc)) {
    $pkginst->error_exit("Output directory $dest_base_inc not found\n");
}

# Determine which packages to install
my @bmd_chips = $pkginst->get_pkg_list("chip");
if (defined($opt_c)) {
    @bmd_chips = split(/,/, $opt_c);
}

# Pull in version and dependencies for chip packages
my @bmd_archs = ();
my @bmd_disabled = (); 

foreach my $chip (@bmd_chips) {
    my $pkginfo = $pkginst->package_info("$pkgdir/chip/$chip/PKGINFO");
    if(($pkginfo->{DISABLED} == 1 && !$opt_a) ||
       ($pkginfo->{NORELEASE} == 1 && $opt_g)) {
      push @bmd_disabled, $chip; 
      next;
    }
    $pkginst->check_version($chip, $basever, $pkginfo->{VERSION});
    $pkgver{$chip} = $pkginfo->{VERSION};
    if (defined($pkginfo->{ARCH})) {
        push @bmd_archs, $pkginfo->{ARCH};
    }
    if (defined($pkginfo->{DEPEND})) {
        push @bmd_chips, split(/,/, $pkginfo->{DEPEND});
    }
}

# Remove duplicates and disabled chips from chip package list
undef %saw;
foreach (@bmd_disabled) { $saw{$_}++; warn "PKG $_ is disabled and will not be installed\n"; }
my @bmd_chips_uniq = grep(!$saw{$_}++, @bmd_chips);

# Remove duplicates from arch package list
undef %saw;
@bmd_archs_uniq = grep(!$saw{$_}++, @bmd_archs);

# Get version of arch packages
foreach my $arch (@bmd_archs_uniq) {
    my $pkginfo = $pkginst->package_info("$pkgdir/arch/$arch/PKGINFO");
    $pkginst->check_version($arch, $basever, $pkginfo->{VERSION});
    $pkgver{$arch} = $pkginfo->{VERSION};
}

# Create summary of packages and versions
$chkfile = "$dest_base_src/installed-chips";
$chkfile_tmp = "$chkfile.tmp";
if (!open($tmpfh, ">$chkfile_tmp")) {
    $pkginst->error_exit("Unable to create $chkfile_tmp\n");
}
foreach my $chip (@bmd_chips_uniq) {
    print $tmpfh "$chip:$pkgver{$chip}\n";
}
foreach my $arch (@bmd_archs_uniq) {
    print $tmpfh "$arch:$pkgver{$arch}\n";
}
close($tmpfh);

# Check summary against current installation and quit if no changes
if (!defined($opt_f) && (-e $chkfile) && compare($chkfile_tmp, $chkfile) == 0) {
    $pkginst->info_msg("BMD packages up to date\n");
    $pkginst->remove_file($chkfile_tmp);
    exit 0;
}

# Create clean destinations for chip and arch files
foreach $dir ("chip", "arch") {
    my $dest_src = "$dest_base_src/$dir";
    if (-e $dest_src) {
        $pkginst->remove_file($dest_src);
    }
    $pkginst->make_path($dest_src);
}
my $dest_arch_inc = "$dest_base_inc/arch";
if (-e $dest_arch_inc) {
    $pkginst->remove_file($dest_arch_inc);
}
$pkginst->make_path($dest_arch_inc);

# Install arch packages
foreach my $arch (@bmd_archs_uniq) {
    my $archdir = "$pkgdir/arch/$arch";
    my $dest_arch_src = "$dest_base_src/arch/$arch";
    if (!opendir(ARCHDIR, $archdir)) {
        $pkginst->error_exit("Package $arch not available\n");
    }
    $pkginst->info_msg("Installing arch/$arch\n");
    $pkginst->make_path($dest_arch_src);
    while (my $file = readdir(ARCHDIR)) {
        if ($file =~ /.*\.c$/) {
            $pkginst->install_file("$archdir/$file", "$dest_arch_src/$file");
        }
        elsif ($file =~ /.*\.h$/) {
            $pkginst->install_file("$archdir/$file", "$dest_arch_inc/$file");
        }
    }
    closedir(ARCHDIR);
}

# Prepare for auto-generated source and header files
my @bmd_devlist_defs = ();

# Install chip packages
foreach my $chip (@bmd_chips_uniq) {
    my $chipdir = "$pkgdir/chip/$chip";
    my $dest_chip_src = "$dest_base_src/chip/$chip";
    if (!opendir(CHIPDIR, $chipdir)) {
        $pkginst->error_exit("Package $chip not available\n");
    }
    $pkginst->info_msg("Installing chip/$chip\n");
    $pkginst->make_path($dest_chip_src);
    while (my $file = readdir(CHIPDIR)) {
        my $thisfile = "$chipdir/$file";
        if ($file eq "bmd_devlist.def") {
            push @bmd_devlist_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file !~ /.*\.[ch]$/) {
            next;
        }
        $pkginst->install_file($thisfile, "$dest_chip_src/$file");
    }
    closedir(CHIPDIR);
}

# Build and install device list file
my $tmpfile = "$pkgdir/bmd_devlist.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating bmd_devlist.h\n");
$bmdinst->begin_bmd_devlist($tmpfh);
print $tmpfh @bmd_devlist_defs;
$bmdinst->end_bmd_devlist($tmpfh, @bmd_chips_uniq);
print $tmpfh "#if BMD_CONFIG_OPTIMIZE_DISPATCH == 1 && !defined(BMD_CONFIG_API_PREFIX)\n"; 
print $tmpfh "#if defined(BMD_DEVLIST_SINGLE_PREFIX) && !defined(BMD_DEVLIST_MULTIPLE)\n"; 
print $tmpfh "#define BMD_CONFIG_API_PREFIX BMD_DEVLIST_SINGLE_PREFIX\n"; 
print $tmpfh "#endif\n"; 
print $tmpfh "#endif\n"; 
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/bmd_devlist.h");

# All done - update summary of installed packages
$pkginst->install_file($chkfile_tmp, $chkfile);
