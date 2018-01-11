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
-d <directory>             Target PHY directory (required)
-c <chip0>,<chip1>...      Alternative List of chips to install
                           (contents of chip-list file used by default)
-b <bus0>,<bus1>...        Alternative List of PHY buses to install
                           (contents of bus-list file used by default)
-a                         Install all packages
-f                         Force installation
-i                         Ignore unsupported patch levels
-s                         Use symlinks when installing
-r                         Release Processing
-g                         Install only Released packages
-v                         Verbose output
-h                         Show this message
EOT
    exit;
}

###############################################################################
#
# MAIN ENTRY POINT
#
###############################################################################

my $options = "d:c:b:gafisvrh";

show_usage() if($#ARGV == -1);
Getopt::Std::getopts($options);
show_usage() if(defined($opt_h));

# Set up base directories
if(!defined($opt_d)) {
    die("no PHY directory specified");
}
my $phydir = $opt_d;
my $pkgdir = "$phydir/PKG";
my $toolsdir = "$phydir/tools";

# Pull in modules
push @INC, $toolsdir;
require PackageInstaller;
require PhyInstaller;
my $pkginst = new PackageInstaller("$pkgdir", defined($opt_i), defined($opt_s), defined($opt_v));
my $phyinst = new PhyInstaller();

if(defined($opt_r)) {
  $pkginst->release_packages(); 
  exit; 
}

# Get library base version
my $basever = "0.0";
if (open(RELFILE, "$phydir/RELEASE")) {
    my @lines = <RELFILE>;
    $basever = @lines[0];
    $basever =~ s/\s+$//;
}

# Check destination directories
my $dest_base_src = "$phydir/pkgsrc";
if (!(-e "$dest_base_src")) {
    $pkginst->error_exit("Output directory $dest_base_src not found\n");
}
my $dest_base_inc = "$phydir/include";
if (!(-e $dest_base_inc)) {
    $pkginst->error_exit("Output directory $dest_base_inc not found\n");
}
my $dest_base_sym = "$phydir/sym";
if (!(-e $dest_base_sym)) {
    $pkginst->error_exit("Output directory $dest_base_sym not found\n");
}

# Determine which packages to install
my @phy_chips = $pkginst->get_pkg_list("chip", $opt_a);
if (defined($opt_c)) {
    @phy_chips = split(/,/, $opt_c);
}
my @phy_buses = $pkginst->get_pkg_list("bus", $opt_a);
if (defined($opt_b)) {
    @phy_buses = split(/,/, $opt_b);
}
@phy_buses = sort(@phy_buses);

my @phy_disabled = (); 

# Pull in version and dependencies for chip packages
foreach my $chip (@phy_chips) {
    my $pkginfo = $pkginst->package_info("$pkgdir/chip/$chip/PKGINFO");
    if(($pkginfo->{DISABLED} == 1 && !$opt_a) ||
       ($pkginfo->{NORELEASE} == 1 && $opt_g)) {
      push @phy_disabled, $chip; 
      next;
    }
    $pkginst->check_version($chip, $basever, $pkginfo->{VERSION});
    $pkgver{$chip} = $pkginfo->{VERSION};
    if (defined($pkginfo->{DEPEND})) {
        push @phy_chips, split(/,/, $pkginfo->{DEPEND});
    }
}

# Remove duplicates from chip package list
undef %saw;
foreach (@phy_disabled) { $saw{$_}++; warn "PKG $_ is disabled and will not be installed\n"; }
my @phy_chips_uniq = grep(!$saw{$_}++, @phy_chips);
@phy_chips_uniq = sort(@phy_chips_uniq);

# Get version of bus packages
foreach my $bus (@phy_buses) {
    my $pkginfo = $pkginst->package_info("$pkgdir/bus/$bus/PKGINFO");
    $pkginst->check_version($bus, $basever, $pkginfo->{VERSION});
    $pkgver{$bus} = $pkginfo->{VERSION};
}

# Create summary of packages and versions
$chkfile = "$dest_base_src/installed-chips";
$chkfile_tmp = "$chkfile.tmp";
if (!open($tmpfh, ">$chkfile_tmp")) {
    $pkginst->error_exit("Unable to create $chkfile_tmp\n");
}
foreach my $chip (@phy_chips_uniq) {
    print $tmpfh "$chip:$pkgver{$chip}\n";
}
foreach my $bus (@phy_buses) {
    print $tmpfh "$bus:$pkgver{$bus}\n";
}
close($tmpfh);

# Check summary against current installation and quit if no changes
if (!defined($opt_f) && (-e $chkfile) && compare($chkfile_tmp, $chkfile) == 0) {
    $pkginst->info_msg("PHY packages up to date\n");
    $pkginst->remove_file($chkfile_tmp);
    exit 0;
}

# Create clean destinations for chip and bus files
foreach $dir ("chip", "bus") {
    my $dest_src = "$dest_base_src/$dir";
    if (-e $dest_src) {
        $pkginst->remove_file($dest_src);
    }
    $pkginst->make_path($dest_src);

    my $dest_inc = "$dest_base_inc/phy/$dir";
    if (-e $dest_inc) {
        $pkginst->remove_file($dest_inc);
    }
    $pkginst->make_path($dest_inc);
}

# Create clean destination for symbol files
my $dest_chip_sym = "$dest_base_sym/chip";
if (-e $dest_chip_sym) {
    $pkginst->remove_file($dest_chip_sym);
}
$pkginst->make_path($dest_chip_sym);

# Prepare for auto-generated source and header files
my @phy_buslist_defs = ();
my @phy_config_chips_defs = ();
my @phy_config_chips_opts = ();
my @phy_devlist_defs = ();
my @phy_allsyms_defs = ();

# Install bus packages
my $dest_bus_inc = "$dest_base_inc/phy/bus";
foreach my $bus (@phy_buses) {
    my $busdir = "$pkgdir/bus/$bus";
    my $dest_bus_src = "$dest_base_src/bus/$bus";
    if (!opendir(BUSDIR, $busdir)) {
        $pkginst->error_exit("Package $bus not available\n");
    }
    $pkginst->info_msg("Installing bus/$bus\n");
    $pkginst->make_path($dest_bus_src);
    while (my $file = readdir(BUSDIR)) {
        my $thisfile = "$busdir/$file";
        if ($file eq "phy_buslist.def") {
            push @phy_buslist_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        elsif ($file =~ /.*\.c$/) {
            $pkginst->install_file("$busdir/$file", "$dest_bus_src/$file");
        }
        elsif ($file =~ /.*\.h$/) {
            $pkginst->install_file("$busdir/$file", "$dest_bus_inc/$file");
        }
    }
    closedir(BUSDIR);
}

# Install chip packages
my $dest_chip_inc = "$dest_base_inc/phy/chip";
foreach my $chip (@phy_chips_uniq) {
    my $chipdir = "$pkgdir/chip/$chip";
    my $dest_chip_src = "$dest_base_src/chip/$chip";
    if (!opendir(CHIPDIR, $chipdir)) {
        $pkginst->error_exit("Package $chip not available\n");
    }
    $pkginst->info_msg("Installing chip/$chip\n");
    $pkginst->make_path($dest_chip_src);
    while (my $file = readdir(CHIPDIR)) {
        my $thisfile = "$chipdir/$file";
        if ($file eq "phy_allsyms.def") {
            push @phy_allsyms_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "phy_depend.def") {
            push @phy_config_chips_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "phy_depend.opt") {
            push @phy_config_chips_opts, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "phy_devlist.def") {
            push @phy_devlist_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file =~ /sym\.c$/) {
            $pkginst->install_file($thisfile, "$dest_chip_sym/$file");
            next;
        }
        if ($file =~ /\.h$/) {
            $pkginst->install_file($thisfile, "$dest_chip_inc/$file");
            next;
        }
        if ($file =~ /\.c$/) {
            $pkginst->install_file($thisfile, "$dest_chip_src/$file");
            next;
        }
    }
    closedir(CHIPDIR);
}

# Build and install bus list file
my $tmpfile = "$pkgdir/phy_buslist.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating phy_buslist.h\n");
$phyinst->begin_phy_buslist($tmpfh);
print $tmpfh @phy_buslist_defs;
$phyinst->end_phy_buslist($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/phy/phy_buslist.h");

# Build and install PHY dependency file
my $tmpfile = "$pkgdir/phy_config_chips.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating phy_config_chips.h\n");
$phyinst->begin_phy_config_chips($tmpfh);
print $tmpfh @phy_config_chips_defs;
$phyinst->end_phy_config_chips($tmpfh);
$phyinst->begin_phy_config_chips_opt($tmpfh);
print $tmpfh @phy_config_chips_opts;
$phyinst->end_phy_config_chips_opt($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/phy_config_chips.h");

# Build and install device list file
my $tmpfile = "$pkgdir/phy_devlist.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating phy_devlist.h\n");
$phyinst->begin_phy_devlist($tmpfh);
print $tmpfh @phy_devlist_defs;
$phyinst->end_phy_devlist($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/phy/phy_devlist.h");

# Build and install consolidated symbol file (for reduced image size)
my $tmpfile = "$pkgdir/phy_allsyms.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating phy_allsyms.c\n");
$phyinst->begin_phy_allsyms($tmpfh);
print $tmpfh @phy_allsyms_defs;
$phyinst->end_phy_allsyms($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_sym/phy_allsyms.c");

# All done - update summary of installed packages
$pkginst->install_file($chkfile_tmp, $chkfile);
