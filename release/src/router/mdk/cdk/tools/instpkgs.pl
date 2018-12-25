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
-d <directory>             Target CDK directory (required)
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
    die("no CDK directory specified");
}
my $cdkdir = $opt_d;
my $pkgdir = "$cdkdir/PKG";
my $toolsdir = "$cdkdir/tools";

# Pull in modules
push @INC, $toolsdir;
require PackageInstaller;
require CdkInstaller;
my $pkginst = new PackageInstaller("$pkgdir", defined($opt_i), defined($opt_s), defined($opt_v));
my $cdkinst = new CdkInstaller();

if(defined($opt_r)) {
  $pkginst->release_packages(); 
  exit; 
}

# Get library base version
my $basever = "0.0";
if (open(RELFILE, "$cdkdir/RELEASE")) {
    my @lines = <RELFILE>;
    $basever = @lines[0];
    $basever =~ s/\s+$//;
}

# Check destination directories
my $dest_base_src = "$cdkdir/pkgsrc";
if (!(-e $dest_base_src)) {
    $pkginst->error_exit("Output directory $dest_base_src not found\n");
}
my $dest_base_inc = "$cdkdir/include";
if (!(-e $dest_base_inc)) {
    $pkginst->error_exit("Output directory $dest_base_inc not found\n");
}
my $dest_base_sym = "$cdkdir/sym";
if (!(-e $dest_base_sym)) {
    $pkginst->error_exit("Output directory $dest_base_sym not found\n");
}

# Determine which packages to install
my @cdk_chips = $pkginst->get_pkg_list("chip");
if (defined($opt_c)) {
    @cdk_chips = split(/,/, $opt_c);
}

# Pull in version and dependencies for chip packages
my @cdk_archs = ();
my @cdk_disabled = (); 

foreach my $chip (@cdk_chips) {
    my $pkginfo = $pkginst->package_info("$pkgdir/chip/$chip/PKGINFO");
    if(($pkginfo->{DISABLED} == 1 && !$opt_a) ||
       ($pkginfo->{NORELEASE} == 1 && $opt_g))  {
      push @cdk_disabled, $chip; 
      next;
    }
    $pkginst->check_version($chip, $basever, $pkginfo->{VERSION});
    $pkgver{$chip} = $pkginfo->{VERSION};
    if (defined($pkginfo->{ARCH})) {
        push @cdk_archs, $pkginfo->{ARCH};
    }
    if (defined($pkginfo->{DEPEND})) {
        push @cdk_chips, split(/,/, $pkginfo->{DEPEND});
    }
}

# Remove duplicates and disabled chips from chip package list
undef %saw;
foreach (@cdk_disabled) { $saw{$_}++; warn "PKG $_ is disabled and will not be installed\n"; }
my @cdk_chips_uniq = grep(!$saw{$_}++, @cdk_chips);

# Remove duplicates from arch package list
undef %saw;
my @cdk_archs_uniq = grep(!$saw{$_}++, @cdk_archs);

# Get version of arch packages
foreach my $arch (@cdk_archs_uniq) {
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
foreach my $chip (@cdk_chips_uniq) {
    print $tmpfh "$chip:$pkgver{$chip}\n";
}
foreach my $arch (@cdk_archs_uniq) {
    print $tmpfh "$arch:$pkgver{$arch}\n";
}
close($tmpfh);

# Check summary against current installation and quit if no changes
if (!defined($opt_f) && (-e $chkfile) && compare($chkfile_tmp, $chkfile) == 0) {
    $pkginst->info_msg("CDK packages up to date\n");
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

    my $dest_inc = "$dest_base_inc/cdk/$dir";
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

# Create clean destination for shell source files
my $dest_shell_src = "$cdkdir/shell/arch";
if (-e $dest_shell_src) {
    $pkginst->remove_file($dest_shell_src);
}
$pkginst->make_path($dest_shell_src);

# Install arch packages
my $dest_arch_inc = "$dest_base_inc/cdk/arch";
foreach my $arch (@cdk_archs_uniq) {
    my $archdir = "$pkgdir/arch/$arch";
    my $dest_arch_src = "$dest_base_src/arch/$arch";
    if (!opendir(ARCHDIR, $archdir)) {
        $pkginst->error_exit("Package $arch not available\n");
    }
    $pkginst->info_msg("Installing arch/$arch\n");
    $pkginst->make_path($dest_arch_src);
    while (my $file = readdir(ARCHDIR)) {
        if ($file eq "shell") {
            my $shelldir = "$archdir/shell";
            if (!opendir(SHELLDIR, $shelldir)) {
                $pkginst->error_exit("Unable to access directory $shelldir\n");
            }
            while (my $file = readdir(SHELLDIR)) {
                if ($file =~ /.*\.c$/) {
                    $pkginst->install_file("$shelldir/$file", "$dest_shell_src/$file");
                    next;
                }
                if ($file =~ /.*\.h$/) {
                    $pkginst->install_file("$shelldir/$file", "$dest_arch_inc/$file");
                    next;
                }
            }
            closedir(SHELLDIR);
            next;
        }
        if ($file =~ /.*\.c$/) {
            $pkginst->install_file("$archdir/$file", "$dest_arch_src/$file");
            next;
        }
        if ($file =~ /.*\.h$/) {
            $pkginst->install_file("$archdir/$file", "$dest_arch_inc/$file");
            next;
        }
    }
    closedir(ARCHDIR);
}

# Prepare for auto-generated source and header files
my @cdk_config_chips_defs = ();
my @cdk_config_chips_opts = ();
my @cdk_config_phys_defs = ();
my @cdk_devlist_defs = ();
my @cdk_devids_defs = ();
my @cdk_allsyms_defs = ();

# Install chip packages
my $dest_chip_inc = "$dest_base_inc/cdk/chip";
foreach my $chip (@cdk_chips_uniq) {
    my $chipdir = "$pkgdir/chip/$chip";
    my $dest_chip_src = "$dest_base_src/chip/$chip";
    if (!opendir(CHIPDIR, $chipdir)) {
        $pkginst->error_exit("Package $chip not available\n");
    }
    $pkginst->info_msg("Installing chip/$chip\n");
    $pkginst->make_path($dest_chip_src);
    while (my $file = readdir(CHIPDIR)) {
        my $thisfile = "$chipdir/$file";
        if ($file eq "cdk_config_chips.def") {
            push @cdk_config_chips_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "cdk_config_chips.opt") {
            push @cdk_config_chips_opts, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "cdk_config_phys.def") {
            push @cdk_config_phys_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "cdk_devids.def") {
            push @cdk_devids_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "cdk_devlist.def") {
            push @cdk_devlist_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file eq "cdk_allsyms.def") {
            push @cdk_allsyms_defs, $pkginst->read_stub_file($thisfile);
            next;
        }
        if ($file !~ /.*\.[ch]$/) {
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

# Build and install chip architecture definitions
my $tmpfile = "$pkgdir/cdk_config_archs.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating cdk_config_archs.h\n");
$cdkinst->begin_cdk_config_archs($tmpfh);
foreach my $arch (@cdk_archs_uniq) {
    $arch = uc($arch);
    printf $tmpfh "#ifndef CDK_CONFIG_ARCH_%s_INSTALLED\n", $arch;
    printf $tmpfh "#define CDK_CONFIG_ARCH_%s_INSTALLED\n", $arch;
    printf $tmpfh "#endif\n";
    printf $tmpfh "\n";
}
$cdkinst->end_cdk_config_archs($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/cdk_config_archs.h");

# Build and install chip dependency file
my $tmpfile = "$pkgdir/cdk_config_chips.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating cdk_config_chips.h\n");
$cdkinst->begin_cdk_config_chips($tmpfh);
print $tmpfh @cdk_config_chips_defs;
$cdkinst->end_cdk_config_chips($tmpfh);
$cdkinst->begin_cdk_config_chips_opt($tmpfh);
print $tmpfh @cdk_config_chips_opts;
$cdkinst->end_cdk_config_chips_opt($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/cdk_config_chips.h");

# Build and install internal PHY dependency file
my $tmpfile = "$pkgdir/cdk_config_phys.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating cdk_config_phys.h\n");
$cdkinst->begin_cdk_config_phys($tmpfh);
print $tmpfh @cdk_config_phys_defs;
$cdkinst->end_cdk_config_phys($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/cdk_config_phys.h");

# Build and install device list file
my $tmpfile = "$pkgdir/cdk_devlist.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating cdk_devlist.h\n");
$cdkinst->begin_cdk_devids($tmpfh);
print $tmpfh @cdk_devids_defs;
$cdkinst->end_cdk_devids($tmpfh);
$cdkinst->begin_cdk_devlist($tmpfh);
print $tmpfh @cdk_devlist_defs;
$cdkinst->end_cdk_devlist($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_inc/cdk/cdk_devlist.h");

# Build and install consolidated symbol file (for reduced image size)
my $tmpfile = "$pkgdir/cdk_allsyms.tmp";
my $tmpfh;
if (!open($tmpfh, ">$tmpfile")) {
    $pkginst->error_exit("Unable to create $tmpfile\n");
}
$pkginst->info_msg("Generating cdk_allsyms.c\n");
$cdkinst->begin_cdk_allsyms($tmpfh);
print $tmpfh @cdk_allsyms_defs;
$cdkinst->end_cdk_allsyms($tmpfh);
close($tmpfh);
$pkginst->install_file($tmpfile, "$dest_base_sym/cdk_allsyms.c");

# All done - update summary of installed packages
$pkginst->install_file($chkfile_tmp, $chkfile);
