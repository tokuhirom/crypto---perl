use inc::Module::Install;
name 'Crypt-Cryptopp';
all_from 'lib/Crypt/Cryptopp.pm';

license 'perl';

tests 't/*.t t/*/*.t';
author_tests 'xt';

build_requires 'Test::More';
build_requires 'YAML';

can_cc or die "This module requires a C compiler";
libs '-lcrypto++';
cc_optimize_flags "-g";

makemaker_args(
	OBJECT => '$(O_FILES)',
    CC => 'g++',
	clean => {
		FILES => q{
			*.stackdump
			*.gcov *.gcda *.gcno
			*.out
			nytprof
			cover_db
		},
	},
);

use_test_base;
auto_include;
WriteAll();
