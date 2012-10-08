/**
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
 *            Dustin Kirkland <kirkland@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <stdio.h>
#include <ecryptfs.h>
#include <string.h>
#include <getopt.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs-insert-wrapped-passphrase-into-keyring [file]\n"
	       "or\n"
	       "printf \"%%s\" \"wrapping passphrase\" | "
	       "ecryptfs-insert-wrapped-passphrase-into-keyring [file] -\n"
	       "or\n"
	       "printf \"%%s\" \"wrapping passphrase\" | "
	       "ecryptfs-insert-wrapped-passphrase-into-keyring -i wrapped-fs-binpass-file\n"
	       "    -i, --in-wrapped=file\n"
	       "        input wrapped-fs-binpass from file\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char *in_wrapped_file = NULL;
	char *wrapping_passphrase;
	char auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;

	static const struct option long_options[] = {
		{"help",       no_argument,       NULL, 'h'},
		{"in-wrapped", required_argument, NULL, 'i'},
		{0, 0, 0, 0}
	};
	static const char short_options[] = "hi:";

	do {
		int option_index = 0;
		int c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
		case 'i':
			in_wrapped_file = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage(); goto out;
		}
	} while (1);

	if (in_wrapped_file != NULL) {
		if (strncmp(in_wrapped_file, "-", 2) == 0)
			{usage(); goto out;}
		--optind;
	}

	--optind;
    if (argc == 1+optind && in_wrapped_file == NULL) {
        /* interactive, and try default wrapped-passphrase file */
    	in_wrapped_file = ecryptfs_get_wrapped_passphrase_filename();
		if (in_wrapped_file == NULL) {
			usage();
			goto out;
		}
		wrapping_passphrase = ecryptfs_get_passphrase("Passphrase");
	} else {
		if (argc == 2+optind) {
			/* interactive mode */
			wrapping_passphrase = ecryptfs_get_passphrase("Passphrase");
		} else if (argc == 3+optind && strncmp(argv[2+optind], "-", 2) == 0) {
			/* stdin mode */
			wrapping_passphrase = ecryptfs_get_passphrase(NULL);
		} else if (argc == 3+optind && strncmp(argv[2+optind], "-", 2) != 0) {
			/* argument mode */
			wrapping_passphrase = argv[2+optind];
		} else {
			usage();
			goto out;
		}
		if (in_wrapped_file == NULL) in_wrapped_file = argv[1+optind];
	}
	if (wrapping_passphrase == NULL ||
	    strlen(wrapping_passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
		usage();
		goto out;
	}

	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_insert_wrapped_passphrase_into_keyring_bk(
		     auth_tok_sig_hex, in_wrapped_file, wrapping_passphrase,
		     strlen(wrapping_passphrase), salt)) < 0) {
		fprintf(stderr, "%s [%d]\n",
			ECRYPTFS_ERROR_UNWRAP_AND_INSERT, rc);
                fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	} else
		rc = 0;
	auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	printf("Inserted auth tok with sig [%s] into the user session "
	       "keyring\n", auth_tok_sig_hex);
out:
	return rc;
}
