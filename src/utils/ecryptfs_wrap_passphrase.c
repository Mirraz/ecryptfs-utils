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
#include <stdlib.h>
#include <getopt.h>
#include <ecryptfs.h>
#include <string.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs-wrap-passphrase [file]\n"
	       "or\n"
	       "printf \"%%s\\n%%s\" \"passphrase to wrap\" "
	       "\"wrapping passphrase\" "
	       "| ecryptfs-wrap-passphrase [file] -\n"
	       "or\n"
	       "printf \"%%s\" \"wrapping passphrase\" | "
	       "ecryptfs-wrap-passphrase -i fs-binpass-file [-o wrapped-fs-binpass-file/-]\n"
	       "    -i, --in-binpass=file\n"
	       "        input fs-binpass from file\n"
	       "    -o, --out-wrapped=file\n"
	       "        output wrapped-fs-binpass to file (\"-\" or miss - output to STDOUT)\n"
	       "\n"
	       "note: passphrase can be at most %d bytes long\n",
	       ECRYPTFS_MAX_PASSWORD_LENGTH);
}

int main(int argc, char *argv[])
{
	char *in_binpass_file = NULL, *out_wrapped_file = NULL;
	char *wrapping_passphrase = NULL;
	char *passphrase = NULL;
	unsigned int passphrase_size;
	int arg_mode_flag = 0;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;

	static const struct option long_options[] = {
		{"help",        no_argument,       NULL, 'h'},
		{"in-binpass" , required_argument, NULL, 'i'},
		{"out-wrapped", required_argument, NULL, 'o'},
		{0, 0, 0, 0}
	};
	static const char short_options[] = "hi:o:";

	do {
		int option_index = 0;
		int c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
		case 'i':
			in_binpass_file = optarg;
			break;
		case 'o':
			out_wrapped_file = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage(); goto out;
		}
	} while (1);

	if (in_binpass_file) {
		/* new behaviour */
		if (strncmp(in_binpass_file, "-", 2) == 0)
			{usage(); goto out;}
		if (out_wrapped_file != NULL && strncmp(out_wrapped_file, "-", 2) == 0)
			out_wrapped_file = NULL;

		if (optind == argc) {
			/* interactive mode */
			wrapping_passphrase = ecryptfs_get_passphrase("Wrapping passphrase");
		} else if (optind+1 == argc && strncmp(argv[optind], "-", 2) == 0) {
			/* stdin mode */
			wrapping_passphrase = ecryptfs_get_passphrase(NULL);
		} else {
			usage(); goto out;
		}
		if (!wrapping_passphrase) {usage(); rc = 1; goto out;}

		passphrase = malloc(ECRYPTFS_MAX_PASSPHRASE_BYTES);
		if (passphrase == NULL) {perror("malloc"); rc = 1; goto out;}
		rc = ecryptfs_get_passphrase_from_file_bk(in_binpass_file,
				passphrase, &passphrase_size);
		if (rc) goto out;

	} else {
		/* old behaviour */
		if (optind != 1) {usage(); goto out;}
		if (argc == 2) {
			/* interactive mode */
			passphrase = ecryptfs_get_passphrase("Passphrase to wrap");
			if (passphrase)
				wrapping_passphrase =
					ecryptfs_get_passphrase("Wrapping passphrase");
		} else if (argc == 3 && strncmp(argv[2], "-", 2) == 0) {
			/* stdin mode */
			passphrase = ecryptfs_get_passphrase(NULL);
			if (passphrase)
				wrapping_passphrase = ecryptfs_get_passphrase(NULL);
		} else if (argc == 4) {
			/* argument mode */
			passphrase = argv[2];
			wrapping_passphrase = argv[3];
		} else {
			usage();
			goto out;
		}
		if (passphrase == NULL || wrapping_passphrase == NULL ||
		    strlen(passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH ||
		    strlen(wrapping_passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
			usage();
			rc = 1;
			goto out;
		}
		out_wrapped_file = argv[1];
		passphrase_size = strlen(passphrase);
	}

	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_wrap_passphrase_bk(out_wrapped_file, wrapping_passphrase,
					   strlen(wrapping_passphrase), salt,
					   passphrase, passphrase_size))) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_WRAP, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	}
out:
	if (!arg_mode_flag) {
		if (passphrase) free(passphrase);
		if (wrapping_passphrase) free(wrapping_passphrase);
	}
	return rc;
}
