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
#include <string.h>
#include <getopt.h>
#include <ecryptfs.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "ecryptfs-add-passphrase [--fnek]\n"
	       "or\n"
	       "printf \"%%s\" \"passphrase\" | ecryptfs-add-passphrase"
	       " [--fnek] -\n"
	       "or\n"
	       "ecryptfs-add-passphrase [--fnek] -i fs-binpass-file/-\n"
	       "    -i, --in-binpass=file\n"
	       "        input fs-binpass from file (\"-\" means STDIN)\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char *in_binpass_file = NULL;
	char *passphrase;
	unsigned int passphrase_size;
	char auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;
	int fnek = 0;
	uint32_t version;

	static const struct option long_options[] = {
		{"help",       no_argument,       NULL, 'h'},
		{"fnek",       no_argument,       NULL, 'n'},
		{"in-binpass", required_argument, NULL, 'i'},
		{0, 0, 0, 0}
	};
	static const char short_options[] = "hni:";

	do {
		int option_index = 0;
		int c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
		case 'n':
			fnek = 1;
			break;
		case 'i':
			in_binpass_file = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage(); goto out;
		}
	} while (1);

	if (in_binpass_file != NULL) {
		/* new behaviour */
		if (optind < argc) {usage(); goto out;}
		if (strncmp(in_binpass_file, "-", 2) == 0)
			in_binpass_file = NULL;
		passphrase = malloc(ECRYPTFS_MAX_PASSPHRASE_BYTES);
		if (passphrase == NULL) {perror("malloc"); rc = 1; goto out;}
		rc = ecryptfs_get_passphrase_from_file_bk(in_binpass_file,
				passphrase, &passphrase_size);
		if (rc) goto out;
	} else {
		/* old behaviour */
		fnek = 0;
		if (argc == 1) {
			/* interactive mode */
			passphrase = ecryptfs_get_passphrase("Passphrase");
		} else if (argc == 2 && strncmp(argv[1], "--fnek", 7) == 0) {
			/* interactive mode, plus fnek */
			passphrase = ecryptfs_get_passphrase("Passphrase");
			fnek = 1;
		} else if (argc == 2 && strncmp(argv[1], "-", 2) == 0) {
			/* stdin mode */
			passphrase = ecryptfs_get_passphrase(NULL);
		} else if (argc == 3 &&
			/* stdin mode, plus fnek */
			   strncmp(argv[1], "--fnek", 7) == 0 &&
			   strncmp(argv[2], "-", 2) == 0) {
			passphrase = ecryptfs_get_passphrase(NULL);
			fnek = 1;
		} else {
			usage();
			goto out;
		}
		if (passphrase == NULL ||
		    strlen(passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
			usage();
			rc = 1;
			goto out;
		}
		passphrase_size = strlen(passphrase);
	}

	if (fnek == 1) {
		rc = ecryptfs_get_version(&version);
		if (rc!=0 || !ecryptfs_supports_filename_encryption(version)) { 
			fprintf(stderr, "%s\n", ECRYPTFS_ERROR_FNEK_SUPPORT);
			rc = 1;
			goto out;
		}
	}

	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_add_passphrase_key_to_keyring_bk(auth_tok_sig_hex,
							 passphrase, passphrase_size,
							 salt)) < 0) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_INSERT_KEY, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	} else
		rc = 0;
	auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	printf("Inserted auth tok with sig [%s] into the user session "
	       "keyring\n", auth_tok_sig_hex);

	if (fnek == 0) {
		goto out;
	}

	/* If we make it here, filename encryption is enabled, and it has
	 * been requested that we add the fnek to the keyring too
	 */
	if ((rc = ecryptfs_add_passphrase_key_to_keyring_bk(auth_tok_sig_hex,
				 passphrase, passphrase_size,
				 ECRYPTFS_DEFAULT_SALT_FNEK_HEX)) < 0) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_INSERT_KEY, rc);
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
