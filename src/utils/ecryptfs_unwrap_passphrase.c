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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs-unwrap-passphrase [file]\n"
	       "or\n"
	       "printf \"%%s\" \"wrapping passphrase\" | "
	       "ecryptfs-unwrap-passphrase [file] -\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char *in_wrapped_file = NULL, *out_binpass_file = NULL;
	char *wrapping_passphrase;
	char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1];
	unsigned int passphrase_size;
	int new_behaviour_flag = 0;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;

	static const struct option long_options[] = {
		{"help",        no_argument,       NULL, 'h'},
		{"in-wrapped" , required_argument, NULL, 'i'},
		{"out-binpass", required_argument, NULL, 'o'},
		{0, 0, 0, 0}
	};
	static const char short_options[] = "hi:o:";

	do {
		int option_index = 0;
		int c = getopt_long(argc, argv, short_options, long_options, &option_index);
		if (c == -1) break;
		switch (c) {
		case 'i':
			in_wrapped_file = optarg;
			new_behaviour_flag = 1;
			break;
		case 'o':
			out_binpass_file = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage(); goto out;
		}
	} while (1);

	if (in_wrapped_file) {
		if (strncmp(in_wrapped_file, "-", 2) == 0)
			{usage(); goto out;}
		if (out_binpass_file != NULL && strncmp(out_binpass_file, "-", 2) == 0)
			out_binpass_file = NULL;
		--optind;
	} else {
		if (out_binpass_file != NULL)
			{usage(); goto out;}
	}

	--optind;
	if (argc == 1+optind && in_wrapped_file == NULL) {
		/* interactive, and try default wrapped-passphrase file */
		in_wrapped_file = ecryptfs_get_wrapped_passphrase_filename();
		if (in_wrapped_file == NULL) {usage(); goto out;}
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
	if ((rc = ecryptfs_unwrap_passphrase_bk(passphrase, &passphrase_size, in_wrapped_file,
					     wrapping_passphrase, strlen(wrapping_passphrase), salt))) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_UNWRAP, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	}

	if (new_behaviour_flag) {
		/* new behaviour */
		int fd;
		if (out_binpass_file != NULL) {
			fd = open(out_binpass_file, (O_WRONLY | O_CREAT | O_EXCL), (S_IRUSR | S_IWUSR));
			if (fd < 0) {perror("open"); rc = 1; goto out;}
		} else {
			fd = STDOUT_FILENO;
		}
		ssize_t wrd = write(fd, passphrase, passphrase_size);
		if (wrd != passphrase_size) {
			if (wrd < 0) perror("write");
			rc = 1;
		}
		if (out_binpass_file != NULL) {
			if (close(fd) && rc == 0) rc = 1;
		}
	} else {
		/* old behaviour */
		printf("%s\n", passphrase);
	}
out:
	return rc;
}
