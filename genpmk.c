/*
 * genpmk - Generate a file with precomputed PMK's and words
 *
 * Copyright (c) 2005, Joshua Wright <jwright@hasborg.com>
 *
 * Threading capability and minor bug fixes contributed by: 
 * Michael Craze <mcraze123@gmail.com>, 2016
 *
 * $Id: genpmk.c,v 4.1 2008-03-20 16:49:38 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * coWPAtty is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "cowpatty.h"
#include "common.h"
#include "utils.h"
#include "sha1.h"

#define PROGNAME "genpmk"
#define VER "1.2"

/* Globals */
int sig = 0;			/* Used for handling signals */
char *words;

/* Arguments passed to the thread(s) */
typedef struct {
	char *passphrase;
} Thread_Arguments;

/* Mutex lock to synchronize adding/removing to/from the hash file */
pthread_mutex_t fpout_mutex;

/* made these variables global so that all threads have access. */
FILE *fpout = NULL;
int iterations = 4096;
int verbosity = 0;
int ssid_len;
char *ssid;

/* Prototypes */
void usage(char *message);
int nextword(char *word, FILE * fp);
void *genpmk_thread_worker(void *args);
void *genpmk_flush_records(void *args);

void
usage(char *message){
	if (strlen(message) > 0) {
		printf("%s: %s\n", PROGNAME, message);
	}

	printf("Usage: %s [options]\n", PROGNAME);
	printf("\n"
	       "\t-f \tDictionary file (required)\n"
	       "\t-d \tOutput hash file (required)\n"
	       "\t-s \tNetwork SSID (required)\n"
		   "\t-n \tNumber threads (Defaults to: #_of_cpu's + 1)\n"
		   "\t   \tThis could be played with to optimize cpu load.\n"
		   "\t   \tThe threads write to disk one at a time, which is why cpu load can drop.\n"
	       "\t-h \tPrint this help information and exit\n"
	       "\t-v \tPrint verbose information (more -v for more verbosity)\n"
	       "\t-V \tPrint program version and exit\n" "\n");
	printf("After precomputing the hash file, run cowpatty with the -d "
		"argument.\n");
}

void
cleanup(){
	/* lame-o-meter++ */
	sig = 1;
}

int
nextword(char *word, FILE * fp){
	if (fgets(word, MAXPASSLEN + 1, fp) == NULL) {
		return (-1);
	}

	/* Remove newline */
	word[strlen(word) - 1] = '\0';

	if (feof(fp)) {
		return (-1);
	}

	return (strlen(word));
}

/* Thread worker for calculating hashes */
void
*genpmk_thread_worker(void *args){
	u8 pmk[32];
	struct hashdb_rec rec;
	Thread_Arguments *ta = (Thread_Arguments *)args;

	if (verbosity > 1) {
		printf("Calculating PMK for \"%s\".\n", ta->passphrase);
	}

	/* calculate the hash */
	pbkdf2_sha1(ta->passphrase, ssid, ssid_len, iterations, pmk, sizeof(pmk), USECACHED);
	if (verbosity > 2) {
		printf("PMK is");
		lamont_hdump(pmk, sizeof(pmk));
	}

	/* Populate record with PMK and record length */
	memcpy(rec.pmk, pmk, sizeof(pmk));

	rec.rec_size = (strlen(ta->passphrase) + sizeof(rec.rec_size) + sizeof(rec.pmk));
	
	/* Lock the output file, so we can write to it */
	pthread_mutex_lock(&fpout_mutex);
	
	/* Write the record contents to the file */
	if (fwrite(&rec.rec_size, sizeof(rec.rec_size), 1, fpout) != 1) {
		perror("fwrite: Couldn't write record size to hash file.");
	}
	if (fwrite(ta->passphrase, strlen(ta->passphrase), 1, fpout) != 1) {
		perror("fwrite: Couldn't write ssid to hash file.");
	}
	if (fwrite(rec.pmk, sizeof(rec.pmk), 1, fpout) != 1) {
		perror("fwrite: Couldn't write pmk to hash file.");
	}
	
	pthread_mutex_unlock(&fpout_mutex);
	
	free(ta->passphrase);
	free(ta);

	pthread_exit(NULL);
}

int
main(int argc, char **argv){
	int fret = 0, c, i, ret;
	unsigned long int wordstested=0;
	float elapsed = 0;
	char passphrase[MAXPASSLEN + 1];
	struct user_opt opt;
	struct hashdb_head hf_header;
	struct stat teststat;
	FILE *fpin = NULL;
	struct timeval start, end;
	
	/* The number of CPU's on the system, which determines how many threads we create */
	int num_cpu = sysconf(_SC_NPROCESSORS_ONLN) + 1;

	printf("%s %s - WPA-PSK precomputation attack. <jwright@hasborg.com>\n",
	       PROGNAME, VER);
	
	memset(&opt, 0, sizeof(opt));
	memset(&hf_header, 0, sizeof(hf_header));

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGQUIT, cleanup);

	/* clear getopt's global error variable */
	opterr = 0;

	/* Collect and test command-line arguments */
	while ((c = getopt(argc, argv, "f:d:s:n:hvV")) != -1) {
		switch(c) {
		case 'f':
			strncpy(opt.dictfile, optarg, sizeof(opt.dictfile));
			break;
		case 'd':
			strncpy(opt.hashfile, optarg, sizeof(opt.hashfile));
			break;
		case 's':
			strncpy(opt.ssid, optarg, sizeof(opt.ssid));
			ssid = strdup(opt.ssid);
			ssid_len = strlen(opt.ssid);
			break;
		case 'n':
			num_cpu = strtol(optarg, 0, 10);
			break;
		case 'h':
			usage("");
			exit(0);
		case 'v':
			opt.verbose++;
			verbosity++;
			break;
		case 'V':
			printf("$Id: genpmk.c,v 4.1 2008-03-20 16:49:38 jwright Exp $\n");
			exit(0);
		case '?':
			printf("Unknown option: %c %s\n", c, optarg);
			usage("");
			exit(0);
		}
	}

	if (IsBlank(opt.dictfile)) {
		usage("Must specify a dictionary file with -f");
		exit(1);
	}

	if (IsBlank(opt.hashfile)) {
		usage("Must specify an output hasfile with -d");
		exit(1);
	}

	if (IsBlank(opt.ssid)) {
		usage("Must specify a SSID with -s");
		exit(1);
	}

	/* Open the dictionary file */
	if (*opt.dictfile == '-') {
		printf("Using STDIN for words.\n");
		fpin = stdin;
	} else {
		fpin = fopen(opt.dictfile, "r");
		if (fpin == NULL) {
			perror("fopen");
			exit(-1);
		}
	}

	/* stat the hashfile, if it exists, print a message and check to
	   ensure specified SSID matches header information.  If so, append
	   new words to the end of the hashdb file.
	   If the file does not exist, populate the hashdb_head record and
	   create the file. */
	ret = stat(opt.hashfile, &teststat);
	if(ret < 0){
		//perror("Couldn't stat hashfile");
	}
	if (errno == ENOENT || teststat.st_size == 0) {
		/* File does not exist or is empty, populate header and 
		   create */
		printf("File %s does not exist, creating.\n", opt.hashfile);
		memcpy(hf_header.ssid, opt.ssid, strlen(opt.ssid));
		hf_header.ssidlen = strlen(opt.ssid);
		hf_header.magic = GENPMKMAGIC;

		fpout = fopen(opt.hashfile, "wb");
		if (fpout == NULL) {
			perror("fopen");
			exit(-1);
		}

		if (fwrite(&hf_header, sizeof(hf_header), 1, fpout) != 1) {
			perror("fwrite");
			exit(-1);
		}

	} else {
		/* File does exist, append to EOF after matching SSID */
		fpout = fopen(opt.hashfile, "r+b");
		if (fpout == NULL) {
			perror("fopen");
			exit(-1);
		}

		if (fread(&hf_header, sizeof(hf_header), 1, fpout) != 1) {
			perror("fread");
			exit(-1);
		}

		if (fclose(fpout) != 0) {
            perror("fclose");
            exit(-1);
        }

		if (memcmp(opt.ssid, hf_header.ssid, hf_header.ssidlen) != 0) {
			fprintf(stderr, "Specified SSID \"%s\" and the SSID in "
				"the output file (\"%s\") do not match.\nCreate"
				" a new file, or change SSID to match.\n",
				opt.ssid, hf_header.ssid);
			exit(-1);
		}
		
		printf("File %s exists, appending new data.\n", opt.hashfile);
		if (fopen(opt.hashfile, "ab") == NULL) {
			perror("fopen");
			exit(-1);
		}
	}
	
	/* Populate capdata struct */

	gettimeofday(&start, 0);
	
	printf("%d CPU's online, Creating %d threads.\n", num_cpu - 1, num_cpu);

	/* Create our pthread's dynamically off the heap --
	   I would prefer to use a static array instead (i.e. pthread_t genpmk_worker[num_cpu];)
	   but pthread_create segfaults when the pthread_t variables are declared like that,
	   and not when declared like this. It's likely because they need to be initialized somehow. 
	*/
	pthread_t *genpmk_worker = (pthread_t *)calloc(num_cpu,sizeof(pthread_t) * num_cpu);

	while (feof(fpin) == 0 && sig == 0) {
		Thread_Arguments *ta;
		
		/* dispatch num_cpu number of threads */
		for(i = 0; i < num_cpu; i++) {
			/* Populate "passphrase" with the next word */
			fret = nextword(passphrase, fpin);
			if (fret < 0) {
				break;
			}
			
			if (opt.verbose > 1) {
				printf("Testing passphrase: %s\n", passphrase);
			}

			/*
			 * Test length of word.  IEEE 802.11i indicates the passphrase must be
			 * at least 8 characters in length, and no more than 63 characters in
			 * length. 
			 */
			if (fret < 8 || fret > 63) {
				if (opt.verbose) {
					printf("Invalid passphrase length: %s (%zu).\n",
							passphrase, strlen(passphrase));
				}
				continue;
			} else {
				/* This word is good, increment the words tested counter */
				wordstested++;
			}

			/* Status display and write to disk */
			if ((wordstested % 1000) == 0) {
				printf("key no. %ld: %s\n", wordstested, passphrase);
				fflush(stdout);
			}
		
			/* Set up arguments structure to pass to threads */
			ta = (Thread_Arguments *)calloc(1,sizeof(Thread_Arguments));
			ta->passphrase = strdup(passphrase);
			
			if(pthread_create(&genpmk_worker[i], NULL, &genpmk_thread_worker, (void*)ta) != 0){
				perror("genpmk_thread_worker: pthread_create");
				exit(-1);
			}
		}

		/*  Wait on threads to finish before firing off the next batch */
		for(i = 0; i < num_cpu; i++) {
			/* I don't check the return value of pthread_join here 
			   because if the word in the wordlist is skipped, then
			   the thread object is still created but the thread is 
			   not fired and causes a bunch of useless error messages.
			*/
			pthread_join(genpmk_worker[i], NULL);
		}
	}
	
	if (fclose(fpin) != 0) {
		perror("fclose");
		exit(-1);
	}
	if (fclose(fpout) != 0) {
		perror("fclose");
		exit(-1);
	}

	gettimeofday(&end, 0);

	/* print time elapsed */
	if (end.tv_usec < start.tv_usec) {
		end.tv_sec -= 1;
		end.tv_usec += 1000000;
	}
	end.tv_sec -= start.tv_sec;
	end.tv_usec -= start.tv_usec;
	elapsed = end.tv_sec + end.tv_usec / 1000000.0;

	printf("\n%lu passphrases tested in %.2f seconds:  %.2f passphrases/"
			"second\n", wordstested, elapsed, wordstested / elapsed);

	/* Free up our dynamically allocated thread data structures */
	free(genpmk_worker);

	return (0);
}
