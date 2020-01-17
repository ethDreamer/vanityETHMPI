AM_CFLAGS = -O3 -Wall
bin_PROGRAMS 		 = vanityETH
vanityETH_SOURCES    = keccak.c sph_keccak.h sph_types.h vanityETHMPI.c cmdline/vanityETHCmdline.c cmdline/vanityETHCmdline.h
vanityETH_LDFLAGS 	 = $(openssl_libs)
vanityETHMPI_SOURCES = keccak.c sph_keccak.h sph_types.h vanityETHMPI.c cmdline/vanityETHCmdline.c cmdline/vanityETHCmdline.h
vanityETHMPI_LDFLAGS = $(openssl_libs) -lmpi
vanityETHMPI_CFLAGS  = -DUSE_MPI

if USE_MPI
bin_PROGRAMS += vanityETHMPI
endif


