vanityETHMPI

HOW TO COMPILE
./configure
make

This will create two binaries. vanityETH is a serial code that can easily be run in an embarassingly parallel way if your system doesn't have MPI installed. vanityETHMPI uses MPI to parallelize the computation.
