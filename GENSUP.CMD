cd sym
nmake | tee >log
cd ..\hll
nmake | tee >log
cd ..\cv32
nmake | tee >log
cd ..
