

pam_perguntas.o: pam_perguntas.c
	gcc -fPIC -fno-stack-protector -c pam_perguntas.c

install: pam_perguntas.o
	ld -x --shared -o /lib64/security/pam_perguntas.so pam_perguntas.o

uninstall:
	rm -f /lib64/security/pam_perguntas.so
	@echo -e "\n\n      Remove any entry related to this module in /etc/pam.d/ files,\n      otherwise you're not going to be able to login.\n\n"
debug:
	gcc -E -fPIC -fno-stack-protector -c pam_perguntas.c
clean:
	rm -rf *.o
