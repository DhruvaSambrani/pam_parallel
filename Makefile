pam_parallel.so: pam_parallel.c
	gcc -fPIC -shared -o pam_parallel.so pam_parallel.c -lpam

clean:
	rm -f pam_parallel.so

install: pam_parallel.so
	install pam_parallel.so /lib/security/

uninstall:
	rm -f /lib/security/pam_parallel.so

.PHONY: clean install uninstall
