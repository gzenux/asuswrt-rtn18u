
all: media_apply.cgi media_print.cgi ms_apply.cgi ms_disk_info.cgi

ifeq ($(PLATFORM),i686)
media_apply.cgi: media_apply_cgi.c cgi.c
	$(CC)  -o $@ $^ -DMS_I686
else
media_apply.cgi: media_apply_cgi.o cgi.o
	$(CC)  -o $@ $^
endif
media_print.cgi: media_print_cgi.o cgi.o
	$(CC)  -o $@ $^ 

ms_apply.cgi: ms_apply_cgi.o ms_cgi.o ms_func.o  ms_url_parser.o ms_http_parser.o ms_ftp_parser.o
	$(CC) -o $@ $^ 

ms_disk_info.cgi: ms_disk_info.o ms_cgi.o
	$(CC)  -o $@ $^ 

clean:
	rm -f *.o *.cgi 

.PHONY: all clean
