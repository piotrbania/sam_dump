#include "utils.h"

void flog(char *text,...)
{
	char buff[512];
	va_list argptr;
	va_start (argptr,text);
	vsprintf (buff, text,argptr);
	va_end(argptr);
	FILE *o = fopen(LOG_FILE,"ab");
	assert(o);
	//fwrite(o,buff,1,strlen(buff));
	fwrite(buff,strlen(buff),1,o);
	fclose(o);
}


void get_error_msg(char *out)
{
	strcpy(out, "UNKNOWN");
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, out, 512, NULL);
}